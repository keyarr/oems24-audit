# S24 OEM unlock on One UI 8.5: findings

Target: SM-S928B (`e3q`), build `S928BXXU5DZDP`, Android 16, security patch 2026-04-05
ABL comparison: `S928BXXU4BYDA` (One UI 7), official BL tar
Root: temporary KernelSU (`u:r:ksu:s0`). Bootloader stayed locked for the whole session.
Date: 2026-08-25

## What I was trying to answer

One UI 8 removed the OEM unlock toggle. I wanted to know whether Samsung also
removed the unlock mechanism itself, or just stopped exposing it to the user.

The document this started from is [original-research.md](original-research.md).
It claimed the full chain still exists and can be driven end to end if you
obtain a valid Engineering Mode token containing mode 3. I went through the
artifacts and checked the claims I could check.

## Short answer

The relevant logic still appears to be there:

- the ABL still reads `IsUnlocked` out of `devinfo` and feeds it to the AVB
  callback,
- at boot it can sync that byte from Engineering Mode bit 3
  (`GetEMBit(3) -> SetUnlocked`),
- the engmode trustlet still validates signed tokens, persists state in RPMB
  and produces the 256-bit mode bitmap,
- the request path still serializes mode 3 (`00 01 00 03`) without a local
  filter.

What is gone is the old user-facing path: the One UI 7 OEM/FRP policy that
read `persistent` and could authorize an unlock is replaced in this build by a
function that logs `[OEM]LOCK:%d` and returns false.

The HLOS carrier gate is still live, but its value is not calculated in
`framework.jar` or by KMX. `framework.jar` only forwards the Binder call;
`services.jar`'s `OemLockService` delegates it to the selected `mOemLock`
backend. That backend can be the AIDL HAL, the HIDL HAL or
`PersistentDataBlockLock`. Because `ro.frp.pst` is populated, SystemServer
starts OemLockService without requiring `isHalPresent()` to succeed, so the
live `oem_lock` service does not identify the active backend.

Two things were never demonstrated and probably cannot be from this side of
the fence:

1. a valid token containing mode 3 (needs Samsung's external authority), and
2. that the EM sync block runs before *every* AVB verification on *every* boot
   path (the static CFG says it does not dominate the AVB call I examined).

## How confident I am

I used four levels, roughly in order of how much static cross-checking backs
each item:

- **Confirmed** - at least two independent static observations agree, or the
  runtime snapshot and the binary analysis point the same way.
- **Likely** - the confirmed part is real, but the claim extends past what the
  evidence covers (usually because it generalizes from one path to all paths).
- **Possible** - consistent with the artifacts, no direct confirmation.
- **Unknown** - no evidence in this repo.

## The claims, one by one

The original document had 19 claims. 14 hold up as stated, 5 only partially.
This audit adds claims 20 and 21 for the later HLOS/KMX and OEM-lock/HAL leads;
they are not part of the original claim count. Verdict column uses the levels
above; the notes carry the why and the key offsets.

| # | Claim | Verdict | Notes |
|---|-------|---------|-------|
| 1 | Current state: locked, green/enforcing, warranty 0 | Confirmed | `properties-targeted.txt` and `proc-bootconfig.txt` agree (`flash.locked=1`, `other.locked=1`, `vbmeta.device_state=locked`, `ulcnt=0`, `warranty_bit=0`, `kg=0x4`). `sys.oem_unlock_allowed` is absent/empty, not zero. |
| 2 | `devinfo` layout, `+0x0d = IsUnlocked` | Confirmed | Snapshot (`devinfo-layout-evidence.txt`) shows magic at `+0x0`, `+0xd=0`, `+0xe=0`, `+0x90=1`, `+0xc88=0`. ABL semantics: `IsUnlocked` reads the global at `0x170e28+0x0d`, `SetUnlocked` writes `strb` at RVA `0x42524`, initializer writes `+0xd/+0xe/+0x90/+0xc88` separately. |
| 3 | Unlock mechanism exists and is consumed by AVB | Confirmed | AVB callback `read_is_device_unlocked` at RVA `0x51048` calls `IsUnlocked` and stores the result; `AvbOps` init installs it at `ops+0x48`; verification path at `0x140dc` and the `Device is unlocked, Skipping boot verification` branch are live code, not dead strings. |
| 4 | OEM/FRP policy changed One UI 7 -> 8.5 | Confirmed | Old build reads `persistent` (`0xa0f70`), can return 1 (`0xa13c0`). New build logs `[OEM]LOCK:%d` and unconditionally `mov w0,wzr` at `0xa141c`. `androidboot.other.locked=1` is appended by the new cmdline builder (`0x4d01c`) and absent from the old build. Two specific builds, not every One UI 7/8.5. |
| 5 | EM bit 3 feeds `SetUnlocked` before AVB | Likely | The chain is there: `BLInitToken` `0x998c`, `mov w0,#3` `0x9990`, `GetEMBit` `0x9994`, dispatcher `0x41f88 -> 0x42100 -> SetUnlocked 0x424cc`. The "before AVB" part does not hold universally: CFG shows an entry-to-AVB path that avoids the EM block and `EM_SYNC_DOMINATES_AVB_BLOCK=False` (`abl-cfg-ordering.txt`). |
| 6 | Mode 3 is `MODE_CUST_KERNEL` | Confirmed | `EngineeringModeManager` in `framework.jar` defines `MODE_CUST_KERNEL=3`; ABL queries literal 3. Both use the number directly, no remapping table. |
| 7 | Engmode TA exists and implements the claimed functions | Confirmed | ELF64 AArch64, no section table. Dispatcher at VA `0x49b0` with branch tables to INIT/INSTALL_TOKEN/GET_MODES_BIT/TOKEN_REQUEST/ESS 26-32 etc. Parser `0xadb8`, signature verify `0xa5cc`, binding `0xa7a8+`, bitmap `0xea8c`. "Certificate validation" is inferred from the crypto control flow, no debug symbols. |
| 8 | `GET_MODES_BIT` is a 256-bit bitmap | Confirmed | TA builds four 64-bit words; `(mode>>6)` picks the word, `1<<mode` the bit; caps at `m<0x100`. Mode 3 is bit 3. The live query returned a zeroed 32-byte buffer, which says nothing about actual mode state (the call failed with a status error). |
| 9 | MODE is inside the signed token region | Confirmed | `0xa654` reads the mode count, `0xa66c` adds 4 bytes per record into the authenticated length passed to the verifier at `0x3070`. Changing mode breaks the signature. |
| 10 | EM state is protected by RPMB | Confirmed | TA imports `qsee_stor_*` and `qsee_kdf`, builds an AES-GCM context (KDF `0x8d0`, write `0x1340`, read `0x1574`, init/open `0x1e14`). Only the logical `engmode` area on secure storage holds validated state; `/steady` and filesystem blobs do not substitute. RPMB contents were not read (safety). |
| 11 | HLOS architecture: AIDL HAL -> internal service -> TLC -> TA | Likely | `hal_engmode_default`/`emservice` domains confirmed running, VINTF `format=aidl` v1, JNI `dlopen`s `lib.engmode.samsung.so`. The part that fails: `libengmode15.so` is **not** in the runtime. The server links `libengmode2lite.so` + `libengmode_tlc.so`; `libengmode15.so` is neither a `DT_NEEDED` entry nor mapped in `emservice` (`engmode-maps.txt`, `engmode-lsof.txt`). Treat it as a legacy/compat artifact. |
| 12 | Client allowlist and direct AIDL bypass | Likely | `lib.engmode.samsung.so` does the caller checks client-side (`caller_check 0x86d0`, `checkSignature 0x10958`, `checkPath 0x10bf0`, ...). The internal server's `callerCheck(int)` is literally `mov w0,wzr; ret`. `getStatus` takes `SehCallerInfo`; `makeTokenReq`/`getModesbit` do not. In the observed root-shell context, read-only transactions 3/5/7/22 reached the service while SELinux was Enforcing. This confirms transport for those transactions only. Transaction 11, its parcel shape, method-specific checks, vendor policy, TLC forwarding and TA acceptance remain untested. |
| 13 | `makeTokenReq()` accepts mode 3 | Confirmed | `EngineeringModeWorld::emGetTokenRequest` (`libengmode_server.so`, VA `0xf07c`) reads a `uint16_be` count, requires `count < 0x40`, byte-swaps each mode, stores them at TA payload `+0x2aa/+0x2ac`, sends command `0x21c7d`. No mode filter. Static only, by design. |
| 14 | Request/token bound to device and nonce | Likely | Device-record memcmp (`0xa7a8/0xa858`), install-path checks for nonce, singleId, model, used-state (`0xd830`), expiration (`0xacd8+`). The generalization "no old token can ever work" is too strong: it depends on expiration, use state, TUC and token type. IMEI is parsed but not proven mandatory. |
| 15 | `SatsService` and `AT+ENGMODES` exist | Confirmed | `SystemServer` publishes `SatsService`; `EngModesCmdHelper` handles `0,5,` fragments and the `FFF` terminator, reassembles, prefixes `0,2,` and calls `commandForESS` (JNI mapping table in `native-sats-ess-evidence.txt`). Runtime shows the service, the abstract socket and `/data/misc/.socket_stream`. No AT command was sent. |
| 16 | ESS format and role of the external certificate | Likely | Parser requires version `01`, 11 nonempty tokens plus the empty component after the terminal `:`, with 7 opaque intermediate fields. SHA-256 over the serialized body, cert length vs decoded length checked. Cert goes into `em_ess_encrypt_message` to encrypt the outbound request; token verification uses a separate trust anchor. The historical DASEUL command matches this token layout, but field semantics and the authority behind the cert are not in local artifacts. |
| 17 | Mode 60 is FRP, not custom kernel | Confirmed | `AuthUnlockATCmd.processCmd` calls `getStatus(60)` with literal `const/16 v1,60` at DEX offset `0x34a` in the `AT+FRPUNLCK` flow, alongside native session/wipe and `PersistentDataBlockManager`. No `getStatus(3)` fixed callsite exists anywhere in framework/APKs. |
| 18 | AIDL transaction map 1-23 | Confirmed | Extracted from the generated NDK proxy in `engmode-V1-ndk-system.so`: each `mov w1,#N` before `AIBinder_transact`. Interface hash `40e3d24c35baf5b934a2515792ae8aae089da246`. State-changing transactions were not executed. |
| 19 | Status words `0x10002df0`/`0x12001fd0` | Confirmed | They were a byte-reversal mistake. `service call` already prints 32-bit words; the real values are `0xf02d0010` (TA parser error, missing/invalid `ENG` magic, constructed at `0xae78`) and `0xd01f0012` (legacy server `Unknown Command` default branch, `0xbbc0`). The private enum names are still unknown. |
| 20 | HLOS/KMX controls OEM unlock state | Partial | Settings reads carrier eligibility with `OemLockManager.isOemUnlockAllowedByCarrier()`, combines it with the current user's base `no_factory_reset` restriction, and writes the user choice through `setOemUnlockAllowedByUser()`. It also broadcasts `CHANGE_OEM_UNLOCK_ALLOWED` explicitly to KMX. Both collected KMX versions schedule a delayed TrustChain scan for that action and later read `sys.oem_unlock_allowed`; neither contains a matching OEM-lock or property write. The proven KMX role is notification and monitoring, not state control. |
| 21 | `isOemUnlockAllowedByCarrier()` is supplied by the selected OemLock backend | Confirmed | `OemLockService$2.isOemUnlockAllowedByCarrier()` directly invokes `mOemLock.isOemUnlockAllowedByCarrier()`. The selected backend can be `VendorLockAidl`, `VendorLockHidl` or `PersistentDataBlockLock`. Because `ro.frp.pst` is populated, SystemServer starts OemLockService regardless of HAL presence; the active backend remains unresolved. |

## Component notes

### ABL (`decompiled/abl-oneui8-evidence.txt`, `abl-oneui7-comparison.txt`, `abl-cfg-ordering.txt`)

- Addresses in the report are PE RVA/file offsets. radare2 loaded this PE with
  a `+0x10000` bias; the extracts record both.
- `devinfo` layout (size `0xcd0`): magic at `+0x0`, `IsUnlocked` `+0x0d`,
  `IsUnlockCritical` `+0x0e`, `UnlockCount` `+0xc88`, and `+0x90` is a
  separate flag initialized to 1. `+0x90` being 1 in the snapshot is what
  originally made it look like the lock bit. It is not.
- Key RVAs: `IsUnlocked 0x41ed0`, `GetUnlockCount 0x41e70`, `SetUnlocked 0x424cc`
  (writes `+0x0d`, bumps `+0xc88`, persists), initializer `0x425ec`,
  AVB callback `0x51048`, `AvbOps` init `0x516c8`, policy `0x140dc/0x16238`,
  lock-state UI `0xacc60`, new OEM policy `0xa13b0`, cmdline
  `androidboot.other.locked=1` at `0x4d01c`.
- The One UI 7 LinuxLoader (from `manifests/oneui7-abl.json`) reads
  `persistent` at `0xa0f70`, policy `0xa1320`, and can return 1. It does not
  contain `androidboot.other.locked=1` anywhere.

### OEM-lock / VaultKeeper (`framework.jar`, `services.jar`, `device/services.txt`)

- `framework.jar` contains the public `OemLockManager`/`IOemLockService` layer.
  `OemLockManager.isOemUnlockAllowedByCarrier()` only forwards to the Binder
  service named `oem_lock`; it contains no carrier-state source.
- The implementation is in `services.jar` (`OemLockService`). Its Binder
  method enforces the carrier permission and directly calls
  `mOemLock.isOemUnlockAllowedByCarrier()`. The constructor probes
  `android.hardware.oemlock.IOemLock/default` through `VendorLockAidl`, then
  `android.hardware.oemlock@1.0::IOemLock/default` through `VendorLockHidl`,
  with `PersistentDataBlockLock` as the final fallback. The extracted method
  addresses and full chain are in
  [oem-lock-service-evidence.txt](../decompiled/oem-lock-service-evidence.txt).
- The automated DEX scan now enumerates the two logical entries in the
  services.jar 041 container and finds `OemLockService`, `VendorLockAidl` and
  `VendorLockHidl` in `classes.dex#logical-2@0x99d3f8`; this coverage was
  previously manual-only.
- `isOemUnlockAllowed()` combines the carrier result with the device result and
  mirrors the aggregate into the persistent-data-block OEM-unlock bit on the
  HAL path. PDB is therefore a mirror/side effect when a HAL backend is
  selected, not the carrier authority on that path. If
  `PersistentDataBlockLock` is selected, its carrier result is instead the
  inverse of the system-user `no_oem_unlock` restriction.
- SystemServer starts `PersistentDataBlockService` when `ro.frp.pst` is
  populated, then starts OemLockService under
  `!noPdb || OemLockService.isHalPresent()`. The populated PDB therefore
  bypasses the HAL-presence probe; the live `oem_lock` service does not prove
  that either vendor HAL was selected.
- Runtime inventory confirms `oem_lock`, `persistent_data_block`, the Java
  `VaultKeeperService` and the vendor `ISehVaultKeeper/default` service. The
  covered DEX shows VaultKeeper clients in DMC, CASS and Rampart, but no direct
  OemLockService/PDB/KMX edge. Rampart's OemLockManager wrapper uses the
  user-side methods, not the carrier query.
- The current `oem-lock-services.txt` is not sufficient to choose AIDL versus
  HIDL: the collector looks for `oem_lock` in the service list and omits
  `oemlock` from its `lshal`/VINTF filters. Absence of the AIDL endpoint in
  that file is therefore only a hint, not a negative result.

### Framework / HLOS (`native-*-evidence.txt`, `aidl-transaction-evidence.txt`, `dex-*`)

- `MODE_ENG_KERNEL=0, MODE_TEST_ENV=1, MODE_DEBUG_LOG=2, MODE_CUST_KERNEL=3,
  MODE_KNOX_TEST=4` in `framework.jar` (`framework-engineeringmode-api.txt`).
- Public HAL is stable AIDL NDK v1, instance `default`, descriptor
  `vendor.samsung.hardware.security.engmode.ISehEngmode`. Not HIDL.
- `makeTokenReq(singleId, otp, modes, expiryDate)` has no `SehCallerInfo`
  argument, so a direct client skips the Samsung client-library allowlist on
  that route. `getStatus` does carry `SehCallerInfo`.
- No fixed `getStatus(3)` callsite anywhere. Fixed mode numbers in the
  framework: 60 (FRP, `AuthUnlockATCmd`), 61 (Rampart/Auto Blocker),
  28 (DevRootKey), 26 (FactoryAirCommandManager gate), 76 (HMT).
- `AT+ENGMODES` JNI mapping (`0,1, -> 1`, `0,2, -> 2`, `0,3, -> 3`,
  `0,4, -> 4`, `1,1,0 -> 5`, `1,2,0 -> 6`, `1,3,1 -> 7`, `2,2, -> 8`,
  `0,0,3,0 -> 9`, `9,0 -> 10`, else 1000). ESS subtype 1 reaches
  `em_ess_make_token_request`, subtype 2 `em_ess_install_token_v1` in the TA.

### Trustlet (`em.img`, `ta-*-evidence.txt`)

- ELF64 AArch64 ET_DYN, no section headers. VA in `PT_LOAD` at file `0x1000`
  maps to VA 0, so `file = VA + 0x1000` in the first load.
- Imports parsed manually from `DT_HASH`/`DT_SYMTAB`/`DT_JMPREL`; the
  sectionless layout means one 16-byte PLT veneer per relocation from VA `0x20`.
- Command map recovered from the dispatcher branch tables (see
  `ta-command-storage-evidence.txt`): 2 INSTALL_TOKEN `0xd830`,
  3 TOKEN_IS_INSTALLED `0xce04`, 11 TOKEN_REQUEST `0x13940`,
  12/26-32/36 ESS family `0x14cec`, 20 GET_MODES `0xe248`,
  21 GET_MODES_BIT `0xea8c`, 23/24 time `0x14128/0xecb0`, 25 INIT `0x1183c`,
  33 INIT_CORE `0xf8c4`, 34 GET_MODES_FT `0xfa24`, 35 GET_INFO `0xfcd0`.
- `GET_MODES_BIT` caps the mode count at `0x80` and each mode at `0xff`.

## Things that went nowhere

Kept for the record, because half of this work was ruling things out.

- **`devinfo+0x90` as the unlock bit.** First hypothesis, because it is the
  only nonzero byte in the snapshot. The ABL initializer writes it
  independently and `SetUnlocked` writes `+0x0d`. Dead end.
- **`libengmode15.so` as part of the runtime chain.** It has convenient
  symbol names and initially looked like the server library. The running
  `emservice` links `libengmode2lite.so`; `libengmode15.so` is not loaded.
  It is still useful as a symbol reference for ESS mapping.
- **"EM sync runs before all AVB logic".** The CFG analysis says no: there is
  an entry-to-AVB path that avoids the EM block, and the block does not
  dominate the AVB call. Also a recursive call into the main function exists,
  so even the intra-procedural result does not settle cross-invocation
  ordering. This killed the "manually setting devinfo is always overwritten
  on the next boot" claim: it is only true when the sync path runs.
- **`0x10002df0` / `0x12001fd0` as unknown magic status words.** Both are
  byte-reversed misreadings of Parcel output. They are `0xf02d0010` (TA
  parser error on missing/invalid `ENG` header) and `0xd01f0012` (legacy
  server "Unknown Command"). The live probes on transactions 3/5/7/22 all hit
  one of these, which is why the bitmap came back zero: the call failed, the
  zeroed buffer proves nothing about mode state.
- **`service call ... 22` parcel shape.** First try (no input array) gave
  `-ENODATA`, second (length only) gave `-ENOMEM`. The AIDL signature is an
  inout byte vector, so both length and 32 bytes must be present. Building
  transaction 11 by hand was judged too error-prone for the same reason and
  skipped.
- **FactoryAirCommandManager and Rampart as token provisioners.** Symbol
  searches suggested `makeTokenReq`/`installToken` callsites. DEX callsite
  analysis showed those were stub/library definitions; the real callsites
  only call `getStatus(26)` (FACM gate) and `getStatus(61)` (Rampart).
  Same story for HMT (`getStatus(76)`) and ServiceMode (`38/25/2`).
- **`uefisecapp.img` and `imagefv.img` as mode-3 authorities.** `uefisecapp`
  is a UEFI-variable/secure-storage trustlet (PKCS#7, QSEE storage), not the
  engmode TA. `imagefv` is a firmware volume of boot images (`device_lock.jpg`,
  `orange_state.jpg`, ...). It does confirm the lock/unlock UI assets still
  ship, and nothing else.
- **Modem/RIL path.** `emservice` talks `AT+ENGMODES` with the CP, but nothing
  suggests the modem signs tokens, chooses modes or grants unlock. Treat the
  modem leg as sync/notification only.
- **RSA trust anchor hashes cited in the original doc.** The two key hashes
  for the DID class `30...` have no matching extract in this repo, so they
  cannot be verified from the published artifacts. I did not re-derive them.
- **VaultKeeper as the Java-side carrier authority.** The live VaultKeeper
  services and the Java manager are real, but the covered DEX places their
  direct clients in DMC, CASS and Rampart. No OemLockService,
  PersistentDataBlockService or KMX call feeds the carrier query. A native HAL
  dependency remains possible and is outside the collected vendor binaries.

## Corrections to the original document

1. "EM sync occurs before later AVB boot logic" does not hold for every path.
2. "Manual `devinfo` edits are overwritten on the next boot" is only true when
   the sync path runs; not proven universal.
3. `libengmode15.so` is not part of the observed runtime (compat/legacy).
4. ESS type-1 format: 11 nonempty tokens plus the trailing empty component;
   7 opaque intermediate fields. A twelfth nonempty token is rejected.
5. Status words: `0xf02d0010` and `0xd01f0012`, not the reversed readings.
6. Direct AIDL avoids the client-side allowlist only on routes without
   `SehCallerInfo`; `getStatus` still carries it.
7. `sys.oem_unlock_allowed` is absent/empty, not proven 0.
8. The current runtime snapshot was collected while SELinux was `Permissive`;
   it cannot extend the earlier Enforcing result beyond the read-only
   transactions already tested.
9. The source of `isOemUnlockAllowedByCarrier()` is the `mOemLock` backend in
   `services.jar`; KMX and the Java VaultKeeper service are not that source.
   The selected backend can be AIDL HAL, HIDL HAL or PDB.
10. Persistent Data Block mirrors the aggregate OEM-unlock state when a HAL
    backend is selected. If `PersistentDataBlockLock` is selected, its
    `no_oem_unlock` restriction supplies the carrier boolean instead.

## What is still unknown

- Whether Samsung's current authority would issue a mode-3 token for this
  retail DID, and which tool/credential is used. Historical public material
  reports a valid token containing mode 3, which shows that the mode was issued
  in the past but says nothing about the current authority or this device/build.
- Which server-side meanings are assigned to the current ESS prefix fields.
  The complete historical DASEUL command maps positionally to the current
  7-field prefix, but does not prove backend semantics or acceptance. See
  [historical-daseul-ess.md](historical-daseul-ess.md).
- Transaction transport and operation semantics are separate questions. In the
  observed root-shell context, read-only transactions 3/5/7/22 reached the
  service with SELinux Enforcing. A correctly shaped request can therefore
  likely reach the same endpoint, but transaction 11 (`makeTokenReq([3])`) was
  not sent. Its parcel shape, method-specific checks, vendor policy, TLC
  forwarding and TA acceptance remain untested.
- Dynamic behavior (token install, reboot with bit 3 set) was never measured:
  it requires changing protected state.
- The exact private names of the status enums.
- Which OemLock backend is active (stable AIDL, HIDL or
  `PersistentDataBlockLock`). If a vendor HAL is active, what it calls below
  that boundary is also unknown. The current collection omitted the decisive
  `oemlock` entries from the `lshal` and VINTF filters, and the HAL binaries
  were not collected.
- Whether the vendor OEM-lock HAL uses VaultKeeper, another secure-world
  service, or a private storage path. The Java-side VaultKeeper callsites do
  not establish that edge.
- Whether KMX has any path beyond monitoring OEM unlock eligibility. Settings
  uses `OemLockManager.isOemUnlockAllowedByCarrier()` together with the current
  user's `no_factory_reset` base restriction, and writes the user choice
  through `setOemUnlockAllowedByUser()`. It also sends an explicit
  `CHANGE_OEM_UNLOCK_ALLOWED` broadcast to
  `com.samsung.android.kmxservice`, carrying the menu value as
  `VALUE_MENU_OEM_UNLOCKING`. Both the stock KMX APK and the installed update
  declare `trustchain.securityscanner.EventReceiver` for that action. Their
  receiver branch does not read the menu-value extra or call an OEM-lock API;
  it schedules a one-time TrustChain security scan after five minutes. The scan
  reads `sys.oem_unlock_allowed` through `SemSystemProperties.get()` and treats
  only the exact string `1` as allowed. No OEM-lock, persistent-data-block or
  property write was found in either KMX APK. This proves a Settings -> KMX
  notification -> delayed read/monitoring path, not KMX control of OEM-lock
  state. Runtime inventory also confirms the generic `oem_lock`,
  `persistent_data_block`, framework and vendor VaultKeeper services, but no
  service-level edge from those components to this KMX receiver was
  established.

## Reproducing the interesting parts

All analysis scripts run on committed artifacts except the SecSettings-derived HLOS analysis; SecSettings.apk exceeds GitHub's file-size limit and must be recollected using pull_artifacts_readonly.sh. Its expected SHA-256 is recorded in manifests/device-artifacts.tsv. Dependencies:
`capstone`, `lief`, `pyelftools`, `androguard`, `loguru`, `lz4`,
`uefi_firmware`; bundled radare2 under `tools/` (abl_audit.py sets
`LD_LIBRARY_PATH` itself); `dexdump` for the services script.

```sh
python3 scripts/abl_audit.py                 # regenerates decompiled/abl-*.txt, devinfo-layout-evidence.txt
python3 scripts/ta_audit.py                  # regenerates decompiled/ta-*-evidence.txt
python3 scripts/native_audit.py              # regenerates decompiled/native-* and aidl-transaction-evidence.txt
python3 scripts/dex_audit.py                 # regenerates decompiled/framework-* and dex-callsites-*
bash scripts/services_dex_audit.sh           # regenerates decompiled/services-systemserver-satsservice.txt
python3 scripts/build_derived_manifest.py    # regenerates manifests/derived-evidence.tsv
```

Re-extraction (needs the original inputs, recorded in `manifests/*.json`):

```sh
python3 scripts/extract_linuxloader.py partitions/abl.img \
    decompiled/linuxloader-oneui8.pe manifests/linuxloader-oneui8.json \
    --outer-volume-output decompiled/abl-inner-oneui8.fv.bin
python3 scripts/import_oneui7_abl.py BL_S928BXXU4BYDA_*.tar.md5 \
    partitions/abl-oneui7.elf manifests/oneui7-abl.json
```

The live AIDL probes are in `scripts/probe_engmode_readonly.sh`; only
transactions 3, 5, 7 and 22, output in `device/engmode-binder-readonly-probes.txt`.

## Safety

Nothing state-changing was run: no token install/remove, no ESS mutations, no
fuse/FRP commands, no partition or RPMB writes, no direct writes to
`devinfo`/`persistent`/`steady`, no DID modification. Partitions were read
with `dd if=... status=none` over adb. The only Binder calls were the
query-only transactions above.

## Artifacts and hashes

Full provenance (source, size, sha256, collection command) is in
`manifests/device-artifacts.tsv`, `manifests/runtime-files.tsv`,
`manifests/runtime-supplement-files.tsv`. The important ones:

| Artifact | SHA-256 |
|---|---|
| `partitions/abl.img` | `49ff63c8b82e1513ea6c41cd5229fa088eee272e238419a8f3067b1abcb9d7eb` |
| `decompiled/linuxloader-oneui8.pe` | `1e57583c18bd1aaac855becf87cc6286d702e703fd8122bf9c3808f625e6da4a` |
| `decompiled/linuxloader-oneui7.pe` | `852b255c7b8c9a24f8306bd2fce78250b40de3ee031913e8fb2df15af8df9bfc` |
| `partitions/devinfo.img` | `ae8e0b0112822c89ce2ea9dbae977a55bbf4efcab7171083f2d9dcec0f668220` |
| `partitions/em.img` | `ac9e4116fa1b2fb4922744ec591190a0727e3d84f1e9a74361a344261f457711` |
| `framework/framework.jar` | `fc9127bda46f6b45f754d0db9f600a56de6beee35a2cdaf1f3916cb2458beeb4` |
| `framework/services.jar` | `9f20a26dc4c7aa599729847b9a0a50978ce754d9c135ce20399264baa724cfe4` |
| `binaries/libengmode_server.so` | `1eba30538f372a48f772bf14d4b92bde277cd969191400ef0fccd6f83c9a5d2c` |
| `binaries/lib.engmode.samsung.so` | `2c83935f5a2b216d2721ad436781392fda8b0baad07be8663ecfe3d4f0076b10` |

`notes/original-research.md` is the document that was audited. The copy
checked into this repo hashes to
`d34d20848a9453b586df6db222b84e534a2077267f724adc89305cd63429cd4b`; the
snapshot originally audited was recorded as
`bf0ec830eec86709e863ab5bf68c759ca8665217021eafcf0c44a01569881028`, so the
two differ. The findings above are the verified state of things.
