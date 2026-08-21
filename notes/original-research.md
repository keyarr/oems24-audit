# S24 Ultra (SM-S928B): Bootloader & Engineering Mode RE Notes

Target: Samsung Galaxy S24 Ultra international (SM-S928B, Snapdragon 8 Gen 3 / SM8650 "pineapple")
Firmware baseline: S928BXXU5DZDP (Android 16 / One UI 8.5, security patch 2026-04-05, CSC ZTO)
Older reference firmware: S928BXXU4BYDA (One UI 7)
Current state: Temporary KernelSU root via exploit; bootloader remains locked on reboot.

Context: Original goal was persistent microG (currently only functional via KernelSU + Zygisk Next + LSPosed + FakeGApps + GMS bind-mounts, which dies on reboot). Samsung removed the OEM Unlock toggle in One UI 8.5 UI, though `ro.oem_unlock_supported=1` is still set. Goal shifted to tracing the unlock code paths to see if the mechanism still exists and what blocks it.

TL;DR: The unlock engine is still fully present inside ABL. Samsung simply nuked the old persistent/FRP authorization check and tied ABL unlock state directly to Engineering Mode bit 3 (`MODE_CUST_KERNEL`). If the engmode TA validates a token containing mode 3, ABL unlocks. The barrier is now purely cryptographic: obtaining a valid Samsung-signed token for this specific retail DID.

---

## 1. Boot State & Partition Map

Observed runtime boot properties:

```text
ro.boot.flash.locked=1
ro.boot.other.locked=1
ro.boot.vbmeta.device_state=locked
ro.boot.verifiedbootstate=green
ro.boot.veritymode=enforcing
ro.boot.warranty_bit=0
ro.boot.kg=0x4
knox.kg.state=Completed
ro.oem_unlock_supported=1
sys.oem_unlock_allowed=<absent>
```

Bootconfig:

```text
androidboot.other.locked="1"
androidboot.em.status="0x0"
androidboot.em.model="SM-S928B"
androidboot.em.did="[REDACTED_EM_DID]"
```

Inspected partitions:
`xbl`, `xbl_b`, `xbl_config`, `xbl_config_b`, `abl`, `uefi`, `boot`, `init_boot`, `vendor_boot`, `vbmeta`, `vbmeta_system`, `tz`, `tz_kg`, `keymaster`, `uefisecapp`, `devinfo`, `frp`, `persistent`, `secdata`, `steady`, `em`, `imagefv`.

Key block node mappings:
- `em` -> `/dev/block/sdd15` (engmode QSEE TA)
- `imagefv` -> `/dev/block/sdd10` (bootloader display assets)
- `uefisecapp` -> `/dev/block/sdd11` (UEFI vars / VaultKeeper)

---

## 2. devinfo & ABL Analysis

### devinfo Layout
Examined `devinfo.bin`. Header starts with magic `"SAMANDR-BOOT!"` at offset `0x00`.

Dissected layout via ABL references:
- `+0x000`: `"SAMANDR-BOOT!"`
- `+0x00d`: `IsUnlocked` (uint8)
- `+0x00e`: `IsUnlockCritical` (uint8)
- `+0x090`: Unrelated field initialized to 1 (disproved early hypothesis that this was a lock bit)
- `+0xc88`: `UnlockCount` (uint32)

### ABL Unlock Engine
The `LinuxLoader` module inside `abl.img` (UEFI FV) still contains the entire unlock logic:
- Active strings/symbols: `IsUnlocked`, `IsUnlockCritical`, `Unable set the unlock value: %r`, `GetUnlockCount`, `Device is unlocked, Skipping boot verification`, `For device lock, Draw Lock Img`, `For device unlock, Draw UnLock Img`.
- AVB's `read_is_device_unlocked` still reads directly from `DeviceInfo.IsUnlocked`.

### One UI 7 vs One UI 8.5 Authorization Policy
In One UI 7, ABL evaluated OEM/FRP flags from `persistent` and checked PLC (`[OEM]Oem unlock value is %d`, `[OEM]PLC:%x`, `[OEM]LOCK:%d`).

In One UI 8.5, the OEM check function was neutered:
```asm
; One UI 8.5 OEM policy
log "[OEM]LOCK:%d"
mov w0, wzr
ret
```
It returns 0 unconditionally, and `androidboot.other.locked=1` is hardcoded into the kernel command line / bootconfig.

### EM -> ABL Sync at Boot
In One UI 8.5, ABL initialization executes:
`BLInitToken()` -> `GetEMBit(3)` -> `SetUnlocked(bit3, 0)`.

This runs before AVB verification. Patching `devinfo +0x0d = 1` statically does not persist across boots because ABL will check EM bit 3, see that it is 0, and rewrite `devinfo` back to 0.

---

## 3. Mode 3 Identity: MODE_CUST_KERNEL

Framework constants (`framework.jar`):
- `0`: `MODE_ENG_KERNEL`
- `1`: `MODE_TEST_ENV`
- `2`: `MODE_DEBUG_LOG`
- `3`: `MODE_CUST_KERNEL`
- `4`: `MODE_KNOX_TEST`

This matches the ABL `GetEMBit(3)` call. Engineering Mode 3 is the official authorization for custom kernels.

---

## 4. Engineering Mode TA (em.img)

The `em` partition contains the QSEE Trusted Application (`engmode` v1.0).

Implemented command family:
`EM_CMD_INIT`, `EM_CMD_INSTALL_TOKEN`, `EM_CMD_TOKEN_IS_INSTALLED`, `EM_CMD_GET_TUC`, `EM_CMD_GET_MODES`, `EM_CMD_GET_MODES_BIT`, `EM_CMD_TOKEN_REQUEST`, `EM_CMD_TIME_REQUEST`, `EM_CMD_TIME_CHECK`, `EM_CMD_REQ_TOKEN_ESS_V1`, `EM_CMD_INSTALL_TOKEN_ESS_V1`, `EM_CMD_DELETE_TOKEN_ESS_V1`, `EM_CMD_REQ_RECOVERY_ESS_V1`, `EM_CMD_RECOVERY_ESS_V1`.

Technical details:
- **Bitmap:** `GET_MODES_BIT` constructs a 256-bit bitmap indexed directly by mode number. Bit 3 = Mode 3.
- **Validation:** Enforces RSA-2048 verification, validity dates, DID, model, nonce matching, and use counters.
- **Trust Anchors:** Hardcoded RSA public key hashes in the TA for DID class starting with `30`:
  - `42edf9dd5623f3149bceb84e9ab085e4c919e8691a4501af9c58bab16ab91ec6`
  - `8ed537b2f076791f7d93d14c1e1bc28d15151045a1615330549844ab0311cca4`
- **Signed MODE Section:** Token layout is split into `MODE`, `VALI`, and `INTE`. The `MODE` section is covered by the RSA signature; modifying an existing token to add mode 3 invalidates the signature.
- **RPMB Protected Storage:** Active mode state is stored in RPMB encrypted with AES-GCM via TrustZone KDF. Modifying `/steady` or filesystem files cannot forge active EM state.
- **Dev Device Check:** TA has a fallback for dev devices ("This is dev device and no token") checking the last 2 ASCII bytes of the DID. On retail units it ends in `"11"`, which classifies as production and enforces full token verification.

---

## 5. Android Userspace Architecture (HLOS)

Process and IPC topology:

```text
Apps / Framework (Java)
  -> lib.engmodejni.samsung.so
  -> lib.engmode.samsung.so (local app allowlist check)
  -> AIDL: vendor.samsung.hardware.security.engmode.ISehEngmode/default (PID 1294, vendor.samsung.hardware.security.engmode-service)
  -> libengmode_client.so
  -> Vendor internal Binder
  -> /vendor/bin/emservice (PID 509)
  -> libengmode_server.so -> libengmode_tlc.so
  -> TA engmode (QSEE)
```

Implementation notes:
- **Public AIDL HAL:** Stable NDK interface `vendor.samsung.hardware.security.engmode.ISehEngmode/default`. Interface hash: `40e3d24c35baf5b934a2515792ae8aae089da246`.
- **Allowlist Bypass:** The package/signature verification (`0x208` byte struct with UID, processName, etc.) is handled entirely client-side inside `lib.engmode.samsung.so`. `EngineeringModeHandler::callerCheck` inside the server binary is just `mov w0, wzr; ret`. Calling the AIDL HAL directly from native code as root bypasses the client-side package allowlist.

---

## 6. Request Generation (makeTokenReq)

Direct API parameters:
`makeTokenReq(singleId, otp, modes, expiryDate, resultBuffer)`
- `singleId`: 1 to 64 bytes
- `otp`: 6 bytes
- `modes`: uint16_be array (`00 01 00 03` for 1 mode: mode 3)
- `expiryDate`: up to 8 bytes
- `resultBuffer`: inout buffer of 70046 bytes (`0x1119e`)

Behavior:
- The TA constructs an `ENGREQ` containing DID, IMEI, model, requested mode 3, and a fresh 32-byte nonce.
- Generating a request is non-persistent (does not write to RPMB/steady), but the challenge/nonce state is cached in TA volatile memory to bind subsequent token installation.

---

## 7. Frontend Apps & SatsService (Factory Path)

DEX analysis of system packages:
- `FactoryAirCommandManager.apk`: Only queries `getStatus(26)`. Token references were unused library stubs.
- `Rampart.apk`: Holds `MANAGE_USER_OEM_UNLOCK_STATE`, but only calls `getStatus(61)` (Auto Blocker).
- `HMT.apk`: Only calls `getStatus(76)`.
- `serviceModeApp_FB.apk`: Only queries modes 38, 25, and 2.
- No standard Android UI app queries or requests mode 3.

External interface: `SatsService` (`framework.jar`, `classes6.dex`):
- Handles `+ENGMODES:` commands over abstract socket `SatsService` and `/data/misc/.socket_stream`.
- Dispatcher operations:
  - `op 1`: `em_ess_make_token_request`
  - `op 2`: `em_ess_install_token_v1`
  - `op 5`: Payload fragmentation handler (`0,5,<seq>,...` terminated by marker `FFF`)
- ESS Format: Envelope structured as `01:f1:f2:f3:f4:f5:f6:f7:cert_len:cert_hex:sha256`. The certificate provided in the envelope is used to encrypt the outbound request payload; it is not the root of trust for validating installed tokens.

---

## 8. Other Components Checked

- **FRP (`AT+FRPUNLCK`):** Managed by `com.android.server.AuthUnlockATCmd` and `libfrpunlock.so`. Operates on `/dev/block/persistent` via mode 60. Clears Google FRP state, but has zero effect on ABL lock evaluation in One UI 8.5.
- **`uefisecapp.img`:** QSEE TA (`uefi_sec.mbn`). Handles secure UEFI variables and VaultKeeper. Does not manage engmode tokens.
- **`imagefv.img`:** Bootloader display bitmaps (`device_lock.jpg`, `device_unlock.jpg`, etc.). Confirms unlock graphics remain in the firmware.
- **Modem / RIL:** `emservice` syncs status over AT channels, but CP does not participate in token signing or ABL unlock decisions.

---

## 9. AIDL Transaction Mapping & Probe Results

Reconstructed transaction IDs for `ISehEngmode`:
- `1`: `getStatus`
- `2`: `installToken`
- `3`: `isTokenInstalled`
- `4`: `removeToken`
- `5`: `getNumOfModes`
- `6`: `sendFuseCmd`
- `7`: `getVersion`
- `8`: `getExpiryDate`
- `9`: `getID`
- `10`: `getRequestMsg`
- `11`: `makeTokenReq`
- `12`: `commandForESS`
- `21`: `getStringModes`
- `22`: `getModesbit`
- `23`: `getTokenInfoForJanus`

Direct probe results:
- Transaction 22 (`getModesbit`): Requires an inout `byte[32]` buffer. Returned Binder status 0, status word `0x10002df0`, and 32 zero bytes.
- Transaction 3 (`isTokenInstalled`): Returned status word `0x10002df0`.
- Transaction 5 (`getNumOfModes`): Returned status word `0x12001fd0`.
- Transaction 7 (`getVersion`): Returned status word `0x12001fd0`.

Status words `0x10002df0` and `0x12001fd0` are internal TA/daemon result codes, not scalar booleans or counts.

---

## 10. Summary & Next Steps

Unlock chain:
`makeTokenReq(mode 3)` -> Samsung signing backend -> `installToken` -> TA verifies RSA/DID/Nonce -> Writes RPMB -> Bit 3 set in bitmap -> Reboot -> ABL `GetEMBit(3)` -> `SetUnlocked()` -> AVB unlocked.

Read-only next steps:
1. Disassemble `libengmode_server.so` / `libengmode_client.so` to map status words `0x10002df0` and `0x12001fd0`.
2. Build a minimal native C++ binary linking against the NDK AIDL HAL to issue `makeTokenReq([3])` and dump the generated `ENGREQ` payload without calling install.
3. Determine field semantics for ESS envelope fields 1 to 7 via external service tool captures if available.

Avoid state-modifying operations (no `installToken`, `removeToken`, ESS mutations, or raw partition writes to `devinfo`/`persistent`/`steady`).
