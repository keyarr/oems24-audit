# Samsung Galaxy S24 Ultra Independent Audit

Special thanks to adfree on xda forums for helping with the engineering mode and token side.

## What happened to bootloader unlocking

On One UI 7, the owner still had a user facing OEM unlock path. The framework policy could read the persistent OEM state and authorize the unlock flow.

On One UI 8 and later builds checked here, including the audited One UI 8.5 build `S928BXXU5DZDP` for the SM-S928B, Samsung removed that user facing access. The new OEM policy returns false, and the bootloader command line forces `androidboot.other.locked=1`.

The underlying bootloader mechanism was not removed. ABL still reads `IsUnlocked` from `devinfo`, passes it to the AVB decision, and can update it from Engineering Mode bit 3. The problem is how to create that state. Mode 3 is inside a signed Engineering Mode token, the token uses Samsung controlled RSA anchors, and the validated state is stored in protected storage. Editing `devinfo`, `/steady`, or other normal partitions does not create a valid unlock state.

This audit found no local path that restores the old user access or creates the required unlocked state. The bootloader stayed locked for the whole session. All collection and analysis described here was read-only.

## Scope and current state

This is a read-only audit of the user facing OEM unlock access removed in the One UI 8 builds checked on the SM-S928B. The tree contains primary evidence collected from the device, device images, static analysis outputs, and the scripts used to produce them.

Target device: SM-S928B (`e3q`)

Audited build: `S928BXXU5DZDP`, Android 16, security patch 2026-04-05

ABL baseline: `S928BXXU4BYDA`, One UI 7 official bootloader tar

Device state during collection: locked, green, enforcing, warranty bit 0

The main read-only audit is complete as far as I can take it. The remaining work needs exploit development, deeper USB or UEFI parsing, or new firmware. That is outside the scope of this tree.

## Current conclusion

- The old One UI 7 user path is gone in the One UI 8 builds checked here.
- ABL still contains the unlock and AVB integration.
- A valid mode 3 token still requires Samsung's signature. MODE is part of the signed body and cannot be changed locally.
- `devinfo+0x0d` has one relevant writer, `SetUnlocked`, fed by `GetEMBit(3)`. The parser reads a fixed `0xcd0` bytes, so direct file edits do not create the unlocked value.
- The normal boot path runs EM synchronization before the AVB decision. A separate error edge skips that block but still loads `DeviceInfo` before AVB. It can preserve a valid existing value, not create one.
- The old OEM and FRP policy is gone, and the new command line reports the device as locked.
- No pre-AVB input examined so far provides a write primitive reaching the unlock byte or bypassing AVB.

## What the audit covered

### Bootloader and AVB

The ABL comparison covers One UI 7, One UI 8.0 CZD1, One UI 8.5 DZDP, and the later DZG1 bootloader material. It maps the `devinfo` layout, the `IsUnlocked` writer, the Engineering Mode sync path, AVB callbacks, OEM policy, command line construction, and pre-AVB inputs.

The remaining pre-AVB leads were triaged at function level: GPT and AVB inputs, UEFI variables, `misc`, `steady`, `sec_efs`, `secdata`, `devcfg`, `abl_x`, and the Odin dispatcher. The examined paths are fixed size, validated, fail closed, or covered by AVB itself. The per-command Odin USB parse-before-verify audit is still open.

### Engineering Mode and TrustZone

The live device DID starts with `30`. Static analysis shows that this selects the TLC and TrustZone path for this unit. The earlier lite-only conclusion was wrong for this DID. The lite backend remains a separate path for DID families such as `25` and `15`.

The Engineering Mode token path still serializes mode 3 without a local mode filter. The trustlet validates the signed token, binds it to device and request data, persists state in protected storage, and exposes the mode bitmap. The pre-auth parser is bounds checked on both sides, requirement flags are OR-only, and the tested TOCTOU and BUG-1 paths did not produce a state write.

The detailed HLOS to TrustZone boundary audit is in [notes/engmode-hlos-tz-boundary-audit.md](notes/engmode-hlos-tz-boundary-audit.md). The DID and backend correction is recorded in [decompiled/em-did-backend-evidence.txt](decompiled/em-did-backend-evidence.txt).

### HLOS, OEM lock, and KMX

Settings still queries the OEM lock service and notifies KMX when the user side state changes. The collected KMX code shows monitoring and delayed TrustChain scanning. It does not show a write to `devinfo` or an independent unlock authority.

The OEM lock service delegates to an AIDL HAL, a HIDL HAL, or the persistent data block fallback. The runtime inventory shows the service and persistent data block service, but the collected evidence does not conclusively identify which backend `OemLockService` selected. Claims about the active backend stay limited to that evidence.

### Public CVEs and downgrade leads

The public GBL path is absent. The secure world paths examined here do not provide a direct bridge to the bootloader unlock state.

CVE-2026-21046 led to a real patch difference in the SPU fabrickeymaster firmware between the available DZDP and DZG1 material. It was not a direct unlock primitive in this audit. It may matter as a downgrade enabler, while the related HLOS `fkeymaster` path remains unanalyzed.

## What remains open

- Per-command USB parse-before-verify audit in Odin. Current map has no lead. Estimated effort is 3 to 5 days.
- Full loop analysis of the `steady` walker and `misc` parser. Current patterns are fixed size and validated, but the complete loops are not closed. Estimated effort is 1 to 2 days.
- HLOS `fkeymaster` and `fabric_crypto` analysis for the SPU downgrade path.
- Monthly patch diffs against new bootloader releases.

None of these open items changes the current conclusion for the audited build.

## Safety

Audit scripts do not invoke token installation or removal APIs, mutating ESS commands, fuse commands, or `AT+FRPUNLCK`. They do not write to partitions. Partition collection uses `dd if=...` on the device and redirects the bytes to a host file.

The live Binder probes are limited to query-only transactions. State-changing transactions were not executed.

## Repository layout

- `device/`: properties, bootconfig, services, processes, and runtime evidence.
- `partitions/`: images read directly from relevant block devices.
- `binaries/`: device executables and libraries.
- `framework/`: JARs, APKs, manifests, and init files.
- `decompiled/`: derived extraction and disassembly outputs.
- `logs/`: collection and analysis logs.
- `manifests/`: origin, size, SHA-256, timestamp, and collection command.
- `notes/`: findings, historical context, and research maps.
- `scripts/`: collection and analysis procedures.

The consolidated report is [notes/findings.md](notes/findings.md). Historical public ESS material is kept in [notes/historical-daseul-ess.md](notes/historical-daseul-ess.md). It documents the old DASEUL schema and is not evidence of current firmware behavior.

Derived extracts record VA or RVA, file offsets, hashes, and disassembly where needed. `decompiled/dex-hlos-oem-policy-evidence.txt` covers decoded DEX from the collected top-level APKs and JARs, including `services.jar`, Settings, and both collected KMX APKs. `decompiled/oem-lock-service-evidence.txt` documents the `framework.jar` and `services.jar` reconstruction of `OemLockService`, its backend options, the PDB fallback, and the VaultKeeper cross-check.

## Read-only collection

The main collectors require a connected device and `adb shell su -c id`:

```sh
./scripts/collect_runtime_readonly.sh
./scripts/collect_runtime_supplement_readonly.sh
./scripts/pull_artifacts_readonly.sh
./scripts/collect_level0_readonly.sh
```

Manifests use UTC timestamps. `collect_level0_readonly.sh` adds the later read-only checks for OEM lock inventory, identity, efivars, bounded logs, and optional tracing.

## Analysis and reproduction

```sh
python3 scripts/abl_audit.py
python3 scripts/abl_audit_czd1.py
python3 scripts/abl_preavb_input_map.py
python3 scripts/ta_audit.py
python3 scripts/native_audit.py
python3 scripts/dex_audit.py
./scripts/services_dex_audit.sh
./scripts/probe_engmode_readonly.sh
python3 scripts/build_derived_manifest.py
```

The focused offline checks are:

```sh
python3 scripts/ta_harness.py
python3 scripts/harness_h2.py
python3 scripts/odin_usb_deep.py
```

Some focused scripts expect artifacts or explicit input paths. Their headers document those requirements.

`abl_audit.py` requires `radare2` (`r2`) on `PATH`. A local `tools/` tree is used automatically when present.

`dex_audit.py` exits non-zero and lists missing packages when the HLOS APKs it needs are absent from `framework/`. The usual source for `com.android.settings` is `framework/SecSettings.apk`. That file is gitignored because it exceeds GitHub's file size limit. Collect it before regenerating the HLOS evidence.

`build_derived_manifest.py` records the hash, size, and producer of scripts, extracts, reports, and this README.
