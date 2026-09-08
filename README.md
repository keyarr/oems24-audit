# Samsung Galaxy S24 Ultra Independent Audit

Special thanks to adfree on xda forums for helping with the engineering mode/token side.

Read-only audit of the One UI 8+ OEM unlock removal on the SM-S928B. This tree holds primary evidence collected from the device in read-only mode and the artifacts used for static analysis.

## status: research done on my side

static read-only work is finished as far as i can take it. every cheap lead is closed, what is left needs actual exploit dev and that is not my area.

why it stops here:
- token with mode 3 needs samsung signature. MODE sits inside the signed body, RSA-2048 with fixed anchors, no rotation CZD1 to DZDP to DZG1. nothing to forge locally.
- devinfo+0x0d has one writer: SetUnlocked fed by GetEMBit(3). parser reads a fixed 0xcd0 bytes. direct edit does not create the 1, the error path only preserves a pre-existing one.
- EM sync does not dominate AVB. normal boot runs it, the bypass edge is ERROR_ONLY and still lazy-loads DeviceInfo before AVB.
- old OEM/FRP policy is gone (returns false), cmdline forces androidboot.other.locked=1.
- HLOS side is monitoring only. Settings to KMX is notify plus delayed scan, backend resolves to PDB with no vendor HAL in lshal or service list. nothing there writes devinfo.
- trustlet pre-auth is closed: request parser bounds-checked on both sides, requirement flags are OR-only, TOCTOU closed, BUG-1 proven as OOB read plus digest mismatch with no state write (unicorn harness).
- pre-AVB inputs all triaged: GPT gate negative (avb_slot_verify unconditional, no vbmeta literals), UEFI vars dead (six reads, none reach unlock), misc, steady, secdata, sec_efs and abl_x show no content-driven length reaching a copy, Odin dispatcher fail-closed with anti-rollback.
- public CVEs do not land: GBL component absent, SPU bugs live in another processor with no bridge to engmode, secure world lateral blocked by per-TA RPMB namespace with no TA changing across builds.

what is left for someone else:
- per-command USB parse-before-verify audit in Odin (3-5 d, no lead).
- full loop of the steady walker plus misc parser (1-2 d, pattern against it so far).
- monthly new-BL patch-diff, cheap lottery.

nothing state-changing was run to get here and none is needed to verify it, just rerun the scripts below.

## Safety Rules

Audit scripts do not invoke token installation or removal APIs, mutating ESS commands, fuse commands, or `AT+FRPUNLCK`, nor do they write to partitions. Partition reading uses `dd if=...` on the device, redirecting bytes to a file on the host.

## Structure

- `device/`: properties, bootconfig, services, processes, and runtime evidence.
- `partitions/`: images read directly from the relevant block devices.
- `binaries/`: device executables and libraries.
- `framework/`: JARs, APKs, manifests, and init files.
- `decompiled/`: derived extraction and disassembly outputs.
- `logs/`: execution logs from collectors and analyzers.
- `manifests/`: origin, size, SHA-256, timestamp, and collection command.
- `notes/`: audit notes and report.
- `scripts/`: reproducible procedures.

## Collectors

```sh
./scripts/collect_runtime_readonly.sh
./scripts/pull_artifacts_readonly.sh
```

Both require `adb shell su -c id` to work. Manifests use UTC timestamps.

## Analyzers and Report

```sh
python3 scripts/abl_audit.py
python3 scripts/ta_audit.py
python3 scripts/native_audit.py
python3 scripts/dex_audit.py
./scripts/services_dex_audit.sh
./scripts/probe_engmode_readonly.sh
./scripts/build_derived_manifest.py
```

`abl_audit.py` requires `radare2` (`r2`) available on `PATH`; a local `tools/` tree is used automatically when present, otherwise install radare2 via your package manager.

`dex_audit.py` aborts with a non-zero exit and lists missing packages when the HLOS APKs it needs (currently `com.android.settings` and `com.samsung.android.kmxservice`) are not present in `framework/`. `framework/SecSettings.apk` is the usual source for `com.android.settings` and is gitignored because it exceeds GitHub's file size limit; if it was not collected by `pull_artifacts_readonly.sh` the gate will fire. Collect it once and rerun before regenerating the HLOS evidence.

The consolidated report is `notes/findings.md`. Historical public ESS evidence is kept separately in `notes/historical-daseul-ess.md`; it is context for mapping the old DASEUL schema, not proof of current firmware behavior. Extracts in `decompiled/` record VA/RVA, file offsets, hashes, and disassembly needed to reproduce each conclusion. `decompiled/dex-hlos-oem-policy-evidence.txt` scans decoded DEX in every collected top-level APK and JAR, including `services.jar`, Settings, and both the stock and installed KMX APKs, for HLOS/KMX OEM-unlock policy references. Its `iter_dex()` path splits concatenated DEX 041 entries into logical units before decoding; names such as `classes.dex#logical-2@0x99d3f8` identify the container offset. `decompiled/oem-lock-service-evidence.txt` records the separate `framework.jar`/`services.jar` reconstruction of `OemLockService`, the AIDL/HIDL adapters, the PDB fallback and the VaultKeeper cross-check. Its coverage states are deliberately narrow: `MATCH` means a reportable decoded DEX reference, `NO_MATCH_IN_COVERED_ARTIFACTS` means no match in the listed hashes, and `NOT_COLLECTED` means the package needed to answer that question is absent. `build_derived_manifest.py` records the hash, size, and producer of scripts, extracts, and reports.
