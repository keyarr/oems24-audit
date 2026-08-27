# Samsung Galaxy S24 Ultra Independent Audit

Special thanks to adfree on xda forums for helping with the engineering mode/token side.

Read-only audit of the One UI 8+ OEM unlock removal on the SM-S928B. This tree holds primary evidence collected from the device in read-only mode and the artifacts used for static analysis.

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

The consolidated report is `notes/findings.md`. Historical public ESS evidence is kept separately in `notes/historical-daseul-ess.md`; it is context for mapping the old DASEUL schema, not proof of current firmware behavior. Extracts in `decompiled/` record VA/RVA, file offsets, hashes, and disassembly needed to reproduce each conclusion. `decompiled/dex-hlos-oem-policy-evidence.txt` scans decoded DEX in every collected top-level APK and JAR, including `services.jar`, Settings, and both the stock and installed KMX APKs, for HLOS/KMX OEM-unlock policy references. Its `iter_dex()` path splits concatenated DEX 041 entries into logical units before decoding; names such as `classes.dex#logical-2@0x99d3f8` identify the container offset. `decompiled/oem-lock-service-evidence.txt` records the separate `framework.jar`/`services.jar` reconstruction of `OemLockService`, the AIDL/HIDL adapters, the PDB fallback and the VaultKeeper cross-check. Its coverage states are deliberately narrow: `MATCH` means a reportable decoded DEX reference, `NO_MATCH_IN_COVERED_ARTIFACTS` means no match in the listed hashes, and `NOT_COLLECTED` means the package needed to answer that question is absent. `build_derived_manifest.py` records the hash, size, timestamp, and producer of scripts, extracts, and reports.
