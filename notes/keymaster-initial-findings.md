# keymaster / vaultkeeper initial findings (static only, no patch-diff)

device: SM-S928B / e3q, S928BXXU5DZDP, One UI 8.5 / Android 16, SPL 2026-04-05
target CVE: CVE-2026-21046 (TOCTOU em fabricKeymaster -> ACE, corrigido SMR Jul-2026 R1)
scope: read-only static analysis. no device mutation, no PoC, no exploit.
classification of every pattern below: **POSSIBLE**, not CONFIRMED. closing needs the SMR Jul-2026 patch-diff (out of repo).

## what was produced (decompiled/)
- keymaster-imports.txt   : ELF header, PT_LOAD, page align, 87 imports (78 qsee_*), first 40 PLT veneers disasm
- keymaster-strings.txt   : keyword string scan (rsa/attest/lock/unlock/bootloader/fuse/secure/rpmb/...)
- keymaster-functions.txt : 1112 prologue candidates (frame sizes) + full disasm of BTI/PAC ones
- fkeymaster-V1-ndk-imports.txt : 29 AIDL Bp methods with recovered txn ids + per-method disasm
- keymaster-aidl-crossref.txt   : AIDL surface x TA state-consuming functions
- vk-imports.txt / vk-strings.txt / vk-functions.txt : same for VaultKeeper
- VaultKeeper-V1-ndk-imports.txt : 11 AIDL Bp methods (verifyCertificate=7, write=3, read=4, migrateToSecureStorage=8, ...)
- vk-aidl-crossref.txt : VaultKeeper surface x TA state functions

scripts added: ta_audit_generic.py (reuses Trustlet), ta_aidl.py, ta_crossref.py (parameterized fkeymaster/vaultkeeper).

## keymaster TA: state consumed before unlock decision (audit target)
functions that call qsee_get_secure_state / fuse / rpmb imports, or reference lock/unlock literals:
- 0x18e90  qsee_blow_sw_fuse        (fuse blow)
- 0x18df0  qsee_is_sw_fuse_blown    (fuse-blown check)
- 0x1cba4  qsee_is_sw_fuse_blown    (fuse-blown check)
- 0x1d31c  qsee_get_secure_state    (device secure/lock state)
- 0x1d3c0  qsee_query_rpmb_enablement
- 0x3c374  "lock"/"unlock" literals
- 0x3fd00  "lock"/"unlock" literals

these are the TA internals that read/write the very state ABL/AVB consult before the
bootloader unlock decision. anything that alters them between a check and a use is the
candidate primitive.

## AIDL surface (fkeymaster) most likely to reach the above
txn recovered from NDK Bp stubs:
  generateKey(1) importKey(4) secureImportKey(20) secureImportKeySHA1(21)
  commonHandler(29) keyRegister(23) keyRecovery(24)  (+ encrypt/decrypt/sign/export etc.)
importKey / secureImportKey / commonHandler are the obvious TOCTOU candidates per the CVE
description (fabricKeymaster: check-then-use on attacker-influenced key/material state).

## VaultKeeper (vk.img) oemlock edge
VaultKeeper is the Knox/vault gate in front of OEM unlock. TA functions that consult state:
- 0x17fc  qsee_get_secure_state
- 0x308c  qsee_is_sw_fuse_blown
AIDL methods most likely to reach them: verifyCertificate(7), write(3), read(4),
migrateToSecureStorage(8), initialize(1).
any TOCTOU between the secure_state/fuse check and the persistent write in these handlers
is a candidate primitive that changes unlock eligibility consumed by ABL/AVB.
(note: vk string xref for "lock"/"bootloader" did not resolve via adrp+add; vk appears to
load those literals through a different path. the import-based state functions above stand
on their own as evidence.)

## open items / what blocks confirmation
1. exact 1:1 AIDL-txn -> TA-opcode -> handler map not statically recoverable from a
   sectionless TA without symbols; the HLOS service uses a jump table and the TA command
   router was not resolved. needs the SMR Jul-2026 TA build to diff.
2. the lock/unlock TA functions (0x3c374, 0x3fd00) need disasm + callgraph to confirm they
   sit on the key-import path vs. an unrelated settings path.
3. no anchor-blob / trust-anchor layout assumed (unlike em); nothing claimed about em offsets.

## bootloader patch-diff done (DZDP device image vs DZG1 bootloader tar)
we got the Jul-2026 build: BL_S928BXXS6DZG1_...tar.md5 (in repo root). the keymaster TA inside is
`keymint.mbn` (lz4, decompressed to partitions_extra/keymint-dzg1-jul2026.mbn).
full result in decompiled/bootloader-dzdp-vs-dzg1-diff.txt.

**keymaster TA is BYTE-IDENTICAL between DZDP and DZG1.** confirmed 3 ways:
- ta_patchdiff.py on keymaster.img vs keymint-dzg1-jul2026.mbn: common=1112, changed=0.
- sha256 of the code PT_LOAD (0..0x5b2dc) is the same in both.
- every other Secure World partition is also identical except devcfg.mbn:
  tz, vaultkeeper, tz_kg, tz_iccc, bksecapp, storsec, aop, aop_devcfg, cpucp, shrm,
  xbl_config, hypvm, tz_hdm all IDENTICAL. ~16 TAs compared.

only changed artifact: **devcfg.mbn** (QTI device config / fuse policy blob). a ~5KB region
differs at file offset 0x54442..0x55917 (packed binary config, no readable strings). that is the
single concrete delta in the whole bootloader.

abl.elf (DZG1) differs from partitions/ baselines (abl-oneui8-czd1.elf, abl.img, abl-oneui7.elf)
but we have no clean DZDP abl in the corpus (device was not connected / only keymaster pulled from
it), so the abl diff does not isolate the CVE.

conclusion: the patch for CVE-2026-21046 is **NOT evidenced inside the keymaster TA** from this
artifact. the fabricKeymaster component that the CVE names is most likely the HLOS HAL
(fkeymaster-service / fkeymaster-V1-ndk.so / fabric_crypto), which is NOT part of a bootloader tar.
three possibilities, none confirmable from the bootloader tar alone:
  (1) fix is in the HLOS HAL -> need a pull of /vendor/bin/hw/vendor.samsung.hardware.security.fkeymaster*
      and the fabric_crypto / keystore TLC off the rooted device (KernelSU). device not connected right now.
  (2) the DZDP keymaster TA on the device was already post-fix (OTA-applied TA), so there is no
      vulnerable "before" in this corpus -> need a pre-Jul-2026 keymaster TA to diff.
  (3) the DZG1 bootloader is not actually the SMR Jul-2026 fixed build.

classification stays **UNCONFIRMED**. the patch-diff did NOT confirm CVE-2026-21046 in the TA.

## next step (blocked on input)
- connect the device (adb over KernelSU) and pull the fkeymaster HLOS HAL + fabric_crypto so we can
  statically read the actual TOCTOU on the vulnerable DZDP build, OR
- drop a DZG1 HLOS image, OR
- confirm DZG1 is truly the fixed build and provide a pre-fix keymaster TA.
absent that, the only further bootloader-side work is reverse-engineering devcfg.mbn (low value
without the QTI devcfg format).
