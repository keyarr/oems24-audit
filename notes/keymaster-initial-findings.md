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

## follow-up: AFTER baseline obtained, fix located (2026-09)

the blocked input arrived: fabrickeymaster SPU split set carrying the SMR
Jul-2026 R1 fix (partitions_extra/spu-firmware-dzg1/, hashes + method in
decompiled/fabrickeymaster-toctou-fix-evidence.txt; source per issue #1:
full DZG1 firmware NON-HLOS.bin, no finer build string).

result: the fix is in the fabrickeymaster SPU firmware, a fourth location
beyond the three guesses above (not the QSEE keymaster TA, not the HLOS HAL).
CORRECTION: the first pass blamed six dispatch stubs (stamp -> check shape),
but content matching refutes it: both builds contain the same 8 stamp stubs
and the same 6 check stubs, so that pattern predates the patch (same-VA
comparison across a shifted binary compared stamp body vs check body). the
true delta is two functions: validator 0x1d24 (limit 0x4b000 -> 0x4b080) and
dispatcher 0x23ac (+34 ins: entry id-range gate at 0x4b081, resolve via
0x8d4, re-validate via 0x1d24, cmp + latch of [x23+#4] before the
w24-keyed table dispatch). full evidence in
decompiled/fabrickeymaster-toctou-fix-evidence.txt,
decompiled/fabrickeymaster-dzdp-vs-dzg1-patchdiff.txt (ta_patchdiff.py,
unaltered) and decompiled/fabrickeymaster-mnemonic-classify.txt (raw tool
output; its "56 real" count is mostly misalignment noise, see evidence file).
repro: scripts/reassemble_mdt.py on each split set, then the two scripts
above plus scripts/fkm_trace_callgraph.py.

reclassification: fix location CONFIRMED (SPU firmware, 0x23ac path), precise
vulnerable statement NOT yet written (needs [x23+#4] dataflow across HLOS
calls + table-entry resolution). intra-TA thread race unlikely (GPAppLib
serial serving, no thread/mutex imports); next look is the HLOS HAL
(fkeymaster-service, fabric_crypto: pulled, never analyzed), not TA threads.
the old QSEE-vs-SPU proximity table is dead (cross-image deltas).

## next step, original (superseded by the follow-up above, kept for history)
- connect the device (adb over KernelSU) and pull the fkeymaster HLOS HAL + fabric_crypto so we can
  statically read the actual TOCTOU on the vulnerable DZDP build, OR
- drop a DZG1 HLOS image, OR
- confirm DZG1 is truly the fixed build and provide a pre-fix keymaster TA.
absent that, the only further bootloader-side work is reverse-engineering devcfg.mbn (low value
without the QTI devcfg format).

## follow-up 2026-10-12: HLOS fkeymaster string-level triage (offline, read-only)
inputs (gitignored raw pulls, not versioned): binaries_extra/
vendor.samsung.hardware.security.fkeymaster-service (75464 B, ELF64),
vendor.samsung.hardware.security.fkeymaster-V1-ndk.so (84256 B),
fabric_crypto (119928 B). method: ELF header + ascii strings only, no
disasm, no device.
result: fkeymaster-service is an AIDL Bn
(vendor.samsung.hardware.security.fkeymaster.ISehFkeymaster) + QSEECom
client to "fabrickeymaster" (QSEECom_start_app/send_cmd/set_bandwidth/
shutdown_app strings + service.cpp path
vendor/samsung/interfaces/security/fkeymaster/aidl/default/service.cpp).
fabric_crypto is a separate crypto service (IFabricCryptoService,
Fkeymaster::ecdh/decryptBegin/signBegin/generatekey/keyRecovery/
exportKey/keyRegister strings). case-insensitive counts for
devinfo/IsUnlocked/bootloader/avb/verified/rpmb/engmode/steady are zero
in all three except mutex unlock (2/1/1 hits for "unlock" = unlockEv).
"qsee" 0, "QSEECom" 9/0/0, "spcom" 0.
verdict: HLOS side is transport to the SPU/QSEE fabrickeymaster, not a
demonstrated writer of devinfo/AVB state. string-level only; full
per-method dispatch + [x23+#4] dataflow across HLOS calls (needed for
the precise CVE-2026-21046 vulnerable statement) remains open. no edge
to unlock shown; do not confuse the SPU bug with an unlock route.
repro: file + python3 strings scan as in decompiled/cve triage method;
full close needs capstone disasm of the Bn onTransact table, out of
scope for this pass.

## decision 2026-10-12: freeze fkeymaster for unlock (P3 answered, offline, read-only)
scope: HLOS dispatch (fkeymaster-service/V1-ndk/fabric_crypto) + SPU flow
  [x23+#4] around the 0x23ac fix. No general audit; five questions only.
  SPU ELFs: partitions_extra/fabrickeymaster-dzdp.elf (sha 1c3306bb...) vs
  -dzg1.elf (sha d4c25a36...), code PT_LOAD file 0x1000 <-> VA 0.
  HLOS: fkeymaster-service (75464 B, sha a8250592...), V1-ndk.so (84256 B,
  sha a8636b74..., 29 Bp txns 1..29 per fkeymaster-V1-ndk-imports.txt),
  fabric_crypto (119928 B, sha 852544d7...).
- Qual dado e validado? Validator 0x1d24: ldr w8,[x0,#4]; w19=w8+8;
  reject unless w19 <= limit (BEFORE cmp w19,#0x4b,lsl#12 = 0x4b000 at
  0x1d40; AFTER mov w20,#0xb080/movk #4 = 0x4b080 + cmp w19,w20 at
  0x1d3c-0x1d48). In NEW 0x23ac: entry id-range gate x23 vs 0x4b081
  (0x23cc-0x23d8); resolve bl 0x8d4(x24,w23,1)->x23 (0x2498-0x24a8);
  validate [x23+#8] via bl 0xde74 (0x24b0-0x24bc, BEFORE twin was 0xddec);
  re-validate via bl 0x1d24 on [x23+#8] (0x2524-0x252c).
- Qual dado e consumido depois? ldr w8,[x23,#4] (0x2530); mov w24,w0
  (validator return); cmp w0,w8 (0x2538); on pass str w24,[x23,#4]
  (0x25b8 latch) then bl 0x1830 (bounded worker, rejects w2>7) and the
  w24-keyed table dispatch at the tail (base 0x105880+w24*16, entry+8
  called if non-null, bounded by cmp w24,#0x1f in BOTH builds).
- Onde ocorre a discrepancia? BEFORE trusted the resolver return
  (bl 0xddec -> mov w24,w0 at 0x23d4-0x23e0) with NO re-read/compare/latch
  of [x23+#4] on this path (zero str [x23,#4] in BEFORE 0x23ac). NEW adds
  re-read + cmp + latch before use. Window spans HLOS requests against the
  shared/persistent object, not TA threads (GPAppLib serial serving, 23
  PLT imports with no thread/mutex primitives).
- Qual estado persistente pode ser alterado? The latched object field
  [x23+#4] (heap object from 0x8d4 factory, malloc 0x10 + tag byte) plus
  whatever the w24-selected table entry + 0x1830 worker write. No evidence
  either is devinfo/AVB/RPMB/engmode state; HLOS string scan is zero for
  devinfo/bootloader/avb/verified/rpmb/engmode/steady in all three HLOS
  binaries (only mutex unlockEv 2/1/1; QSEECom 9/0/0; fabrickeymaster 1).
- Existe ligacao com o estado consultado pelo bootloader? NONE
  demonstrated. ABL consults devinfo+0x0d via IsUnlocked 0x41ed0 <->
  GetEMBit(3) 0xadae0 -> SetUnlocked 0x424cc -> AVB callback 0x51048 ->
  avb_slot_verify 0x18f98. No path from the SPU object/table dispatch to
  any of those was shown; SPU is a separate processor (S:C = escape to
  HLOS, not to QTEE/ABL). A real SPU bug that does not reach the unlock
  equation gets no more priority for being interesting.
verdict: FROZEN for unlock. Reopen only on: HLOS txn->object mapping
  showing [x23+#4] aliases bootloader-queried state, or a demonstrated
  SPU->QTEE/ABL edge. CVE-2026-21046 fix location stays CONFIRMED (SPU
  0x23ac + 0x1d24 limit); precise vulnerable statement stays open but
  out of scope for unlock.
