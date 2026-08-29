#!/usr/bin/env python3
"""Cross-reference the fkeymaster AIDL surface against the keymaster TA.

Two independent static recoveries are joined:
  * AIDL method -> transaction id  (from the NDK shim, Tarefa 2)
  * TA function -> what state it consults (secure state / fuse / lock / unlock /
    bootloader strings, via import veneer xref and adrp+add string xref)

A precise 1:1 AIDL-txn -> TA-opcode -> handler map is NOT recoverable from a
sectionless TA without symbols; that step needs the SMR Jul-2026 patch-diff.
What this produces is the set of TA functions that consume lock/fuse/secure
state (the audit's actual target: state read before the bootloader unlock
decision) and flags which AIDL methods most plausibly reach them.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile

import importlib.util
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ta_audit_generic",
                                             ROOT / "scripts" / "ta_audit_generic.py")
TAG = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TAG)

KM = ROOT / "partitions_extra" / "keymaster.img"
NDK = ROOT / "binaries_extra" / "vendor.samsung.hardware.security.fkeymaster-V1-ndk.so"
OUT = ROOT / "decompiled"


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--image", type=Path, default=KM)
    ap.add_argument("--iface", type=str, default="Fkeymaster")
    ap.add_argument("--ndk", type=Path, default=NDK)
    ap.add_argument("--label", type=str, default=None)
    args, _ = ap.parse_known_args()
    KM_i = args.image.resolve()
    IFACE = args.iface
    NDK_i = args.ndk.resolve()
    LABEL = args.label or KM_i.stem

    ta = TAG.Trustlet(KM_i)
    symbols, plt = ta.symbols_and_plt()
    plt_by_va = {pv: name for pv, _, _, _, name in plt}

    # TA code disasm
    code = ta.loads[0]
    cstart = int(code["p_vaddr"]); csize = int(code["p_filesz"])
    MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); MD.detail = True
    insns = list(MD.disasm(ta.data[ta.va_to_file(cstart): ta.va_to_file(cstart) + csize], cstart))

    # function starts (stp xN,xM,[sp]! store-pair pre-index to sp)
    def word_at(foff): return struct.unpack_from("<I", ta.data, foff)[0]
    funcs = [0]
    foff = ta.va_to_file(cstart); end = foff + csize - 4
    while foff <= end:
        w = word_at(foff)
        if (w & 0xFF000000) == 0xA9000000 and ((w >> 5) & 0x1F) == 0x1F:
            funcs.append(cstart + (foff - ta.va_to_file(cstart)))
        foff += 4
    funcs = sorted(set(funcs))

    def owner(va: int) -> int:
        best = 0
        for f in funcs:
            if f <= va:
                best = f
        return best

    # ---- import-veneer xref: which functions call stateful imports ----
    state_imports = {
        "qsee_get_secure_state": "secure_state",
        "qsee_blow_sw_fuse": "fuse_blow",
        "qsee_is_sw_fuse_blown": "fuse_blown",
        "qsee_query_rpmb_enablement": "rpmb_en",
    }
    import_owner = {tag: set() for tag in state_imports.values()}
    for ins in insns:
        if ins.mnemonic == "bl" and ins.op_str.startswith("#0x"):
            tgt = int(ins.op_str[1:], 16)
            name = plt_by_va.get(tgt)
            if name in state_imports:
                import_owner[state_imports[name]].add(owner(ins.address))

    # ---- string xref: lock / unlock / bootloader ----
    def string_vas(needle: bytes):
        out = []
        cur = 0
        while True:
            cur = ta.data.find(needle, cur)
            if cur < 0:
                break
            try:
                out.append(ta.file_to_va(cur))
            except ValueError:
                pass
            cur += 1
        return out

    str_owner = {}
    for kw, needle in [("lock", b"lock"), ("unlock", b"unlock"), ("bootloader", b"bootloader")]:
        for tva in string_vas(needle):
            pg = tva & ~0xFFF
            off = tva - pg
            for i, ins in enumerate(insns):
                if ins.mnemonic == "adrp" and "#0x" in ins.op_str:
                    try:
                        base = int(ins.op_str.split("#")[1], 16)
                    except ValueError:
                        continue
                    if base != pg:
                        continue
                    nxt = insns[i + 1] if i + 1 < len(insns) else None
                    if nxt and nxt.mnemonic in ("add", "movk") \
                            and nxt.op_str.split(",")[0].strip() == ins.op_str.split(",")[0].strip():
                        m = re.search(r"#(-?0x[0-9a-fA-F]+|\d+)", nxt.op_str)
                        imm = int(m.group(1), 0) if m else -1
                        if imm == off:
                            str_owner.setdefault(kw, set()).add(owner(ins.address))

    # ---- AIDL method -> txn (reuse ta_aidl logic by re-deriving lightly) ----
    import subprocess
    def dm(name): return subprocess.run(["c++filt", name], capture_output=True, text=True).stdout.strip()
    e = ELFFile(open(NDK_i, "rb"))
    ndk_syms = [s.name for s in e.get_section_by_name(".dynsym").iter_symbols() if s.name]
    marker_cls = f"BpSeh{IFACE}::"
    aidl = []
    for n in ndk_syms:
        d = dm(n)
        pos = d.find(marker_cls)
        if pos < 0 or "(" not in d:
            continue
        method = d[pos + len(marker_cls):].split("(")[0]
        if not method or method[0] in "~" or method in ("getInterfaceHash", "getInterfaceVersion", f"BpSeh{IFACE}"):
            continue
        aidl.append(method)
    # read txn from the imports file we produced in Tarefa 2
    txn_file = OUT / f"{IFACE}-V1-ndk-imports.txt"
    txn_of = {}
    if txn_file.exists():
        for line in txn_file.read_text().splitlines():
            m = re.match(r"\s*txn=(\d+)\s+VA=0x[0-9a-f]+ sz=\d+\s+(\w+)", line)
            if m:
                txn_of[m.group(2)] = int(m.group(1))
    aidl_sorted = sorted(((m, txn_of.get(m, -1)) for m in set(aidl)), key=lambda r: (r[1] if r[1] >= 0 else 999, r[0]))

    # ---- assemble report ----
    lines = [
        f"{LABEL.upper()} AIDL <-> TA CROSS-REFERENCE (static, no patch-diff)",
        "",
        f"TA {KM_i.relative_to(ROOT)}  SHA256 {TAG.sha256(KM_i)}",
        f"NDK SHIM {NDK_i.relative_to(ROOT)}",
        "",
        "LIMITATION",
        "  A 1:1 AIDL-txn -> TA-opcode -> handler map is not recoverable from a",
        "  sectionless TA without symbols.  The HLOS service dispatches via a jump",
        "  table and the TA command router was not statically resolvable.  Closing",
        "  the exact mapping requires the SMR Jul-2026 patch-diff (out of repo).",
        "  What follows is the recoverable, evidence-backed subset.",
        "",
        "AIDL METHODS (txn recovered from the NDK Bp stubs, Tarefa 2)",
    ]
    for m, t in aidl_sorted:
        lines.append(f"  txn={t:<3} {m}")

    lines += ["", "TA FUNCTIONS THAT CONSUME LOCK/FUSE/SECURE STATE",
              "  (state read before the bootloader unlock decision; audit target)", ""]
    state_funcs = set()
    for tag, owners in import_owner.items():
        for o in owners:
            state_funcs.add(o)
    for kw, owners in str_owner.items():
        for o in owners:
            state_funcs.add(o)
    for f in sorted(state_funcs):
        tags = []
        for tag, owners in import_owner.items():
            if f in owners:
                tags.append(tag)
        for kw, owners in str_owner.items():
            if f in owners:
                tags.append(f"str:{kw}")
        lines.append(f"  0x{f:06x}  consumes: {', '.join(tags) if tags else '?'}")
    lines += ["", "DETAIL: import-veneer xref (function -> stateful TEE call)",
              "  qsee_get_secure_state  = device secure/lock/fuse state"]
    for tag, owners in import_owner.items():
        lines.append(f"  {tag}: " + (", ".join(f"0x{o:06x}" for o in sorted(owners)) or "none"))
    lines += ["", "DETAIL: string xref (function -> lock/unlock/bootloader literal)"]
    for kw, owners in str_owner.items():
        lines.append(f"  {kw}: " + (", ".join(f"0x{o:06x}" for o in sorted(owners)) or "none"))

    if IFACE == "Fkeymaster":
        lines += ["", "PLAUSIBLE ENTRY FOR CVE-2026-21046 TOCTOU",
                  "  The AIDL methods that move key material / invoke the generic handler are the",
                  "  most likely callers of the lock/fuse-state-consuming TA functions above:",
                  "    importKey(4), secureImportKey(20), secureImportKeySHA1(21),",
                  "    commonHandler(29), keyRegister(23), keyRecovery(24), generateKey(1).",
                  "  These should be diffed against the SMR Jul-2026 TA to confirm the TOCTOU",
                  "  between state check and use inside fabricKeymaster."]
    else:
        lines += ["", "PLAUSIBLE OEMLOCK ENTRY (VaultKeeper gates bootloader unlock)",
                  "  VaultKeeper is the Knox/vault gate in front of OEM unlock.  The AIDL methods",
                  "  most likely to reach the secure_state(0x17fc)/fuse_blown(0x308c) TA functions",
                  "  are the certificate / persistent-state ones:",
                  "    verifyCertificate(7), write(3), read(4), migrateToSecureStorage(8), initialize(1).",
                  "  Any TOCTOU between the secure_state check and the persistent write is the",
                  "  candidate primitive consumed by ABL/AVB before the unlock decision."]

    out = OUT / f"{LABEL}-aidl-crossref.txt"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)} ({len(chr(10).join(lines).encode())} bytes)")
    print("state-consuming TA functions:", [f"0x{f:x}" for f in sorted(state_funcs)])


if __name__ == "__main__":
    main()
