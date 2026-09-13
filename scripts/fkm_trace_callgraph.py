#!/usr/bin/env python3
"""Static callgraph trace for a set of target VAs inside a QSEE TA (read-only).

Tries, in order, every way a PIC ARM64 binary can reference a function
address without a plain immediate `bl`:

  1. direct `bl #imm`               -- ordinary direct calls
  2. `adrp`+`add` pair               -- materializing an absolute address
                                        for an indirect call/store
  3. R_AARCH64_RELATIVE addends      -- how PIC binaries populate
                                        function-pointer tables/vtables
                                        at load time
  4. .dynsym symbol values           -- named/exported entry points

Reports which of the four found each target, or none. Never mutates the
input, never touches a device.
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path
import importlib.util

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ta_audit_generic", ROOT / "scripts" / "ta_audit_generic.py")
TAG = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TAG)

MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

R_AARCH64_RELATIVE = 1027


def scan_direct_bl(ta, targets: set[int]) -> dict[int, list[int]]:
    code_va = int(ta.loads[0]["p_vaddr"])
    code_off = int(ta.loads[0]["p_offset"])
    code_size = int(ta.loads[0]["p_filesz"])
    code = ta.data[code_off:code_off + code_size]
    hits = {t: [] for t in targets}
    for insn in MD.disasm(code, code_va):
        if insn.mnemonic == "bl":
            try:
                dest = int(insn.op_str.strip().lstrip("#"), 0)
            except ValueError:
                continue
            if dest in hits:
                hits[dest].append(insn.address)
    return hits


def scan_adrp_add(ta, targets: set[int]) -> list[tuple[int, str, int]]:
    code_va = int(ta.loads[0]["p_vaddr"])
    code_off = int(ta.loads[0]["p_offset"])
    code_size = int(ta.loads[0]["p_filesz"])
    code = ta.data[code_off:code_off + code_size]
    reg_page: dict[str, int] = {}
    out = []
    for insn in MD.disasm(code, code_va):
        if insn.mnemonic == "adrp":
            m = re.match(r"(x\d+|w\d+),\s*#(0x[0-9a-f]+)", insn.op_str)
            if m:
                reg_page[m.group(1)] = int(m.group(2), 16)
        elif insn.mnemonic == "add":
            m = re.match(r"(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+)", insn.op_str)
            if m and m.group(2) in reg_page:
                total = reg_page[m.group(2)] + int(m.group(3), 16)
                if total in targets:
                    out.append((insn.address, m.group(1), total))
    return out


def scan_rela_addends(ta, targets: set[int]) -> list[tuple[int, int]]:
    dyn = ta.dynamic()
    if 7 not in dyn:  # DT_RELA
        return []
    rela_off = ta.va_to_file(dyn[7])
    n = dyn[8] // dyn[9]
    hits = []
    for i in range(n):
        base = rela_off + i * dyn[9]
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", ta.data, base)
        if (r_info & 0xffffffff) == R_AARCH64_RELATIVE and r_addend in targets:
            hits.append((r_offset, r_addend))
    return sorted(hits)


def scan_dynsym(ta, targets: set[int]) -> list[tuple[int, str]]:
    dyn = ta.dynamic()
    if 6 not in dyn or 5 not in dyn:  # DT_SYMTAB / DT_STRTAB
        return []
    symtab_off = ta.va_to_file(dyn[6])
    strtab_off = ta.va_to_file(dyn[5])
    hits = []
    off = symtab_off
    while off + 24 <= strtab_off:
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", ta.data, off)
        if st_value in targets:
            p = strtab_off + st_name
            name = b""
            while ta.data[p:p + 1] != b"\x00":
                name += ta.data[p:p + 1]
                p += 1
            hits.append((st_value, name.decode(errors="replace")))
        off += 24
    return hits


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", type=Path, required=True)
    ap.add_argument("--targets", type=str, required=True,
                     help="comma-separated hex VAs, e.g. 0x1aec8,0x1afc8")
    args = ap.parse_args()

    targets = {int(x, 0) for x in args.targets.split(",") if x.strip()}
    ta = TAG.Trustlet(args.image.resolve())

    print(f"Image: {args.image}  targets: {[hex(t) for t in sorted(targets)]}")
    print()

    direct = scan_direct_bl(ta, targets)
    print("[1] direct `bl` callers:")
    for t, callers in direct.items():
        print(f"    0x{t:x}: {[hex(c) for c in callers] or 'none'}")

    adrp = scan_adrp_add(ta, targets)
    print("[2] adrp+add address materialization:")
    print(f"    {adrp or 'none found'}")

    rela = scan_rela_addends(ta, targets)
    print("[3] R_AARCH64_RELATIVE relocation addends (vtable/fnptr-table slots):")
    print(f"    {[(hex(o), hex(a)) for o, a in rela] or 'none found'}")

    dynsym = scan_dynsym(ta, targets)
    print("[4] dynamic symbol table entries:")
    print(f"    {dynsym or 'none found'}")

    unresolved = targets - set(direct.keys()).union(
        {a for _, _, a in adrp}, {a for _, a in rela}, {v for v, _ in dynsym})
    # direct bl entries with empty caller lists still count as "checked, not found"
    unresolved = {t for t in targets if not direct.get(t) and
                  t not in {a for _, _, a in adrp} and
                  t not in {a for _, a in rela} and
                  t not in {v for v, _ in dynsym}}
    print()
    print(f"UNRESOLVED (no reference found by any of the 4 methods): "
          f"{[hex(t) for t in sorted(unresolved)] or 'none -- all targets resolved'}")


if __name__ == "__main__":
    main()
