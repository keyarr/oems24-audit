#!/usr/bin/env python3
"""Read-only helper: annotate a function range with every string literal it
materialises via adrp+add, in address order. Useful for naming anonymous
functions from their DebugPrint(__func__) arguments.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG  # noqa: E402

from em_pw import load  # noqa: E402


def function_strings(img, lo: int, hi: int, minlen: int = 3):
    out = []
    pending = {}
    for addr in img.order:
        if not (lo <= addr < hi):
            continue
        ins = img.insns[addr]
        if ins.mnemonic == "adrp" and ins.operands and ins.operands[0].type == ARM64_OP_REG:
            pending[ins.reg_name(ins.operands[0].reg)] = (
                addr,
                ins.operands[1].imm & ~0xFFF,
            )
            continue
        if ins.mnemonic == "add" and len(ins.operands) == 3:
            dst = ins.reg_name(ins.operands[0].reg)
            src = ins.reg_name(ins.operands[1].reg)
            if dst == src and dst in pending and ins.operands[2].type == ARM64_OP_IMM:
                adrp_at, page = pending.pop(dst)
                rva = page + ins.operands[2].imm
                s = img.cstr(rva, 160)
                if len(s) >= minlen and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s):
                    out.append((addr, rva, s))
                continue
        if ins.operands and ins.operands[0].type == ARM64_OP_REG:
            pending.pop(ins.reg_name(ins.operands[0].reg), None)
    return out


if __name__ == "__main__":
    img = load(sys.argv[1])
    lo = int(sys.argv[2], 16)
    hi = int(sys.argv[3], 16)
    for addr, rva, s in function_strings(img, lo, hi):
        print("0x%06x  0x%06x  %r" % (addr, rva, s))
