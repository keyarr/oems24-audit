#!/usr/bin/env python3
"""Odin USB deep audit stage 1: ordered trace per dispatcher func.

For each func in the parse-before-verify map, dump address-ordered events:
STRREF (blob contains enforcement/dispatcher keyword), BL (call target),
SIZEOP (length handling: ldr w1/w2, narrow load, add/mul/madd/lsl, sub sp).

Read-only, offline. Output is meant for human verdict copy-vs-verify order.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PE = ROOT / "decompiled" / "odin-oneui8.pe"
OUT = ROOT / "decompiled" / "odin-usb-deep-audit.txt"

sys.path.insert(0, str(ROOT / "scripts"))
from abl_string_xref import function_bounds as real_bounds, pe_layout, rva_to_file, sweep  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG  # noqa: E402

MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

FUNCS = [
    0x0309DC, 0x0405C0, 0x045504, 0x04A08C, 0x04CE90, 0x04E158,
    0x04E278, 0x04E570, 0x057478, 0x0577F0, 0x0579A8, 0x0593B0,
    0x05B640, 0x05B850, 0x05DAF0, 0x062EC0,
]

# PIT/token enforcement handlers (parse-before-verify map): the other half of
# the question. If packet length reaches a copy inside THESE funcs before their
# own STRREF, that is the flag. Dispatchers above decide routing; these decide auth.
PIT_FUNCS = [
    0x010570, 0x0127B0, 0x012C20, 0x014FD8, 0x024540,
]
TOKEN_FUNCS = [
    0x0593B0, 0x05B080, 0x05DAF0, 0x05F720, 0x060350, 0x061B10,
]

KEYWORDS = [
    "Not defined cmdid", "Only official", "KG locked", "Failed to verify token",
    "Remaining token use count", "SW REV CHECK FAIL", "Mismatched image",
    "SECURE CHECK FAIL", "doesn't check a signing", "doesn't check for arp",
    "BLInitToken", "BLReadToken", "BLWriteToken",
]


def func_range(image: bytes, layout: dict, start: int) -> tuple[int, int]:
    # reuse map bounds: find ret within 0x4000, same as function_bounds prologue=start
    code = image[start : start + 0x4000]
    end = start + 0x4000
    for ins in MD.disasm(code, start):
        if ins.mnemonic == "ret":
            end = ins.address + 4
            break
    # clamp to section
    return start, end


def main() -> int:
    data = PE.read_bytes()
    layout = pe_layout(data)
    # precompute all adrp/add resolved -> blob text for STRREF lookup
    pairs = []  # (adrp_rva, add_rva, resolved)
    pending: dict[str, tuple[int, int]] = {}
    for ins in sweep(data, layout):
        if ins.mnemonic == "adrp" and ins.operands and ins.operands[0].type == ARM64_OP_REG:
            pending[ins.reg_name(ins.operands[0].reg)] = (ins.address, ins.operands[1].imm & ~0xFFF)
            continue
        if ins.mnemonic == "add" and len(ins.operands) == 3:
            try:
                dst = ins.reg_name(ins.operands[0].reg)
                src = ins.reg_name(ins.operands[1].reg)
            except Exception:
                continue
            if dst == src and dst in pending and ins.operands[2].type == ARM64_OP_IMM:
                a, page = pending[dst]
                pairs.append((a, ins.address, page + ins.operands[2].imm))
                pending.pop(dst, None)
                continue
    # index by add_rva for quick lookup
    by_add = {a: (p, r) for p, a, r in pairs}

    lines = []
    lines.append("ODIN USB DEEP AUDIT stage 1: ordered trace per func")
    lines.append(f"input: decompiled/odin-oneui8.pe ({len(data)} B)")
    lines.append("legend: STRREF=verify/dispatch string materialised, BL=call,")
    lines.append("  SIZEOP=length handling (ldr w1/w2, narrow load, add/mul/lsl, sp sub).")
    lines.append("  Verdict rule: copy/alloc with packet length BEFORE first STRREF/verify = flag.")
    lines.append("")

    for f in FUNCS:
        lo, hi = func_range(data, layout, f)
        off = rva_to_file(layout, lo)
        if off is None:
            lines.append(f"== func 0x{f:06x}: (unmapped)")
            continue
        code = data[off : off + (hi - lo)]
        lines.append(f"== func 0x{f:06x} [0x{lo:06x},0x{hi:06x}) ({(hi-lo)//4} words)")
        first_strref = None
        for ins in MD.disasm(code, lo):
            a = ins.address
            m = ins.mnemonic
            o = ins.op_str
            if a in by_add:
                _, resolved = by_add[a]
                fo = rva_to_file(layout, resolved)
                blob = data[fo : fo + 200] if fo is not None else b""
                hit = next((k for k in KEYWORDS if k.encode() in blob), None)
                if hit:
                    lines.append(f"  0x{a:06x} STRREF {hit!r} (blob 0x{resolved:06x})")
                    if first_strref is None:
                        first_strref = a
                    continue
            if m == "bl" and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
                tgt = ins.operands[0].imm
                # classify target with real bounds (not fixed window): size + STRREF inside target
                toff = rva_to_file(layout, tgt)
                tag = ""
                if toff is not None:
                    try:
                        tlo, thi = real_bounds(data, layout, tgt)
                        n = (thi - tlo) // 4
                    except Exception:
                        tlo, thi, n = tgt, tgt + 0x400, 256
                    tag = f" (tgt {n}w)"
                    has_str = False
                    tcode = data[rva_to_file(layout, tlo): rva_to_file(layout, tlo) + (thi - tlo)]
                    from capstone import Cs as _Cs, CS_ARCH_ARM64 as _A, CS_MODE_LITTLE_ENDIAN as _L
                    _md = _Cs(_A, _L); _md.detail = True
                    for ins2 in _md.disasm(tcode, tlo):
                        if ins2.address in by_add:
                            _, r2 = by_add[ins2.address]
                            fo2 = rva_to_file(layout, r2)
                            blob2 = data[fo2 : fo2 + 200] if fo2 is not None else b""
                            if any(k.encode() in blob2 for k in KEYWORDS):
                                has_str = True
                                break
                    tag += " VERIFY" if has_str else " helper/copy?"
                lines.append(f"  0x{a:06x} BL 0x{tgt:06x}{tag}")
            elif m == "blr":
                lines.append(f"  0x{a:06x} BLR {o}  <-- indirect (BootServices/CopyMem? check preceding ldr)")
            elif m in ("add", "mul", "madd", "msub", "lsl", "lslv", "sdiv", "udiv"):
                lines.append(f"  0x{a:06x} SIZEOP {m} {o}")
            elif m in ("ldrb", "ldrh", "ldrsb", "ldrsh", "ldurb", "ldurh"):
                lines.append(f"  0x{a:06x} SIZEOP {m} {o}")
            elif m == "ldr" and (", w1]" in o or ", w2]" in o or ", x1]" in o or ", x2]" in o):
                lines.append(f"  0x{a:06x} SIZEOP {m} {o}")
            elif m == "sub" and o.startswith("sp, sp, x"):
                lines.append(f"  0x{a:06x} SIZEOP-VLA {m} {o}  <-- variable stack alloc, flag")
        if first_strref is not None:
            lines.append(f"  first STRREF at 0x{first_strref:06x}; BL-helper/copy? before it = review for parse-before-verify")
        else:
            lines.append("  no STRREF in func; verify (if any) is in callee, resolve BL VERIFY targets above")
        lines.append("")

    for group, title in ((PIT_FUNCS, "PIT handlers"), (TOKEN_FUNCS, "token handlers")):
        lines.append(f"== {title} ==")
        for f in group:
            lo, hi = func_range(data, layout, f)
            off = rva_to_file(layout, lo)
            if off is None:
                lines.append(f"  func 0x{f:06x}: (unmapped)")
                continue
            code = data[off : off + (hi - lo)]
            n = (hi - lo) // 4
            # first STRREF in handler
            first = None
            for ins in MD.disasm(code, lo):
                if ins.address in by_add:
                    _, r = by_add[ins.address]
                    fo = rva_to_file(layout, r)
                    blob = data[fo : fo + 200] if fo is not None else b""
                    if any(k.encode() in blob for k in KEYWORDS):
                        first = ins.address
                        break
            lines.append(f"  func 0x{f:06x} [{n}w] first STRREF: {f'0x{first:06x}' if first else 'none in func (callee?)'}")
        lines.append("")

    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
