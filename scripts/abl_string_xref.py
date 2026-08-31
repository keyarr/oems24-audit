#!/usr/bin/env python3
"""Read-only AArch64 literal-pool xref helper for ABL PE images.

Finds, for a set of target RVAs (usually string literals), every `adrp xN, #page`
+ `add xN, xN, #lo12` pair in the executable sections that materialises that RVA,
and reports the enclosing function.

Used to turn a string delta between two ABL builds into concrete function
addresses. No state-changing operation is performed.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG

MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

# Mnemonics whose operands[0] is genuinely overwritten. Everything else leaves
# operands[0] intact even when it is listed as a source register.
DESTROYS_REGISTER = frozenset(
    {
        "adr", "adrp", "add", "sub", "mov", "movz", "movk", "movn", "neg",
        "and", "orr", "eor", "bic", "orn", "eon", "ands", "bics",
        "lsl", "lsr", "asr", "ror", "mul", "mneg", "madd", "msub",
        "sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw",
        "sbfx", "ubfx", "sbfiz", "ubfiz", "bfxil", "extr",
        "ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "ldrsh", "ldp",
        "ldur", "ldurb", "ldurh", "ldursw", "ldursb", "ldursh",
        "ldar", "ldarb", "ldarh", "ldxr", "ldaxr", "ldrb", "ldr",
        "csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc",
        "adc", "sbc", "ngc", "mrs", "bl", "blr", "cvt", "fmov", "fadd",
        "ld1", "ldr q", "ldnp", "ldpsw", "rev", "rev16", "rev32", "clz", "rbit",
    }
)


def pe_layout(image: bytes) -> dict:
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    coff = pe_offset + 4
    section_count = struct.unpack_from("<H", image, coff + 2)[0]
    optional_size = struct.unpack_from("<H", image, coff + 16)[0]
    optional = coff + 20
    magic = struct.unpack_from("<H", image, optional)[0]
    entry_rva = struct.unpack_from("<I", image, optional + 16)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", image, optional + 24)[0]
    else:
        image_base = struct.unpack_from("<I", image, optional + 28)[0]
    table = optional + optional_size
    sections = []
    for index in range(section_count):
        pos = table + index * 40
        name = image[pos : pos + 8].rstrip(b"\0").decode("ascii", "replace")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", image, pos + 8)
        flags = struct.unpack_from("<I", image, pos + 36)[0]
        sections.append(
            {
                "name": name,
                "rva": rva,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "file_offset": raw_offset,
                "executable": bool(flags & 0x20000000),
            }
        )
    return {
        "image_base": image_base,
        "entry_rva": entry_rva,
        "magic": magic,
        "sections": sections,
    }


def rva_to_file(layout: dict, rva: int) -> int | None:
    for section in layout["sections"]:
        span = max(section["raw_size"], section["virtual_size"])
        if section["rva"] <= rva < section["rva"] + span:
            return section["file_offset"] + (rva - section["rva"])
    return None


def executable_ranges(layout: dict) -> list[tuple[int, int, int]]:
    """(rva_start, rva_end, file_offset) for each executable section."""
    out = []
    for section in layout["sections"]:
        if not section["executable"] or not section["raw_size"]:
            continue
        out.append(
            (
                section["rva"],
                section["rva"] + section["raw_size"],
                section["file_offset"],
            )
        )
    return out


def function_bounds(image: bytes, layout: dict, rva: int) -> tuple[int, int]:
    """Approximate the enclosing function by scanning for a standard prologue
    backwards and a `ret` forwards. Documented as approximate on purpose."""
    ranges = executable_ranges(layout)
    host = None
    for start, end, file_offset in ranges:
        if start <= rva < end:
            host = (start, end, file_offset)
            break
    if host is None:
        return rva, rva
    start, end, file_offset = host
    lo = start
    hi = min(end, rva + 0x4000)
    # walk back up to 0x2000 bytes looking for a prologue
    scan_lo = max(start, rva - 0x2000)
    insns = []
    for ins in MD.disasm(
        image[file_offset + (scan_lo - start) : file_offset + (hi - start)], scan_lo
    ):
        insns.append(ins)
    prologue = scan_lo
    best = None
    for index, ins in enumerate(insns):
        text = f"{ins.mnemonic} {ins.op_str}"
        if ins.address > rva:
            break
        if (
            (ins.mnemonic == "stp" and "x29" in ins.op_str and "sp" in ins.op_str)
            or (ins.mnemonic == "sub" and ins.op_str.startswith("sp, sp"))
            or (ins.mnemonic == "mov" and ins.op_str == "x29, sp")
            or ins.mnemonic == "pacibsp"
        ):
            best = ins.address
    if best is not None:
        prologue = best
    function_end = hi
    for ins in insns:
        if ins.address < prologue:
            continue
        if ins.mnemonic == "ret":
            function_end = ins.address + 4
            break
    return prologue, function_end


def sweep(image: bytes, layout: dict):
    """Yield instructions across every executable section, resuming after gaps.

    A plain linear sweep silently stops at the first un-decodable word. Real ABL
    images interleave constant pools (SHA tables, GUID tables) with code, so a
    single stop can hide hundreds of kilobytes of instructions. This restarts
    the sweep 4 bytes after each failure instead of giving up.
    """
    for start, end, file_offset in executable_ranges(layout):
        code = image[file_offset : file_offset + (end - start)]
        pos = start
        while pos < end:
            last = pos
            for ins in MD.disasm(code[pos - start :], pos):
                yield ins
                last = ins.address + ins.size
            if last <= pos:
                pos += 4
            else:
                pos = last + 4


def find_adrp_xrefs(image: bytes, layout: dict, targets: dict[int, str]) -> dict[int, list[dict]]:
    """Return {target_rva: [{'adrp_rva','add_rva','reg','function'}]}."""
    results: dict[int, list[dict]] = {key: [] for key in targets}
    pending: dict[int, tuple[int, int]] = {}  # reg -> (adrp_rva, page)
    for ins in sweep(image, layout):
        if ins.mnemonic == "adr" and len(ins.operands) == 2:
            if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_IMM:
                resolved = ins.address + ins.operands[1].imm
                if resolved in targets:
                    lo, hi = function_bounds(image, layout, ins.address)
                    results[resolved].append(
                        {
                            "adrp_rva": ins.address,
                            "add_rva": ins.address,
                            "reg": ins.reg_name(ins.operands[0].reg),
                            "resolved_rva": resolved,
                            "function_start": lo,
                            "function_end": hi,
                        }
                    )
            continue
        if ins.mnemonic == "adrp" and ins.operands and ins.operands[0].type == ARM64_OP_REG:
            reg = ins.reg_name(ins.operands[0].reg)
            imm = ins.operands[1].imm
            pending[reg] = (ins.address, imm & ~0xFFF)
            continue
        if ins.mnemonic == "add" and len(ins.operands) == 3:
            dst = ins.reg_name(ins.operands[0].reg)
            src = ins.reg_name(ins.operands[1].reg)
            if dst == src and dst in pending and ins.operands[2].type == ARM64_OP_IMM:
                adrp_rva, page = pending[dst]
                resolved = page + ins.operands[2].imm
                if resolved in targets:
                    lo, hi = function_bounds(image, layout, adrp_rva)
                    results[resolved].append(
                        {
                            "adrp_rva": adrp_rva,
                            "add_rva": ins.address,
                            "reg": dst,
                            "resolved_rva": resolved,
                            "function_start": lo,
                            "function_end": hi,
                        }
                    )
                pending.pop(dst, None)
                continue
        # Only instructions that actually DESTROY the register may invalidate a
        # pending adrp. `str x0, [x1]`, `cmp x0, x2`, `br x0`, `cbz x0` all list
        # the register as operands[0] but leave it intact, so invalidating on
        # every instruction silently drops real adrp/add pairs.
        if ins.operands and ins.operands[0].type == ARM64_OP_REG:
            base = ins.mnemonic.split(".")[0]
            if base in DESTROYS_REGISTER:
                pending.pop(ins.reg_name(ins.operands[0].reg), None)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("targets", nargs="+", help="RVAs in 0xhex form")
    args = parser.parse_args()
    image = args.image.read_bytes()
    layout = pe_layout(image)
    targets = {}
    for value in args.targets:
        rva = int(value, 16)
        snippet = image[rva_to_file(layout, rva) : rva_to_file(layout, rva) + 48]
        printable = "".join(chr(c) if 32 <= c < 127 else "." for c in snippet)
        targets[rva] = printable
    hits = find_adrp_xrefs(image, layout, targets)
    for rva in sorted(targets):
        print(f"target RVA 0x{rva:06x}  {targets[rva]!r}")
        for item in hits[rva]:
            print(
                f"    adrp 0x{item['adrp_rva']:06x} add 0x{item['add_rva']:06x} "
                f"{item['reg']:<3}  func [0x{item['function_start']:06x}, 0x{item['function_end']:06x})"
            )
        if not hits[rva]:
            print("    (no adrp/add xref found)")


if __name__ == "__main__":
    main()
