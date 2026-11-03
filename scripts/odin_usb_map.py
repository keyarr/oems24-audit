#!/usr/bin/env python3
"""Odin USB parse-before-verify map (DZDP odin app).

Read-only static triage: enumerate command dispatchers and enforcement
sites in decompiled/odin-oneui8.pe, so a human can check per command
whether a USB packet length reaches a copy before PIT/token/KG/AR/
signature verification.

Clone of scripts/abl_preavb_input_map.py logic, retargeted. No device,
no writes, no new deps.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PE = ROOT / "decompiled" / "odin-oneui8.pe"
OUT = ROOT / "decompiled" / "odin-usb-parse-before-verify-map.txt"

sys.path.insert(0, str(ROOT / "scripts"))
from abl_string_xref import DESTROYS_REGISTER, function_bounds, pe_layout, rva_to_file, sweep  # noqa: E402
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG  # noqa: E402

EXPECTED_SHA = "c05b772ce3715b0df0ae7cc876c0825d366c3506b660389e2dc44d8725abf135"

# label -> (note). count and xrefs are computed.
ASCII_INPUTS = [
    ("Not defined cmdid", "dispatcher default-deny, one func per site"),
    ("Only official released binaries are allowed to be flashed", "enforcement: official check"),
    ("All binaries are not allowed to be flashed due to KG locked", "enforcement: KG lock"),
    ("Failed to verify token", "enforcement: token auth"),
    ("ODIN: USED token", "enforcement: token reuse"),
    ("Remaining token use count is zero", "enforcement: token count"),
    ("SW REV CHECK FAIL", "enforcement: anti-rollback"),
    ("Mismatched image Header version", "enforcement: header AR"),
    ("SECURE CHECK FAIL : PIT", "enforcement: PIT signature"),
    ("SECURE CHECK FAIL", "enforcement: generic secure check"),
    ("This image doesn't check a signing..", "exception path, fail-closed per audit"),
    ("This image doesn't check for arp case..", "exception path, fail-closed per audit"),
    ("BLInitToken", "token entry, compare order vs parse"),
    ("BLReadToken", "token entry, compare order vs parse"),
    ("BLWriteToken", "token entry, compare order vs parse"),
]

# log sites from prior string-level audit, to confirm they still exist
KNOWN_SITES = [0x5A118, 0x5B770, 0x5B9E8, 0x5C87C, 0x5C994, 0x5C9C8, 0x5DBF0]


def ascii_hits(data: bytes, needle: bytes) -> list[int]:
    out = []
    at = 0
    while True:
        at = data.find(needle, at)
        if at < 0:
            return out
        out.append(at)
        at += 1


def all_adrp_pairs(image: bytes, layout: dict) -> list[dict]:
    # Odin rodata packs strings: code refs blob base, needle sits inside.
    # Exact-target match misses, so enumerate every pair and match by blob.
    # No function_bounds here, too slow. Resolve bounds only for matches.
    out = []
    pending: dict[str, tuple[int, int]] = {}
    for ins in sweep(image, layout):
        if ins.mnemonic == "adrp" and ins.operands and ins.operands[0].type == ARM64_OP_REG:
            reg = ins.reg_name(ins.operands[0].reg)
            pending[reg] = (ins.address, ins.operands[1].imm & ~0xFFF)
            continue
        if ins.mnemonic == "add" and len(ins.operands) == 3:
            dst = ins.reg_name(ins.operands[0].reg)
            src = ins.reg_name(ins.operands[1].reg)
            if dst == src and dst in pending and ins.operands[2].type == ARM64_OP_IMM:
                adrp_rva, page = pending[dst]
                resolved = page + ins.operands[2].imm
                out.append(
                    {
                        "resolved": resolved,
                        "adrp_rva": adrp_rva,
                        "add_rva": ins.address,
                    }
                )
                pending.pop(dst, None)
                continue
        if ins.operands and ins.operands[0].type == ARM64_OP_REG:
            # same rule as abl_string_xref: only real dest writes kill pending
            if ins.mnemonic.split(".")[0] in DESTROYS_REGISTER:
                pending.pop(ins.reg_name(ins.operands[0].reg), None)
    return out


def blob_contains(image: bytes, layout: dict, rva: int, needle: bytes) -> bool:
    # read 256B at rva, needle can sit past the first null (packed blob)
    off = rva_to_file(layout, rva)
    if off is None:
        return False
    return needle in image[off : off + 256]


def main() -> int:
    if not PE.exists():
        print(f"missing {PE}", file=sys.stderr)
        return 1
    data = PE.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        print(f"sha mismatch: {sha} != {EXPECTED_SHA}", file=sys.stderr)
        return 1
    layout = pe_layout(data)

    lines = []
    lines.append("ODIN USB PARSE-BEFORE-VERIFY MAP (DZDP odin app)")
    lines.append(f"input: decompiled/odin-oneui8.pe sha256 {sha}")
    lines.append("method: ascii search + adrp/add xref via")
    lines.append("  scripts/abl_string_xref.py (same sweep as abl_preavb_input_map.py).")
    lines.append("  Question per command: does USB packet length reach a copy")
    lines.append("  before PIT/token/KG/AR/signature checks? If yes, flag it.")
    lines.append("scope: offline, read-only. No writes, no reboots.")
    lines.append("")

    lines.append("1. DISPATCHERS AND ENFORCEMENT SITES")
    pairs = all_adrp_pairs(data, layout)
    funcs_of_interest: set[int] = set()
    for label, note in ASCII_INPUTS:
        needle = label.encode()
        hits = ascii_hits(data, needle)
        if not hits:
            lines.append(f"  {label:<60} ABSENT  // {note}")
            continue
        shown = hits[:4]
        lines.append(f"  {label:<60} count={len(hits)} e.g. {', '.join(f'0x{x:06x}' for x in shown)}  // {note}")
        matched = [p for p in pairs if blob_contains(data, layout, p["resolved"], needle)]
        if not matched:
            lines.append(f"    (no blob xref found; likely table-driven)")
            continue
        for p in matched[:6]:
            lo, hi = function_bounds(data, layout, p["adrp_rva"])
            p["function_start"] = lo
            p["function_end"] = hi
            lines.append(
                f"    blob 0x{p['resolved']:06x} {label!r}: adrp 0x{p['adrp_rva']:06x} "
                f"add 0x{p['add_rva']:06x} func [0x{lo:06x},0x{hi:06x})"
            )
        if label == "Not defined cmdid":
            for p in matched:
                if "function_start" not in p:
                    lo, hi = function_bounds(data, layout, p["adrp_rva"])
                    p["function_start"] = lo
                    p["function_end"] = hi
                funcs_of_interest.add(p["function_start"])
    lines.append("")

    lines.append("2. DISPATCHER FUNCS TO AUDIT (parse-before-verify per command)")
    if funcs_of_interest:
        for f in sorted(funcs_of_interest):
            lines.append(f"  func 0x{f:06x}: disassemble, list recv->length->copy vs verify order")
    else:
        lines.append("  (none resolved, check xref method before manual work)")
    lines.append("  known log sites to confirm: " + ", ".join(f"0x{x:06x}" for x in KNOWN_SITES))
    lines.append("  exception func 0x058350, caller 0x00aa28: already fail-closed (w0=0=deny).")
    lines.append("")

    lines.append("3. STOP CONDITIONS")
    lines.append("  - If every dispatcher validates PIT/token/KG/AR/signature before")
    lines.append("    any USB length is used for copy/alloc: freeze F-4 until new BL.")
    lines.append("  - Any length from packet reaching copy/alloc first = escalate to")
    lines.append("    offline Unicorn harness of that handler (never on device).")
    lines.append("")
    lines.append("REPRO: python3 scripts/odin_usb_map.py")
    lines.append("OUT: decompiled/odin-usb-parse-before-verify-map.txt")

    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
