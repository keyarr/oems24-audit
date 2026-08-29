#!/usr/bin/env python3
"""Function-level patch-diff for two sectionless QSEE TAs (read-only).

Diffs a "before" TA (e.g. DZDP keymaster.img) against an "after" TA
(e.g. SMR Jul-2026 keymaster.img) by aligning on virtual address and
comparing each recovered function body.  The VA layout of a given TA is
stable across Samsung monthly builds, so unchanged functions keep the same
VA and only the patched ones differ.

The "after" binary is NOT in the audit repo (it is an external SMR build);
this script is the harness that produces the real diff the moment the
patched image is dropped in.  A self-test (before == after) prints no
changes, proving the tool is wired correctly.

No device access; nothing is mutated.
"""

from __future__ import annotations

import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

import importlib.util
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ta_audit_generic",
                                             ROOT / "scripts" / "ta_audit_generic.py")
TAG = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TAG)

OUT = ROOT / "decompiled"


def detect_functions(ta) -> list[int]:
    """Recover function starts (prologue stp-to-sp / stp x29,x30 / bti / pac)."""
    code = ta.loads[0]
    cstart = int(code["p_vaddr"]); csize = int(code["p_filesz"])

    def word_at(foff): return struct.unpack_from("<I", ta.data, foff)[0]
    def is_stp_sp(w):
        if (w & 0xFF000000) != 0xA9000000:
            return False
        if ((w >> 22) & 1) != 0:
            return False
        return ((w >> 5) & 0x1F) == 0x1F
    def is_stp_fp(w):
        return ta.data[foff_ + 1] == 0x7B and ta.data[foff_ + 2] == 0xBF and ta.data[foff_ + 3] == 0xA9 \
            and (w & 0xFF000000) == 0xA9000000
    def is_bti_c(w): return w == 0xD503241F
    def is_pac(w): return (w & 0xFFFFFF00) == 0xD5032200 and ((w & 0xFF) in (0x1F, 0x3F, 0x5F, 0x7F, 0x9F, 0xBF, 0xDF, 0xFF))

    funcs = [0]
    foff = ta.va_to_file(cstart); end = foff + csize - 4
    prev_stp = False
    while foff <= end:
        global foff_
        foff_ = foff
        w = word_at(foff)
        this_stp = is_stp_sp(w) or is_stp_fp(w)
        is_start = (is_bti_c(w) or is_pac(w) or this_stp) and not prev_stp
        if is_start:
            funcs.append(cstart + (foff - ta.va_to_file(cstart)))
        prev_stp = this_stp
        foff += 4
    return sorted(set(funcs))


def func_regions(funcs: list[int], code_end: int) -> list[tuple[int, int]]:
    out = []
    for i, f in enumerate(funcs):
        nxt = funcs[i + 1] if i + 1 < len(funcs) else code_end
        out.append((f, nxt))
    return out


def first_diff(before: bytes, after: bytes) -> int:
    n = min(len(before), len(after))
    for i in range(n):
        if before[i] != after[i]:
            return i
    if len(before) != len(after):
        return n
    return -1


def main() -> None:
    import argparse, hashlib
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--before", type=Path, required=True)
    ap.add_argument("--after", type=Path, required=True)
    ap.add_argument("--label", type=str, default=None)
    ap.add_argument("--focus", type=str, default="",
                    help="comma-separated VAs to prioritise (e.g. 0x18e90,0x1d31c)")
    ap.add_argument("--out", type=Path, default=None)
    args, _ = ap.parse_known_args()

    before = TAG.Trustlet(args.before.resolve())
    after = TAG.Trustlet(args.after.resolve())
    label = args.label or f"{args.before.stem}-vs-{args.after.stem}"
    out_path = args.out or (OUT / f"{label}-patchdiff.txt")

    bf = detect_functions(before)
    af = detect_functions(after)
    bset, aset = set(bf), set(af)
    added = sorted(aset - bset)
    removed = sorted(bset - aset)
    common = sorted(bset & aset)

    focus = [int(x, 0) for x in args.focus.split(",") if x.strip()]

    MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    bcode_end = int(before.loads[0]["p_vaddr"]) + int(before.loads[0]["p_filesz"])
    acode_end = int(after.loads[0]["p_vaddr"]) + int(after.loads[0]["p_filesz"])

    lines = [
        "QSEE TA PATCH-DIFF (function-level, VA-aligned, static)",
        "",
        f"BEFORE {before.path.relative_to(ROOT)}  sha256 {hashlib.sha256(before.path.read_bytes()).hexdigest()}",
        f"AFTER  {after.path.relative_to(ROOT)}  sha256 {hashlib.sha256(after.path.read_bytes()).hexdigest()}",
        f"  before functions={len(bf)}  after functions={len(af)}",
        f"  ADDED={len(added)} REMOVED={len(removed)} COMMON={len(common)}",
        "",
    ]

    changed = []
    for va in common:
        # region = [va, next common func in THAT image)
        bn = sorted(x for x in bf if x > va)
        an = sorted(x for x in af if x > va)
        bend = min(bn[0] if bn else bcode_end, bcode_end)
        aend = min(an[0] if an else acode_end, acode_end)
        bfile0 = before.va_to_file(va)
        afile0 = after.va_to_file(va)
        braw = before.data[bfile0: bfile0 + (bend - va)]
        araw = after.data[afile0: afile0 + (aend - va)]
        d = first_diff(braw, araw)
        if d >= 0:
            changed.append((va, d, braw, araw))

    lines.append(f"CHANGED functions (common VA, byte differs): {len(changed)}")
    if not changed and not added and not removed:
        lines.append("  (no differences -- self-test with before==after, or builds are identical)")

    # prioritise focus VAs
    def prio(va):
        return 0 if va in focus else 1

    for va, doff, braw, araw in sorted(changed, key=lambda r: (prio(r[0]), r[0])):
        lines.append("")
        lines.append(f"CHANGED @0x{va:06x}  first differing byte at +0x{doff:x}")
        # disasm window around the change in both images
        win_lo = max(va, va + doff - 0x40)
        win_hi = va + doff + 0x80
        try:
            bdis = MD.disasm(before.data[before.va_to_file(win_lo): before.va_to_file(win_lo) + (win_hi - win_lo)], win_lo)
            adis = MD.disasm(after.data[after.va_to_file(win_lo): after.va_to_file(win_lo) + (win_hi - win_lo)], win_lo)
            lines.append("  -- BEFORE --")
            for i in bdis:
                mark = " <== diff" if before.va_to_file(i.address) - before.va_to_file(va) >= doff else ""
                lines.append(f"    VA 0x{i.address:06x}  {i.mnemonic:<8} {i.op_str}{mark}")
            lines.append("  -- AFTER --")
            for i in adis:
                mark = " <== diff" if after.va_to_file(i.address) - after.va_to_file(va) >= doff else ""
                lines.append(f"    VA 0x{i.address:06x}  {i.mnemonic:<8} {i.op_str}{mark}")
        except ValueError:
            lines.append("    (window not file-backed; raw bytes differ)")

    if added:
        lines += ["", "ADDED functions (only in AFTER):",
                  "  " + ", ".join(f"0x{v:06x}" for v in added)]
    if removed:
        lines += ["", "REMOVED functions (only in BEFORE):",
                  "  " + ", ".join(f"0x{v:06x}" for v in removed)]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out_path.relative_to(ROOT)} ({len(chr(10).join(lines).encode())} bytes)")
    print(f"  common={len(common)} changed={len(changed)} added={len(added)} removed={len(removed)}")


if __name__ == "__main__":
    main()
