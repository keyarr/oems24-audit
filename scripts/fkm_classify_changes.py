#!/usr/bin/env python3
"""Separate real code changes from pure address-shift noise in a TA patch-diff.

For each function whose bytes differ between before/after, disassemble both
versions and compare the *mnemonic sequence* (opcode names only, operands
stripped). A pure offset/target shift (e.g. a string-table `add` immediate
moving because something earlier in rodata grew) changes the operand but not
the instruction sequence; an actual logic change changes which instructions
appear at all.

Caveat, stated plainly: this is an opcode-sequence heuristic, not a
semantic-equivalence check. A compiler swapping one instruction for an
equivalent one between builds registers as a false "real change". Take the
output as "candidates for real change", not a proven count. Implausible
before/after instruction-count deltas in the tail of the binary mean the
function-boundary detector broke down there, not a real giant change; don't
trust those entries without re-deriving boundaries by hand.
Known failure mode (seen on fabrickeymaster SPU): when an early insertion
shifts all downstream VAs, VA-aligned pairing compares DIFFERENT functions
and both this script and ta_patchdiff.py report noise as change (there: 2582
added/removed, 56 "real" here, vs 2688/2691 exact mnemonic matches by content
matching). Pair by content before trusting counts.

Read-only, static only. No device access; nothing is mutated.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ta_audit_generic",
                                              ROOT / "scripts" / "ta_audit_generic.py")
TAG = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TAG)

spec2 = importlib.util.spec_from_file_location("ta_patchdiff",
                                               ROOT / "scripts" / "ta_patchdiff.py")
TPD = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(TPD)

MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--before", type=Path, required=True)
    ap.add_argument("--after", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=None,
                    help="write report to this file (default: stdout)")
    args = ap.parse_args()

    before = TAG.Trustlet(args.before.resolve())
    after = TAG.Trustlet(args.after.resolve())

    bf = TPD.detect_functions(before)
    af = TPD.detect_functions(after)
    bset, aset = set(bf), set(af)
    common = sorted(bset & aset)

    bcode_end = int(before.loads[0]["p_vaddr"]) + int(before.loads[0]["p_filesz"])
    acode_end = int(after.loads[0]["p_vaddr"]) + int(after.loads[0]["p_filesz"])

    real_changes = []
    noise = []

    for va in common:
        bn = sorted(x for x in bf if x > va)
        an = sorted(x for x in af if x > va)
        bend = min(bn[0] if bn else bcode_end, bcode_end)
        aend = min(an[0] if an else acode_end, acode_end)
        bfile0 = before.va_to_file(va)
        afile0 = after.va_to_file(va)
        braw = before.data[bfile0: bfile0 + (bend - va)]
        araw = after.data[afile0: afile0 + (aend - va)]
        if braw == araw:
            continue

        bmn = [i.mnemonic for i in MD.disasm(braw, va)]
        amn = [i.mnemonic for i in MD.disasm(araw, va)]

        if bmn == amn:
            noise.append(va)
        else:
            real_changes.append((va, bmn, amn))

    lines = [
        f"BEFORE {args.before}  AFTER {args.after}",
        f"Common functions: {len(common)}",
        f"Byte-changed: {len(noise) + len(real_changes)}",
        f"  -> pure operand/offset noise (same mnemonic sequence): {len(noise)}",
        f"  -> REAL mnemonic-sequence changes: {len(real_changes)}",
        "",
    ]
    for va, bmn, amn in real_changes:
        lines.append(f"=== REAL CHANGE @0x{va:06x} ===")
        lines.append(f"  BEFORE: {bmn}")
        lines.append(f"  AFTER : {amn}")
        lines.append("")

    report = "\n".join(lines)
    if args.out:
        out = args.out if args.out.is_absolute() else ROOT / args.out
        out.write_text(report, encoding="utf-8")
        print(f"wrote {out.relative_to(ROOT)}")
    else:
        print(report)


if __name__ == "__main__":
    main()
