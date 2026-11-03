#!/usr/bin/env python3
"""Offline pre-AVB input map for unlock (DZDP LinuxLoader).

Read-only static triage: which disk / varstore / blob inputs the ABL can
consume before avb_slot_verify (0x18f98, called from 0x15990), and whether
any of them can still reach IsUnlocked / SetUnlocked / AVB decision.

Reuses scripts/abl_string_xref.py for adrp/add resolution. No device,
no writes, no new deps.
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PE = ROOT / "decompiled" / "linuxloader-oneui8.pe"
OUT = ROOT / "decompiled" / "abl-preavb-input-map.txt"

sys.path.insert(0, str(ROOT / "scripts"))
from abl_string_xref import find_adrp_xrefs, pe_layout, rva_to_file  # noqa: E402

EXPECTED_SHA = "1e57583c18bd1aaac855becf87cc6286d702e703fd8122bf9c3808f625e6da4a"

# inputs that matter for unlock. label -> (ascii needle, avb coverage, note)
ASCII_INPUTS = [
    ("SAMANDR-BOOT!", "N/A (magic)", "devinfo magic, fixed 0xcd0 read at 0x4260c"),
    ("persistent", "NOT_COVERED", "OneUI7 policy read it, OneUI8 returns 0 at 0xa141c"),
    ("frp", "NOT_COVERED", "raw partition, check callers"),
    ("secdata", "NOT_COVERED", "raw partition, check callers"),
    ("steady", "NOT_COVERED", "raw partition, check callers"),
    ("sec_efs", "NOT_COVERED", "raw partition, check callers"),
    ("devcfg", "NOT_COVERED", "config blob, changed abr->jul"),
    ("RESET_PARAM", "NOT_COVERED", "param partition string in PE"),
    ("misc", "NOT_COVERED", "aboot / recovery msg path"),
    ("boot", "COVERED (vbmeta)", "image under AVB verify"),
    ("init_boot", "COVERED (vbmeta)", "image under AVB verify"),
    ("vendor_boot", "COVERED (vbmeta)", "image under AVB verify"),
    ("dtbo", "COVERED (vbmeta)", "check user_dtbo vs dtbo"),
    ("user_dtbo", "COVERED (vbmeta)", "in 35-literal set"),
    ("vbmeta", "COVERED (self)", "expected absent as CHAR16 gate, ascii logs only"),
    ("super", "COVERED (vbmeta)", "in 35-literal set"),
    ("system", "COVERED (vbmeta)", "in 35-literal set"),
    ("recovery", "COVERED (vbmeta)", "in 35-literal set"),
    ("recoveryfs", "COVERED (vbmeta)", "in 35-literal set"),
    ("modem", "COVERED? (check)", "in 35-literal set, modem verify path"),
    ("abl_x", "NOT_COVERED? (check)", "in 35-literal set, second-stage loader"),
    ("EDL", "N/A (mode)", "cookie / mode switch, not a verify input"),
    ("emac", "UNKNOWN", "in 35-literal set, purpose unclear"),
    ("debug", "UNKNOWN", "in 35-literal set, purpose unclear"),
    ("sysfont2x", "N/A (asset)", "display asset"),
    ("androidboot.other.locked", "N/A (output)", "cmdline built at 0x4d01c, not an input"),
    ("androidboot.em.status", "N/A (output)", "bootconfig output"),
    ("GetEMBit", "N/A (code)", "symbol-ish, bitmap read at 0xadae0"),
    ("BL_EM_CMD_GET_MODES_BIT", "N/A (code)", "EM sync opcode string"),
]

# UEFI vars / quest names (UTF-16 in PE). From consumer map + discriminator.
VAR_NAMES = [
    "QuestFVFlashed", "BootDeviceBaseAddr", "DisplayPanelConfiguration",
    "HwFenceConfiguration", "GpuConfiguration", "ImageFv",
]

# Partition names that live as UTF-16 CHAR16 literals (GetPartitionIndex args).
# ASCII search above catches logs; the real xref uses the UTF-16 address.
PART_UTF16 = [
    "boot", "boot_a", "boot_b", "init_boot", "vendor_boot", "user_dtbo",
    "recovery", "recoveryfs", "super", "system", "modem", "misc", "abl_x",
    "EDL", "emac", "debug", "sysfont2x",
]

UNLOCK_POINTS = {
    0x41ED0: "IsUnlocked (ldrb devinfo+0x0d)",
    0x424CC: "SetUnlocked (strb devinfo+0x0d, single writer)",
    0x425EC: "DeviceInfoInit (fixed 0xcd0 read at 0x4260c)",
    0x18F98: "avb_slot_verify (unconditional call, caller 0x15990)",
    0x51048: "read_is_device_unlocked (AVB callback -> IsUnlocked)",
    0xADAE0: "GetEMBit (EM bitmap, bit 3 = unlock)",
    0xA141C: "current OEM policy (mov w0,wzr, always 0)",
}


def ascii_hits(data: bytes, needle: bytes) -> list[int]:
    out = []
    at = 0
    while True:
        at = data.find(needle, at)
        if at < 0:
            return out
        out.append(at)
        at += 1


def utf16_strings(data: bytes) -> dict[str, int]:
    # same pattern as discriminator: (ascii \0){3,}
    found = {}
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){3,}", data):
        raw = m.group(0)
        try:
            s = raw.decode("utf-16-le")
        except Exception:
            continue
        if s not in found:
            found[s] = m.start()
    return found


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
    u16 = utf16_strings(data)

    lines = []
    lines.append("ABL PRE-AVB INPUT MAP FOR UNLOCK (DZDP LinuxLoader)")
    lines.append(f"input: decompiled/linuxloader-oneui8.pe sha256 {sha}")
    lines.append("method: ascii search + UTF-16 scan + adrp/add xref via")
    lines.append("  scripts/abl_string_xref.py (resilient sweep, approximate function bounds).")
    lines.append("  AVB anchor: bl 0x18f98 called from 0x15990, unconditional.")
    lines.append("  Unlock equation: IsUnlocked(0x41ed0) -> AVB callback 0x51048;")
    lines.append("  single writer SetUnlocked 0x424cc <- GetEMBit(3) 0xadae0.")
    lines.append("scope: offline, read-only. No writes, no reboots.")
    lines.append("")

    lines.append("UNLOCK DECISION POINTS (fixed)")
    for rva in sorted(UNLOCK_POINTS):
        lines.append(f"  0x{rva:06x}  {UNLOCK_POINTS[rva]}")
    lines.append("")

    # resolve ascii needles to targets with at least one xref
    lines.append("1. ASCII INPUTS (partition / blob / cmdline)")
    targets: dict[int, str] = {}
    needle_of: dict[int, str] = {}
    for label, cov, note in ASCII_INPUTS:
        hits = ascii_hits(data, label.encode())
        if not hits:
            lines.append(f"  {label:<28} ABSENT  cov={cov}  // {note}")
            continue
        # keep first few hits as xref targets (cap to avoid noise on 'boot')
        shown = hits[:4]
        lines.append(f"  {label:<28} count={len(hits)} e.g. {', '.join(f'0x{x:06x}' for x in shown)}  cov={cov}  // {note}")
        for h in shown:
            targets[h] = label
            needle_of[h] = label
    lines.append("")
    if targets:
        hits = find_adrp_xrefs(data, layout, targets)
        lines.append("  XREFS (who references each literal):")
        for rva in sorted(hits):
            label = targets[rva]
            items = hits[rva]
            if not items:
                lines.append(f"    0x{rva:06x} {label!r}: (no direct adrp/add xref; maybe via table/unicode)")
                continue
            for it in items[:6]:
                lines.append(
                    f"    0x{rva:06x} {label!r}: adrp 0x{it['adrp_rva']:06x} "
                    f"add 0x{it['add_rva']:06x} func [0x{it['function_start']:06x},0x{it['function_end']:06x})"
                )
    lines.append("")

    lines.append("1b. PARTITION LITERALS UTF-16 (real GetPartitionIndex args)")
    puff: dict[int, str] = {}
    for name in PART_UTF16:
        rva = u16.get(name)
        if rva is None:
            lines.append(f"  {name:<20} ABSENT_UTF16")
            continue
        lines.append(f"  {name:<20} utf16 @ 0x{rva:06x}")
        puff[rva] = name
    if puff:
        phits = find_adrp_xrefs(data, layout, puff)
        for rva in sorted(phits):
            for it in phits[rva][:8]:
                lines.append(
                    f"    0x{rva:06x} {puff[rva]!r}: adrp 0x{it['adrp_rva']:06x} "
                    f"add 0x{it['add_rva']:06x} func [0x{it['function_start']:06x},0x{it['function_end']:06x})"
                )
            if not phits[rva]:
                lines.append(f"    0x{rva:06x} {puff[rva]!r}: (no xref)")
    lines.append("")

    lines.append("2. UEFI VARS / QUEST (UTF-16, same technique as the discriminator)")
    for name in VAR_NAMES:
        rva = u16.get(name)
        if rva is None:
            lines.append(f"  {name:<28} ABSENT_UTF16")
            continue
        lines.append(f"  {name:<28} utf16 @ 0x{rva:06x}")
    # xref only for present ones
    present = {u16[n]: n for n in VAR_NAMES if n in u16}
    if present:
        vhits = find_adrp_xrefs(data, layout, present)
        for rva in sorted(vhits):
            for it in vhits[rva][:6]:
                lines.append(
                    f"    0x{rva:06x} {present[rva]!r}: adrp 0x{it['adrp_rva']:06x} "
                    f"add 0x{it['add_rva']:06x} func [0x{it['function_start']:06x},0x{it['function_end']:06x})"
                )
    lines.append("  baseline (consumer map 05/09): QuestFVFlashed log-only;")
    lines.append("  BootDeviceBaseAddr hw base; Display*/HwFence/Gpu display init;")
    lines.append("  ImageFv quest-protocol, far from the AVB gate. None reaches")
    lines.append("  IsUnlocked/SetUnlocked/DeviceInfoInit/0x18f98.")
    lines.append("")

    lines.append("3. TRIAGE FOR UNLOCK (see preavb-leads-and-odin-exceptions.txt")
    lines.append("   for the per-lead function-level verdicts; all 5 closed)")
    lines.append("  DEAD (do not touch): devinfo parser (fixed 0xcd0 read, no")
    lines.append("  content-driven length field); persistent policy (0xa141c")
    lines.append("  returns 0); GPT gate (no Is_VERIFIED_BOOT_2, 0x18f98")
    lines.append("  unconditional); UEFI vars above; vbmeta CHAR16 absent")
    lines.append("  (35 literals, no vbmeta).")
    lines.append("  LOG-ONLY (string exists, no lookup): frp (3x ascii, logs only")
    lines.append("  frp_state/FRPLOCK, no UTF-16, no xref); persistent ascii = AVB")
    lines.append("  persistent digest (avb_sha256, ops->read/write_persistent_value),")
    lines.append("  not the OneUI7 OEM partition. Not unlock inputs.")
    lines.append("  AVB-COVERED (no pre-AVB gain): boot/init_boot/vendor_boot/")
    lines.append("  dtbo/super/system/recovery. Corrupting these fails verify,")
    lines.append("  does not skip it.")
    lines.append("  FORMER LEADS, NOW CLOSED (were NOT_COVERED with xref):")
    lines.append("  - misc utf16 0x0d44b4 <- 0x010078/0x01009c func 0x010004, read")
    lines.append("    in the SetUnlock path at 0x42234 when mode == 2; fixed")
    lines.append("    0x400/0x440 buffers, validated dispatch. Closed.")
    lines.append("  - abl_x utf16 0x0d43da <- 0x00e6b0: loaded from INSIDE")
    lines.append("    avb_slot_verify (caller 0x14284). Covered by definition.")
    lines.append("  - secdata 0x0cf402 <- 0x0a9238/0x0a939c, devcfg 0x0b388c <-")
    lines.append("    0x0a90d0, func 0x0a8ff0 = SW REV anti-rollback gate")
    lines.append("    (default-deny). An obstacle, not a primitive.")
    lines.append("  - steady 0x0c2514 (6 xrefs), sec_efs 0x0d1534 (func 0x099020):")
    lines.append("    fixed/clamped sizes, tag checks, validated dispatch. Closed.")
    lines.append("  - modem/emac/recoveryfs/EDL: real lookups but covered or mode;")
    lines.append("    back only if everything above reopens.")
    lines.append("  Rule: no cmp on untrusted input = close and move on.")
    lines.append("")

    lines.append("4. STOP CONDITIONS")
    lines.append("  - If all xrefs of frp/secdata/steady/sec_efs/devcfg/misc are")
    lines.append("    fixed-size reads with no branch on content fields: close F-3.")
    lines.append("    (MET 2026-09-07, see evidence file above.)")
    lines.append("  - If Odin handlers validate signature/PIT/token/KG/AR before")
    lines.append("    any USB packet parse: freeze F-4 until a new BL drops.")
    lines.append("  - Any pre-AVB write primitive reaching devinfo+0x0d or the")
    lines.append("    [x19+0x438] flag before 0x18f98 = escalate to an offline")
    lines.append("    Unicorn harness of LinuxLoader (never on device).")
    lines.append("")
    lines.append("REPRO: python3 scripts/abl_preavb_input_map.py")
    lines.append("OUT: decompiled/abl-preavb-input-map.txt")

    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
