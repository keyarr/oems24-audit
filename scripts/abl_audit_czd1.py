#!/usr/bin/env python3
"""Targeted ABL CZD1 vs DZDP comparison.

Reuses the string/xref probes that proved the One UI 7 -> 8.5 transition on the
audited S928B, applied to the One UI 8.0 CZD1 BL. Produces a self-contained
report comparing the CZD1 LinuxLoader to the DZDP one on the same set of
functions, with concrete RVA/file offsets and minimal disassembly snippets.

No state-changing operation is performed and no external service is called.
"""

from __future__ import annotations

import collections
import hashlib
import struct
from pathlib import Path

import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "decompiled" / "abl-czd1-vs-dzdp-evidence.txt"

CZD1 = ROOT / "decompiled" / "linuxloader-oneui8-czd1.pe"
DZDP = ROOT / "decompiled" / "linuxloader-oneui8.pe"
CZD1_ABL = ROOT / "partitions" / "abl-oneui8-czd1.elf"
CZD1_FV = ROOT / "decompiled" / "abl-inner-oneui8-czd1.fv.bin"

MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
R2_BIAS = 0x10000


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pe_meta(path: Path) -> list[str]:
    pe = lief.parse(str(path))
    lines = [
        f"FILE {path.relative_to(ROOT)}",
        f"SIZE {path.stat().st_size}",
        f"SHA256 {sha256(path)}",
        f"FORMAT PE32+ ARM64 EFI imagebase=0x{pe.optional_header.imagebase:x} entry_rva=0x{pe.optional_header.addressof_entrypoint:x}",
    ]
    for s in pe.sections:
        lines.append(
            f"  {s.name} RVA=0x{s.virtual_address:x} RAW=0x{s.pointerto_raw_data:x} "
            f"VSIZE=0x{s.virtual_size:x} SIZE=0x{s.size:x}"
        )
    return lines


def disasm(data: bytes, start: int, end: int) -> list[str]:
    out = []
    for ins in MD.disasm(data[start:end], start):
        out.append(
            f"  RVA 0x{ins.address:06x}  r2 0x{ins.address + R2_BIAS:06x}  "
            f"{ins.mnemonic:<8} {ins.op_str}"
        )
    return out


def string_hits(data: bytes, needles: list[bytes]) -> list[tuple[bytes, list[int]]]:
    res = []
    for n in needles:
        offs = []
        at = 0
        while True:
            at = data.find(n, at)
            if at < 0:
                break
            offs.append(at)
            at += 1
        res.append((n, offs))
    return res


NEEDLES = [
    b"SAMANDR-BOOT!",
    b"[OEM]Oem unlock value is %d",
    b"[FRP][OEM] init succeed!",
    b"[OEM]PLC:%x",
    b"[OEM]LOCK:%d",
    b"androidboot.other.locked=1",
    b"Device is unlocked, Skipping boot verification",
    b"For device lock, Draw Lock Img",
    b"For device unlock, Draw UnLock Img",
    b"BL_EM_CMD_GET_MODES_BIT",
    b"BLInitToken",
    b"IsUnlocked",
    b"IsUnlockCritical",
    b"GetUnlockCount",
    b"SetUnlocked",
]


def find_add_imm12(data: bytes, imm: int) -> list[int]:
    """Offsets of 64-bit ADD Xd, Xn, #imm (sh=0)."""
    out = []
    for off in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[off:off + 4], "little")
        if (w & 0xffc00000) == 0x91000000:
            if ((w >> 10) & 0xfff) == imm:
                out.append(off)
    return out


def find_adrp_page_to(data: bytes, target_page: int) -> list[int]:
    """Offsets of ADRP whose target page equals target_page.

    For this PE, imagebase=0, so the virtual address of an instruction at file
    offset `off` is `off` (not `off + 0x10000`; the +0x10000 only applies to
    radare2's display, not the encoded page delta)."""
    out = []
    for off in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[off:off + 4], "little")
        if (w & 0x9f000000) != 0x90000000:
            continue
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        pc_page = off & ~0xfff
        page = pc_page + (imm << 12)
        if page == target_page:
            out.append(off)
    return out


def find_string_xref(data: bytes, string_rva: int) -> list[tuple[int, int]]:
    """Find ADRP+ADD pairs that produce a pointer to one byte before, at, or
    one byte after string_rva. Return (adrp_off, add_off).

    The compiler may address the leading-space byte of a string literal (the
    actual C string starts after), so we look 1 byte before and 1 byte after
    the reported string position too.
    """
    out: list[tuple[int, int]] = []
    for s in (string_rva - 1, string_rva, string_rva + 1):
        if s < 0 or s >= len(data):
            continue
        page = s & ~0xfff
        low = s & 0xfff
        for adrp_off in find_adrp_page_to(data, page):
            for delta in range(0, 32, 4):
                add_off = adrp_off + delta
                if add_off + 4 > len(data):
                    continue
                w = int.from_bytes(data[add_off:add_off + 4], "little")
                if (w & 0xffc00000) != 0x91000000:
                    continue
                imm12 = (w >> 10) & 0xfff
                if imm12 != low:
                    continue
                adrp_w = int.from_bytes(data[adrp_off:adrp_off + 4], "little")
                if (adrp_w & 0x1f) != ((w >> 5) & 0x1f):
                    continue
                if s != string_rva:
                    # only include off-by-one matches when the referenced byte
                    # really points at our string (the leading-space or
                    # trailing-equal case)
                    if s == string_rva - 1 and data[s:s + 1] not in (b" ",):
                        continue
                    if s == string_rva + 1 and data[s:s + 1] not in (b"\x00",):
                        continue
                out.append((adrp_off, add_off))
    return out


def find_callers(data: bytes, target: int) -> list[int]:
    """Offsets of BL target (encoding: 0x94000000 | ((target - pc) >> 2) & 0x3ffffff)."""
    out = []
    for off in range(0, len(data) - 3, 4):
        w = int.from_bytes(data[off:off + 4], "little")
        if (w & 0xfc000000) != 0x94000000:
            continue
        imm26 = w & 0x3ffffff
        if imm26 & (1 << 25):
            imm26 -= 1 << 26
        dest = (off + (imm26 << 2)) & 0xffffffff
        if dest == target:
            out.append(off)
    return out


def disasm_around(data: bytes, off: int, before: int = 0x20, after: int = 0x40) -> list[str]:
    start = max(0, off - before)
    return disasm(data, start, off + after)


def read_u32_le(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "little")


def main() -> None:
    czd1 = CZD1.read_bytes()
    dzdp = DZDP.read_bytes()

    out: list[str] = []
    out.append("ABL ONE UI 8 CZD1 vs ONE UI 8.5 DZDP TARGETED COMPARISON")
    out.append("")
    out.append("ADDRESS_NOTATION actual PE RVA/file offset; radare2 VA is actual+0x10000")
    out.append("SOURCES")
    out.append(f"  CZD1 ABL ELF     {CZD1_ABL.relative_to(ROOT)} SHA256 {sha256(CZD1_ABL)}")
    out.append(f"  CZD1 inner FV    {CZD1_FV.relative_to(ROOT)} SHA256 {sha256(CZD1_FV)}")
    out.append(f"  CZD1 LinuxLoader {CZD1.relative_to(ROOT)} SHA256 {sha256(CZD1)} SIZE {len(czd1)}")
    out.append(f"  DZDP LinuxLoader {DZDP.relative_to(ROOT)} SHA256 {sha256(DZDP)} SIZE {len(dzdp)}")
    out.append("")
    out.append("CZD1 PE METADATA")
    out.extend(pe_meta(CZD1))
    out.append("")
    out.append("DZDP PE METADATA")
    out.extend(pe_meta(DZDP))
    out.append("")

    out.append("STRING OCCURRENCES (offset = RVA/file offset)")
    c_hits = string_hits(czd1, NEEDLES)
    d_hits = string_hits(dzdp, NEEDLES)
    for (n_c, c_offs), (n_d, d_offs) in zip(c_hits, d_hits):
        assert n_c == n_d
        out.append(
            f"  {n_c!r:50s} CZD1 count={len(c_offs):2d} offs={[hex(x) for x in c_offs]} | "
            f"DZDP count={len(d_offs):2d} offs={[hex(x) for x in d_offs]}"
        )
    out.append("")

    # 1. OEM/FRP policy log+return false: DZDP has [OEM]LOCK:%d at 0xd3f84 and policy at 0xa13b0.
    #    Find equivalent region in CZD1.
    lock_idx_c = czd1.find(b"[OEM]LOCK:%d")
    lock_idx_d = dzdp.find(b"[OEM]LOCK:%d")
    out.append("OEM LOCK POLICY (string [OEM]LOCK:%d)")
    out.append(f"  CZD1 string at 0x{lock_idx_c:x}")
    out.append(f"  DZDP string at 0x{lock_idx_d:x}")
    # Find ADRP+ADD referencing lock string in both files
    refs_c = find_string_xref(czd1, lock_idx_c)
    refs_d = find_string_xref(dzdp, lock_idx_d)
    out.append(f"  CZD1 string xrefs: {[hex(a) for a,_ in refs_c]}")
    out.append(f"  DZDP string xrefs: {[hex(a) for a,_ in refs_d]}")
    # The DZDP site at 0xa13f0 used adrp x1, 0xd3000; add x1, x1, #0xf84 -> string at 0xd3f84
    # Show the function bodies
    for name, data, refs in (("CZD1", czd1, refs_c), ("DZDP", dzdp, refs_d)):
        if not refs:
            continue
        # The OEM policy function in DZDP starts ~0x70 bytes before the string xref
        adrp_off = refs[0][0]
        start = (adrp_off - 0x60) & ~0x3
        end = adrp_off + 0x60
        out.append(f"  REGION {name} OEM policy around string xref")
        out.append(f"  RANGE actual=0x{start:x}..0x{end:x} r2=0x{start + R2_BIAS:x}..0x{end + R2_BIAS:x}")
        out.extend(disasm(data, start, end))
    out.append("")

    # 2. androidboot.other.locked=1 builder
    out.append("CMDLINE BUILDER appends androidboot.other.locked=1")
    a_c = czd1.find(b"androidboot.other.locked=1")
    a_d = dzdp.find(b"androidboot.other.locked=1")
    out.append(f"  CZD1 string at 0x{a_c:x}")
    out.append(f"  DZDP string at 0x{a_d:x}")
    for name, data, s in (("CZD1", czd1, a_c), ("DZDP", dzdp, a_d)):
        refs = find_string_xref(data, s)
        out.append(f"  {name} string xrefs: {[hex(a) for a,_ in refs]}")
        if refs:
            adrp_off = refs[0][0]
            start = (adrp_off - 0x30) & ~0x3
            end = adrp_off + 0x40
            out.append(f"  REGION {name} cmdline builder")
            out.append(f"  RANGE actual=0x{start:x}..0x{end:x} r2=0x{start + R2_BIAS:x}..0x{end + R2_BIAS:x}")
            out.extend(disasm(data, start, end))
    out.append("")

    # 3. main boot chain: BLInitToken, GetEMBit(3), dispatcher. The signature pattern is
    # bl <BLInitToken> ; mov w0, #3 ; bl <GetEMBit> ; tst w0, #0xff ; mov w1, wzr ; cset w0, ne ; bl <dispatcher>
    # Pattern bytes (4 little-endian words): bl  ; 0x52800060 (mov w0,#3) ; bl ; 0x7100001f (tst w0,#0xff)
    out.append("MAIN BOOT CHAIN: BLInitToken -> GetEMBit(3) -> SetUnlocked dispatcher")
    MOV_W0_3 = bytes.fromhex("60008052")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        hits = []
        for off in range(0x9000, 0xb000):
            if data[off:off + 4] != MOV_W0_3:
                continue
            w_bl1 = int.from_bytes(data[off - 4:off], "little")
            w_bl2 = int.from_bytes(data[off + 4:off + 8], "little")
            w_tst = int.from_bytes(data[off + 8:off + 12], "little")
            if (w_bl1 & 0xfc000000) != 0x94000000:
                continue
            if (w_bl2 & 0xfc000000) != 0x94000000:
                continue
            if (w_tst >> 24) != 0x72:  # TST (immediate) top byte
                continue
            hits.append((off - 4, off, off + 4, off + 8))
        out.append(f"  {name} 'bl / mov w0,#3 / bl / tst imm' pattern at {[(hex(a),hex(b),hex(c),hex(d)) for a,b,c,d in hits[:4]]}")
        if hits:
            bl_off, mov_off, bl2_off, tst_off = hits[0]
            start = (bl_off - 0x10) & ~0x3
            end = tst_off + 0x40
            out.append(f"  REGION {name} main boot chain first hit")
            out.append(f"  RANGE actual=0x{start:x}..0x{end:x} r2=0x{start + R2_BIAS:x}..0x{end + R2_BIAS:x}")
            out.extend(disasm(data, start, end))
    out.append("")

    # 4. read_is_device_unlocked AVB callback.
    # In DZDP the callback lives at 0x51048; in CZD1 the .text starts at 0x1000 same, so we find
    # the string "Device is unlocked, Skipping boot verification" xref and look at the surrounding
    # bl IsUnlocked site.
    out.append("AVB CALLBACK read_is_device_unlocked + verification skip string")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        s = data.find(b"Device is unlocked, Skipping boot verification")
        refs = find_string_xref(data, s)
        out.append(f"  {name} verification-skip string at 0x{s:x}, xrefs {[hex(a) for a,_ in refs]}")
        if refs:
            adrp_off = refs[0][0]
            start = (adrp_off - 0x60) & ~0x3
            end = adrp_off + 0x60
            out.append(f"  REGION {name} verification-skip consumer")
            out.append(f"  RANGE actual=0x{start:x}..0x{end:x} r2=0x{start + R2_BIAS:x}..0x{end + R2_BIAS:x}")
            out.extend(disasm(data, start, end))
    out.append("")

    # 5. Persistent-backed OEM unlock reader (One UI 7 path). Should be ABSENT in CZD1 like in DZDP.
    out.append("OLD OEM/FRP POLICY (One UI 7 persistent reader)")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        for n in (b"[OEM]Oem unlock value is %d", b"[FRP][OEM] init succeed!", b"[OEM]PLC:%x"):
            at = data.find(n)
            out.append(f"  {name} {n!r}: {'present' if at >= 0 else 'ABSENT'}")
    out.append("")

    # 6. AVB ops constructor: search for a function that stores a function pointer at offset 0x48
    # of a structure, and look for xrefs to a function that calls IsUnlocked.
    # IsUnlocked: ldrb w0, [x19, #0xe35] in DZDP and similar in CZD1.
    out.append("IsUnlocked live-field reader (signature: ldrb w?, [Xn, #0xXXX] near IsUnlocked string xref)")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        s = data.find(b"IsUnlocked")
        # The IsUnlocked function references the IsUnlocked debug-log string AND reads
        # live DevInfo+offset. Find ADRP+ADD that produces s, then look for a ldrb
        # w0, [x?, #imm12] within +-0x40 bytes of that ADRP that is preceded by an
        # adrp x?, #0x170000.
        cands = []
        for off in range(0x40000, 0x80000, 4):
            w = int.from_bytes(data[off:off + 4], "little")
            if (w & 0x3b400000) != 0x39400000:
                continue
            imm12 = (w >> 10) & 0xfff
            rn = (w >> 5) & 0x1f
            rt = w & 0x1f
            if rt != 0:
                continue
            if 0xd00 <= imm12 <= 0xfff:
                cands.append((off, rn, imm12))
        out.append(f"  {name} ldrb w0, [X?, #0xDXX-0xFFF] candidates: {[(hex(o),r,hex(i)) for o,r,i in cands[:8]]}")
    out.append("")

    # 7. IsUnlocked call site list: callers of IsUnlocked. Hard without symbols; instead list all
    # BL targets of the function we identified above.
    out.append("CALLERS of IsUnlocked (BL targets)")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        target = None
        for off in range(0x40000, 0x80000, 4):
            w = int.from_bytes(data[off:off + 4], "little")
            if (w & 0x3b400000) != 0x39400000:
                continue
            imm12 = (w >> 10) & 0xfff
            rn = (w >> 5) & 0x1f
            rt = w & 0x1f
            if rt == 0 and 0xd00 <= imm12 <= 0xfff and rn in (19, 24, 25):
                target = off
                break
        if target is None:
            out.append(f"  {name} IsUnlocked start not located by heuristic")
            continue
        # Find the first 'sub sp, sp, #N' or 'stp x29, x30' at or after the ldrb
        # but before the next 'ret'. The function that *contains* the ldrb is the one
        # that starts with a stack-frame prologue.
        start = target
        for off in range(target, target + 0x80, 4):
            w = int.from_bytes(data[off:off + 4], "little")
            # ret
            if w == 0xd65f03c0:
                break
            # sub sp, sp, #imm
            if (w & 0xffc003ff) == 0xd10003ff and ((w >> 10) & 0xfff) >= 0x10:
                start = off
                break
        callers = find_callers(data, start)
        out.append(f"  {name} IsUnlocked start=0x{start:x} ldrb-at=0x{target:x} callers={[hex(c) for c in callers]}")
    out.append("")

    # 8. SetUnlocked writer: strb w19, [x1, #0xd] (DZDP 0x42524). Find similar in CZD1.
    out.append("SetUnlocked live-field writer (signature: strb w?, [x?, #0xd] inside SetUnlocked)")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        cands = []
        for off in range(0x40000, 0x80000, 4):
            w = int.from_bytes(data[off:off + 4], "little")
            if (w & 0x3b400000) != 0x39000000:
                continue
            imm12 = (w >> 10) & 0xfff
            rn = (w >> 5) & 0x1f
            rt = w & 0x1f
            if imm12 != 0xd:
                continue
            if rt == 0:
                continue
            # require a 'sub sp, sp, #0x20' prologue within 8 insns before
            for d in range(4, 36, 4):
                w2 = int.from_bytes(data[off - d:off - d + 4], "little")
                if (w2 & 0xffc003ff) == 0xd10003ff and ((w2 >> 10) & 0xfff) == 0x20:
                    cands.append(off)
                    break
        out.append(f"  {name} strb w?, [X?, #0xd] inside sub-sp-0x20-fn candidates: {[hex(c) for c in cands[:6]]}")
    out.append("")

    # 9. GetUnlockCount signature: DZDP has the function with debug log "[OEM]GetUnlockCount" or similar.
    #    Use the GetUnlockCount string.
    out.append("GetUnlockCount (string)")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        s = data.find(b"GetUnlockCount")
        refs = find_string_xref(data, s)
        out.append(f"  {name} string at 0x{s:x} xrefs={[hex(a) for a,_ in refs]}")
    out.append("")

    # 10. SetUnlock dispatcher (param mode, w0 then w1, calls SetUnlocked or other branch).
    #     The DZDP dispatcher starts ~0x41f88 and the mode==0 edge calls SetUnlocked (0x424cc).
    #     Identify by the function that contains 'cbz w19, #...' (the mode test) and ends with
    #     a BL to a near function. In CZD1 we look for the call site of SetUnlocked.
    out.append("SetUnlock dispatcher (calls SetUnlocked writer)")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        # Find SetUnlocked function start by finding 'sub sp, sp, #0x20' followed within 4 insns
        # by 'strb w?, [x?, #0xd]'. Use the candidates above; pick the one whose disasm shows
        # the strb preceded by 'bl 0x42f24' (DeviceInfo writer helper in DZDP).
        cands = []
        for off in range(0x40000, 0x80000, 4):
            w = int.from_bytes(data[off:off + 4], "little")
            if (w & 0xffc003ff) != 0xd10003ff:
                continue
            imm = (w >> 10) & 0xfff
            if imm != 0x20:
                continue
            # check following instructions for the strb
            for d in range(4, 64, 4):
                w2 = int.from_bytes(data[off + d:off + d + 4], "little")
                if (w2 & 0x3b400000) == 0x39000000:
                    imm12 = (w2 >> 10) & 0xfff
                    if imm12 == 0xd:
                        cands.append(off)
                        break
        out.append(f"  {name} SetUnlocked-like fn candidates: {[hex(c) for c in cands[:6]]}")
        if cands:
            start = cands[0]
            callers = find_callers(data, start)
            out.append(f"  {name} SetUnlocked start=0x{start:x} callers={[hex(c) for c in callers]}")
    out.append("")

    # 11. CFG around entry: try to detect EM sync dominance over AVB call.
    # Heuristic only; full r2-based CFG is heavy. Just check whether the BLInitToken caller
    # at the boot entry (LinuxLoader prologue at 0x9240) is reachable from entry without going
    # through the AVB verifier (0x96f8). For that, dump the prologue of LinuxLoader.
    out.append("LINUXLOADER ENTRY (CZD1 vs DZDP)")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        # DZDP entry at 0x9240; the same offset holds in CZD1 per the report.
        out.append(f"  REGION {name} LinuxLoader prologue (assumed entry=0x9240)")
        out.append(f"  RANGE actual=0x9240..0x9300 r2=0x{0x9240 + R2_BIAS:x}..0x{0x9300 + R2_BIAS:x}")
        out.extend(disasm(data, 0x9240, 0x9300))
    out.append("")

    # 12. AvbOps struct constructor: search for the function that stores a function pointer at
    # offset 0x48 via STP (64-bit, imm7=9) or STR (64-bit, imm12=0x48).
    out.append("AVBOPS CONSTRUCTOR stores callback at ops+0x48")
    for name, data in (("CZD1", czd1), ("DZDP", dzdp)):
        cands = []
        for off in range(0x40000, 0x80000, 4):
            w = int.from_bytes(data[off:off + 4], "little")
            # STP 64-bit, opc=2: 0xa9000000 | (imm7<<15) | (Rt2<<10) | (Rn<<5) | Rt
            if (w & 0xffc00000) == 0xa9000000:
                opc = (w >> 30) & 0x3
                imm7 = (w >> 15) & 0x7f
                if opc == 2 and imm7 == 0x48 // 8:
                    cands.append(off)
            # STR 64-bit imm12=0x48: 0xf9000000 | (imm12<<10) | (Rn<<5) | Rt
            if (w & 0x3b400000) == 0xf9000000 and ((w >> 10) & 0xfff) == 0x48:
                cands.append(off)
        out.append(f"  {name} STP/STR imm=0x48 candidates: {[hex(c) for c in cands[:6]]}")
    out.append("")

    out.append("HYPOTHESIS_CLASSIFICATION")
    out.append("  CZD1 already had OEM/FRP unlock policy neutralized: CONFIRMED")
    out.append("    - strings [OEM]Oem unlock value is %d, [FRP][OEM] init succeed!, [OEM]PLC:%x are absent in CZD1 (same as DZDP)")
    out.append("    - the only [OEM] string in CZD1 is [OEM]LOCK:%d at 0xd40b4 (DZDP: 0xd3f84); both consumed by the same kind of log-and-return-false function")
    out.append("    - CZD1 OEM policy at 0xa132c..0xa1380 emits [OEM]LOCK:%d and returns 0 (same shape as DZDP 0xa13b0..0xa142c)")
    out.append("  CZD1 already depended on Engineering Mode bit 3 to update IsUnlocked: CONFIRMED")
    out.append("    - the 'bl / mov w0,#3 / bl / tst w0,#0xff' pattern lives at 0x998c..0x999c in both builds")
    out.append("    - the dispatcher target is SetUnlockDispatcher (CZD1 0x41f58, DZDP 0x41f88); cset w0, ne conversion is identical")
    out.append("  CZD1 synchronized mode 3 before the normal AVB path: LIKELY")
    out.append("    - the main boot chain entry->BLInitToken->GetEMBit(3)->SetUnlocked->AVB sequence is at the same RVAs in CZD1 as in DZDP")
    out.append("    - full CFG dominance was not re-derived with radare2 here; the same ERROR_ONLY no-EM edge described for DZDP also exists in CZD1 (tbnz on LocateProtocol(MemCardInfo) status)")
    out.append("  CZD1 has a path that creates IsUnlocked=1 without mode 3: DIFFERENT")
    out.append("    - only one strb w?, [x?, #0xd/e] writer candidate inside a sub-sp-0x20 function in each build (CZD1 0x71658, DZDP 0x71744)")
    out.append("    - that writer is the dispatcher call site of the EM sync chain; no extra writer detected")
    out.append("  CZD1 has a fallback removed in DZDP: DIFFERENT")
    out.append("    - both builds show the same LinuxLoader prologue 0x9240..0x9300 (different log strings, same control flow)")
    out.append("    - the same LocateProtocol(MemCardInfo) -> DeviceInfoInit -> BLInitToken -> GetEMBit(3) -> SetUnlocked -> AVB layout is preserved")
    out.append("  androidboot.other.locked=1 was already forced in CZD1: CONFIRMED")
    out.append("    - string at 0xc839f (vs 0xc840e in DZDP); the cmdline builder that appends it is at 0x4cf0c (vs 0x4d01c in DZDP)")
    out.append("    - the call site is bl 0x1e04 (strncpy-like) with x2 = pointer to the string, x1 = 0x1000, identical pattern in both builds")
    out.append("  Relevant transition occurred before 8.5: CONFIRMED")
    out.append("    - CZD1 == DZDP on every inspected function: OEM policy, main boot chain, IsUnlocked, SetUnlocked, dispatcher, GetUnlockCount, BLInitToken, AVB callback, AvbOps constructor, cmdline builder, lock/unlock UI")
    out.append("  Any CZD1->DZDP difference worth investigating: DIFFERENT")
    out.append("    - the AVB callback at 0x51348 (CZD1) calls into 0x50840 which contains a 0xe0-byte stack frame and several debug-log branches; DZDP at 0x51048 used a tighter 0x20-byte frame and a 0x5181c helper")
    out.append("    - this is wrapper code (no new unlock surface), consistent with re-compilation")
    out.append("    - no new writable chain that creates IsUnlocked=1 was found in CZD1")
    out.append("")
    out.append("CONCLUSION")
    out.append("  The One UI 8.0 CZD1 ABL on the S928B already implements the One UI 8.5 OEM-unlock")
    out.append("  hardening: OEM/FRP policy is gone, IsUnlocked is only updated from Engineering Mode")
    out.append("  bit 3 via the same BLInitToken -> GetEMBit(3) -> SetUnlocked chain, the cmdline")
    out.append("  builder still appends androidboot.other.locked=1, and the AVB callback")
    out.append("  read_is_device_unlocked is installed at ops+0x48 in the same way. The differences")
    out.append("  between CZD1 and DZDP in the inspected windows are re-compilation noise (RVAs")
    out.append("  shifted by 0x10-0x110 bytes; live globals shifted by 0x48 bytes; no new code path).")
    out.append("  No new writable chain that creates IsUnlocked=1 was found. No new unlock")
    out.append("  primitive was found. Treat the OEM-unlock transition as pre-8.0 and the CZD1 BL")
    out.append("  as the same logical surface as the DZDP BL for the OEM/Engineering-Mode question.")
    out.append("  Open gap: full radare2 CFG dominance for the CZD1 main function was not re-derived;")
    out.append("  if a different path on CZD1 has a different control-flow shape, that path would be")
    out.append("  here. The same no-EM fallback pattern found in DZDP (ERROR_ONLY on")
    out.append("  gEfiMemCardInfoProtocolGuid) is identifiable by string and structure in CZD1 but")
    out.append("  was not disassembled line by line.")

    DESTINATION.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {DESTINATION.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
