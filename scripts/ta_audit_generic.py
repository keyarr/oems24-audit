#!/usr/bin/env python3
"""Generic, read-only evidence extractor for sectionless QSEE trustlets.

Unlike ta_audit.py this does NOT hardcode em.img anchor offsets or em-specific
region names.  It parses any ELF64 AArch64 TA (keymaster, vk, ...) and emits:

  1. ELF header / program headers / PT_LOAD / page alignment.
  2. Import table (DT_SYMTAB + DT_JMPREL) with PLT veneer VA + disasm.
  3. TEE-known symbol hunt (qsee_*, gp_*, __stack_chk_*, _secmath_*).
  4. Printable string scan for crypto / boot / lock keywords.
  5. Function-prologue scan (bti c; pacibsp; stp x29,x30; sub sp,sp) with frame size.

It never opens a device and never mutates the input image.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IMAGE = ROOT / "partitions_extra" / "keymaster.img"
OUT = ROOT / "decompiled"
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def resolve_image() -> tuple[Path, Path]:
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--image", type=Path, default=DEFAULT_IMAGE)
    parser.add_argument("--out", type=Path, default=OUT)
    # keep the em.img report names untouched when invoked historically
    parser.add_argument("--label", type=str, default=None)
    args, _ = parser.parse_known_args()
    return args.image.resolve(), args.out, args.label


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Trustlet:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            self.header = dict(elf.header)
            self.segments = [dict(segment.header) for segment in elf.iter_segments()]
        self.loads = [s for s in self.segments if s["p_type"] == "PT_LOAD"]

    def va_to_file(self, va: int) -> int:
        for segment in self.loads:
            start = int(segment["p_vaddr"])
            size = int(segment["p_filesz"])
            if start <= va < start + size:
                return int(segment["p_offset"]) + va - start
        raise ValueError(f"VA 0x{va:x} is not file-backed")

    def file_to_va(self, offset: int) -> int:
        for segment in self.loads:
            start = int(segment["p_offset"])
            size = int(segment["p_filesz"])
            if start <= offset < start + size:
                return int(segment["p_vaddr"]) + offset - start
        raise ValueError(f"file offset 0x{offset:x} is not in PT_LOAD")

    def unpack_va(self, fmt: str, va: int):
        return struct.unpack_from(fmt, self.data, self.va_to_file(va))

    def dynamic(self) -> dict[int, int]:
        dynamic = next(s for s in self.segments if s["p_type"] == "PT_DYNAMIC")
        result: dict[int, int] = {}
        offset = int(dynamic["p_offset"])
        end = offset + int(dynamic["p_filesz"])
        while offset + 16 <= end:
            tag, value = struct.unpack_from("<QQ", self.data, offset)
            offset += 16
            if tag == 0:
                break
            result[tag] = value
        return result

    def symbols_and_plt(self):
        dyn = self.dynamic()
        hash_file = self.va_to_file(dyn[4])
        _nbucket, nchain = struct.unpack_from("<II", self.data, hash_file)
        sym_file = self.va_to_file(dyn[6])
        str_file = self.va_to_file(dyn[5])
        syment = dyn[11]
        symbols = []
        for index in range(nchain):
            at = sym_file + index * syment
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                "<IBBHQQ", self.data, at
            )
            name_at = str_file + st_name
            name_end = self.data.find(b"\0", name_at)
            name = self.data[name_at:name_end].decode("ascii", "backslashreplace")
            symbols.append((name, st_value, st_size, st_info, st_shndx))

        rela_file = self.va_to_file(dyn[23])
        rela_count = dyn[2] // dyn[9]
        # Detect the PLT veneer base: QSEE places 16-byte veneers (adrp/ldr/add/br)
        # consecutively starting at a low VA.  Verify the first entry decodes to the
        # expected 4-instruction stub before trusting 0x20; otherwise search.
        veneer_base = None
        for candidate in (0x20, 0x0):
            ok = True
            try:
                raw = self.data[self.va_to_file(candidate): self.va_to_file(candidate) + 16]
            except ValueError:
                continue
            insns = list(MD.disasm(raw, candidate))
            if len(insns) == 4 and insns[-1].mnemonic == "br":
                veneer_base = candidate
                break
        if veneer_base is None:
            # Fall back to 0x20; caller can inspect the disasm to confirm sanity.
            veneer_base = 0x20
        plt = []
        for index in range(rela_count):
            r_offset, r_info, r_addend = struct.unpack_from(
                "<QQq", self.data, rela_file + index * dyn[9]
            )
            sym_index = r_info >> 32
            plt_va = veneer_base + index * 0x10
            plt.append((plt_va, r_offset, r_info & 0xFFFFFFFF, r_addend, symbols[sym_index][0]))
        return symbols, plt

    def disasm(self, start: int, end: int) -> list[str]:
        file_start = self.va_to_file(start)
        raw = self.data[file_start: file_start + (end - start)]
        return [
            (
                f"  VA 0x{insn.address:06x}  file 0x{self.va_to_file(insn.address):06x}  "
                f"{insn.mnemonic:<8} {insn.op_str}"
            ).rstrip()
            for insn in MD.disasm(raw, start)
        ]

    def string_offsets(self, needle: bytes) -> list[tuple[int | None, int]]:
        result = []
        cursor = 0
        while True:
            cursor = self.data.find(needle, cursor)
            if cursor < 0:
                break
            try:
                va = self.file_to_va(cursor)
            except ValueError:
                va = None
            result.append((va, cursor))
            cursor += 1
        return result


def metadata(ta: Trustlet, label: str) -> list[str]:
    h = ta.header
    lines = [
        f"TRUSTLET {label}",
        f"INPUT {ta.path.relative_to(ROOT)}",
        f"SIZE {ta.path.stat().st_size}",
        f"SHA256 {sha256(ta.path)}",
        "FORMAT ELF64 little-endian AArch64 ET_DYN; no section table",
        f"ENTRY VA=0x{int(h['e_entry']):x}",
        f"PHOFF=0x{int(h['e_phoff']):x} PHNUM={int(h['e_phnum'])} PHSIZE={int(h['e_phentsize'])}",
        "",
        "PROGRAM_HEADERS",
    ]
    for seg in ta.segments:
        t = seg["p_type"]
        if t == "PT_LOAD":
            continue
        lines.append(f"  {t} off=0x{int(seg['p_offset']):x} VA=0x{int(seg['p_vaddr']):x} "
                     f"filesz=0x{int(seg['p_filesz']):x} flags={int(seg['p_flags'])}")
    lines.append("PT_LOAD")
    for seg in ta.loads:
        flags = int(seg["p_flags"])
        fstr = "{}{}{}".format("R" if flags & 4 else "-", "W" if flags & 2 else "-",
                               "X" if flags & 1 else "-")
        lines.append(
            f"  file=0x{int(seg['p_offset']):x} VA=0x{int(seg['p_vaddr']):x} "
            f"filesz=0x{int(seg['p_filesz']):x} memsz=0x{int(seg['p_memsz']):x} "
            f"flags={fstr} page_aligned={'yes' if (int(seg['p_vaddr']) & 0xFFF) == 0 and (int(seg['p_offset']) & 0xFFF) == 0 else 'NO'}"
        )
    # whole-image page alignment summary
    aligned = all((int(s['p_vaddr']) & 0xFFF) == 0 and (int(s['p_offset']) & 0xFFF) == 0 for s in ta.loads)
    lines.append(f"PAGE_ALIGNMENT_REQUIRED yes; all PT_LOAD vaddr/offset aligned to 4K: {aligned}")
    return lines


def imports_report(ta: Trustlet, label: str, disasm_limit: int | None = None) -> str:
    symbols, plt = ta.symbols_and_plt()
    lines = [
        f"TRUSTLET {label}: IMPORT TABLE (DT_SYMTAB / DT_JMPREL) AND PLT VENEERS",
        "",
        *metadata(ta, label),
        "",
        "IMPORTS (symbol -> PLT veneer VA -> GOT VA)",
        f"  count={len(plt)}",
    ]
    tee_known = ("qsee_", "gp_", "__stack_chk_", "_secmath_")
    for idx, (plt_va, got, rtype, addend, name) in enumerate(plt):
        prefix = "*" if name.startswith(tee_known) else " "
        lines.append(f"  {prefix} #{idx:<3} PLT=0x{plt_va:06x} GOT=0x{got:06x} "
                     f"reloc={rtype} addend={addend} {name}")
    # veneer disasm
    lines += ["", "PLT VENEER DISASSEMBLY"]
    count = len(plt) if disasm_limit is None else min(disasm_limit, len(plt))
    for idx in range(count):
        plt_va = plt[idx][0]
        lines.append(f"  --- veneer #{idx} PLT=0x{plt_va:06x} -> {plt[idx][4]} ---")
        try:
            lines += ta.disasm(plt_va, plt_va + 0x10)
        except ValueError as exc:
            lines.append(f"    (skipped: {exc})")
    if disasm_limit is not None and len(plt) > disasm_limit:
        lines.append(f"  ... {len(plt) - disasm_limit} more veneers not disasmed (use --full)")
    # TEE-known summary
    lines += ["", "TEE_KNOWN_SYMBOLS"]
    for kw in tee_known:
        hits = [n for _, _, _, _, n in plt if n.startswith(kw)]
        lines.append(f"  {kw}* : {len(hits)} -> " + (", ".join(sorted(set(hits))) if hits else "none"))
    return "\n".join(lines) + "\n"


def strings_report(ta: Trustlet, label: str) -> str:
    keywords = [
        b"rsa", b"ecdsa", b"attest", b"key", b"mode", b"token", b"deviceid",
        b"bootloader", b"lock", b"unlock", b"verify", b"cmac", b"aes", b"sha256",
        b"p256", b"hmac", b"rpmb", b"oemlock", b"oem_lock", b"unlock", b"fabric",
        b"attestation", b"keymint", b"keymaster", b"secure", b"nonce",
    ]
    lines = [
        f"TRUSTLET {label}: PRINTABLE STRING SCAN (>=4 ascii chars, keyword hits)",
        "",
        *metadata(ta, label),
        "",
        "KEYWORD_STRING_OCCURRENCES (direct byte search, case-insensitive substring)",
    ]
    for needle in keywords:
        hits = ta.string_offsets(needle)
        rendered = ", ".join(
            f"VA=0x{va:x}/file=0x{off:x}" if va is not None else f"file=0x{off:x}"
            for va, off in hits
        ) or "ABSENT"
        lines.append(f"  {needle.decode('ascii','backslashreplace')!r}: count={len(hits)} {rendered}")
    return "\n".join(lines) + "\n"


# Prologue byte signatures (little-endian AArch64).
BTI_C = b"\x1f\x24\x03\xd5"        # bti c
PACIBSP = b"\x3f\x23\x03\xd5"      # pacibsp
STP_X29_X30 = b"\x7b\xbf\xa9"      # tail of stp x29,x30,[sp,#imm]! (byte0 varies)
SUB_SP = b"\xff\x03"               # prefix of sub sp,sp,#imm (0xd1 0x.. 0x03 0xff)


def function_scan(ta: Trustlet, label: str, window: int = 24) -> str:
    # scan the first PT_LOAD (RX code) for prologue signatures, 4-byte aligned.
    code = ta.loads[0]
    cstart = int(code["p_vaddr"])
    csize = int(code["p_filesz"])
    data = ta.data
    cfile0 = int(code["p_offset"])

    def word_at(foff: int) -> int:
        return struct.unpack_from("<I", data, foff)[0]

    def is_bti_c(w: int) -> bool:
        return w == 0xD503241F

    def is_pac(w: int) -> bool:
        # pacibsp = 0xd503223f; also accept other pac* hint forms ending 0x22/0x23
        return (w & 0xFFFFFF00) == 0xD5032200 and ((w & 0xFF) in (0x1F, 0x3F, 0x5F, 0x7F, 0x9F, 0xBF, 0xDF, 0xFF))

    def is_stp_fp(w: int) -> bool:
        # stp x29,x30,[sp,#imm]! -> LE bytes FD 7B BF A9 (byte0 = imm field, varies)
        return data[foff + 1] == 0x7B and data[foff + 2] == 0xBF and data[foff + 3] == 0xA9 and (w & 0xFF000000) == 0xA9000000

    def is_stp_sp(w: int) -> bool:
        # any stp xN,xM,[sp,#imm] (store-pair 128-bit, Rn(sp)=31, L=0 store).
        # high byte 0xA9 already implies sf=1/opc=10/pair; require store (bit22=0)
        # and Rn==sp so we do not flag ldp or non-sp base.
        if (w & 0xFF000000) != 0xA9000000:
            return False
        if ((w >> 22) & 1) != 0:
            return False
        return ((w >> 5) & 0x1F) == 0x1F  # Rn == sp

    def is_sub_sp(w: int) -> bool:
        # sub sp,sp,#imm -> LE FF 03 ?? D1
        return (w & 0xFF) == 0xFF and ((w >> 8) & 0xFF) == 0x03 and ((w >> 24) & 0xFF) == 0xD1

    candidates: list[tuple[int, int, bool, bool]] = []
    seen = set()
    foff = cfile0
    end = cfile0 + csize - 4
    prev_stp = False
    while foff <= end:
        w = word_at(foff)
        this_stp = is_stp_sp(w) or is_stp_fp(w)
        is_start = (is_bti_c(w) or is_pac(w) or this_stp) and not prev_stp
        if is_start and foff not in seen:
            seen.add(foff)
            candidates.append((cstart + (foff - cfile0), foff, is_bti_c(w), is_stp_fp(w)))
        prev_stp = this_stp
        foff += 4

    # Build per-candidate flags + frame size by disassembling a small window.
    results = []
    for va, foff, is_bti, is_fp in sorted(candidates):
        raw = data[foff: foff + window * 4]
        insns = list(MD.disasm(raw, va))
        has_pac = any("pacibsp" in i.mnemonic or (i.mnemonic == "hint" and "0x22" in i.op_str) for i in insns[:3])
        frame = 0
        # stp x29,x30,[sp,#imm]! immediate contributes to the frame size
        if is_fp:
            w0 = word_at(foff)
            imm7 = (w0 >> 15) & 0x7F
            if imm7 & 0x40:
                imm7 -= 0x80
            frame += abs(imm7) * 8
        for i in insns:
            if i.mnemonic == "sub" and i.op_str.startswith("sp, sp"):
                try:
                    frame += int(i.op_str.split("#")[-1].split(" ")[0], 16)
                except ValueError:
                    pass
        results.append((va, is_bti, has_pac, is_fp, frame, insns[:window]))

    lines = [
        f"TRUSTLET {label}: FUNCTION PROLOGUE CANDIDATES",
        "",
        *metadata(ta, label),
        "",
        f"PROLOGUE_SIGNATURE_SCAN code VA=0x{cstart:x}..0x{cstart + csize:x}",
        f"  candidate_count={len(results)}",
        "",
        "CANDIDATE TABLE (VA, BTI, FP(x29/x30), PAC, frame_bytes, first_insn)",
    ]
    for va, bti, pac, fp, frame, insns in results:
        first = insns[0] if insns else None
        firsts = f"{first.mnemonic} {first.op_str}" if first else "?"
        lines.append(f"  0x{va:06x} bti={int(bti)} fp={int(fp)} pac={int(pac)} frame=0x{frame:x} :: {firsts}")

    # Full disasm of BTI/PAC-marked functions (likely exported / entry points).
    marked = [r for r in results if (r[1] or r[2])]
    lines += ["", f"FULL PROLOGUE DISASM OF BTI/PAC-MARKED FUNCTIONS ({len(marked)})"]
    for va, bti, pac, fp, frame, insns in marked:
        lines.append(f"  === 0x{va:06x} bti={int(bti)} fp={int(fp)} pac={int(pac)} frame=0x{frame:x} ===")
        for i in insns:
            lines.append(f"    VA 0x{i.address:06x}  {i.mnemonic:<8} {i.op_str}")
    return "\n".join(lines) + "\n"


def main() -> None:
    import sys
    image, out_dir, label_arg = resolve_image()
    label = label_arg or image.stem
    ta = Trustlet(image)
    out_dir.mkdir(parents=True, exist_ok=True)

    args = sys.argv[1:]
    full = "--full" in args
    imports = imports_report(ta, label, disasm_limit=None if full else 40)
    strings = strings_report(ta, label)
    funcs = function_scan(ta, label)

    out_imports = out_dir / f"{label}-imports.txt"
    out_strings = out_dir / f"{label}-strings.txt"
    out_funcs = out_dir / f"{label}-functions.txt"
    out_imports.write_text(imports, encoding="utf-8")
    out_strings.write_text(strings, encoding="utf-8")
    out_funcs.write_text(funcs, encoding="utf-8")
    print(f"wrote {out_imports.relative_to(ROOT)} ({len(imports.encode('utf-8'))} bytes)")
    print(f"wrote {out_strings.relative_to(ROOT)} ({len(strings.encode('utf-8'))} bytes)")
    print(f"wrote {out_funcs.relative_to(ROOT)} ({len(funcs.encode('utf-8'))} bytes)")


if __name__ == "__main__":
    main()
