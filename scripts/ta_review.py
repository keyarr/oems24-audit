#!/usr/bin/env python3
"""Adversarial review helper for the Engineering Mode trustlet.

Read-only.  Pure static analysis: resolves VA<->file through PT_LOAD,
disassembles ranges, resolves imports/PLT, finds code cross references and
dumps data.  Never touches a device.

usage:
  python scripts/ta_review.py d      <va> [len]        disassemble
  python scripts/ta_review.py df     <fileoff> [len]   disassemble by file offset
  python scripts/ta_review.py x      <va> [len]        hex dump at VA
  python scripts/ta_review.py xf     <fileoff> [len]   hex dump at file offset
  python scripts/ta_review.py v2f    <va>              VA -> file offset
  python scripts/ta_review.py f2v    <fileoff>         file offset -> VA
  python scripts/ta_review.py str    <needle>          find literal bytes
  python scripts/ta_review.py xref   <va>              find bl/b/br/cbz/tbz to VA
  python scripts/ta_review.py adr    <va>              find ADRP+ADD materialisations of VA
  python scripts/ta_review.py fn     <va>              disassemble until ret
  python scripts/ta_review.py sym    [needle]          list dynamic symbols / PLT
  python scripts/ta_review.py u32/u64/sb <va> [count]  decode a data table
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IMAGE = ROOT / "partitions" / "em.img"
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

BRANCH_MNEMONICS = {
    "bl", "b", "br", "blr", "b.eq", "b.ne", "b.cs", "b.hs", "b.cc", "b.lo",
    "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt", "b.gt",
    "b.le", "cbz", "cbnz", "tbz", "tbnz", "ret", "brk",
}


class Trustlet:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            self.segments = [dict(s.header) for s in elf.iter_segments()]
        self.loads = [s for s in self.segments if s["p_type"] == "PT_LOAD"]
        self.exec_segs = [s for s in self.loads if int(s["p_flags"]) & 1]
        self._plt_cache: dict[int, str] | None = None
        self._sym_cache: list | None = None

    # ---------- address translation ----------
    def va_to_file(self, va: int) -> int:
        for s in self.loads:
            start, size = int(s["p_vaddr"]), int(s["p_filesz"])
            if start <= va < start + size:
                return int(s["p_offset"]) + va - start
        raise ValueError(f"VA 0x{va:x} not file-backed")

    def file_to_va(self, off: int) -> int:
        for s in self.loads:
            start, size = int(s["p_offset"]), int(s["p_filesz"])
            if start <= off < start + size:
                return int(s["p_vaddr"]) + off - start
        raise ValueError(f"file 0x{off:x} not in a PT_LOAD")

    def readable(self, va: int, n: int) -> bool:
        try:
            off = self.va_to_file(va)
        except ValueError:
            return False
        return 0 <= off and off + n <= len(self.data)

    def bytes_at(self, va: int, n: int) -> bytes:
        off = self.va_to_file(va)
        return self.data[off : off + n]

    # ---------- disassembly ----------
    def insns(self, start: int, length: int):
        off = self.va_to_file(start)
        raw = self.data[off : off + length]
        return list(MD.disasm(raw, start))

    def disasm(self, start: int, length: int, annotate=True) -> list[str]:
        out = []
        for i in self.insns(start, length):
            line = f"  {i.address:06x}  f{i._file_off(self) if False else self.va_to_file(i.address):06x}  {i.mnemonic:<8} {i.op_str}".rstrip()
            if annotate:
                note = self._annotate(i)
                if note:
                    line += f"   ; {note}"
            out.append(line)
        return out

    def _annotate(self, i) -> str:
        """Add target names / literal strings for branch and adrp instructions."""
        ops = i.op_str
        if i.mnemonic in ("bl", "b") and ops.startswith("0x"):
            tgt = int(ops.split()[0], 16)
            name = self.plt_name(tgt)
            return f"-> 0x{tgt:x}" + (f" ({name})" if name else "")
        if i.mnemonic == "adrp" and "#0x" in ops:
            page = int(re.search(r"#(0x[0-9a-f]+)", ops).group(1), 16)
            # try to show the string/data hint at page+known lo12 later; print page only
            try:
                if self.readable(page, 8):
                    b = self.bytes_at(page, 8)
                    if all(32 <= c < 127 for c in b):
                        return f"page=0x{page:x} '{b.decode('ascii')}'"
            except Exception:
                pass
            return f"page=0x{page:x}"
        return ""

    # ---------- symbols ----------
    def dynamic(self) -> dict[int, int]:
        dyn = next(s for s in self.segments if s["p_type"] == "PT_DYNAMIC")
        res: dict[int, int] = {}
        off, end = int(dyn["p_offset"]), int(dyn["p_offset"]) + int(dyn["p_filesz"])
        while off + 16 <= end:
            tag, val = struct.unpack_from("<QQ", self.data, off)
            off += 16
            if tag == 0:
                break
            res[tag] = val
        return res

    def symbols(self):
        if self._sym_cache is not None:
            return self._sym_cache
        dyn = self.dynamic()
        hf = self.va_to_file(dyn[4])
        _nb, nchain = struct.unpack_from("<II", self.data, hf)
        symf = self.va_to_file(dyn[6])
        strf = self.va_to_file(dyn[5])
        syment = dyn[11]
        syms = []
        for idx in range(nchain):
            at = symf + idx * syment
            st_name, st_info, _o, _sh, st_value, st_size = struct.unpack_from("<IBBHQQ", self.data, at)
            end = self.data.find(b"\0", strf + st_name)
            syms.append((self.data[strf + st_name : end].decode("ascii", "backslashreplace"),
                         st_value, st_size, st_info))
        self._sym_cache = syms
        return syms

    def plt_map(self) -> dict[int, str]:
        """VA of PLT veneer -> symbol name (veneers are 16 bytes from 0x20)."""
        if self._plt_cache is not None:
            return self._plt_cache
        dyn = self.dynamic()
        syms = self.symbols()
        relaf = self.va_to_file(dyn[23])
        count = dyn[2] // dyn[9]
        out: dict[int, str] = {}
        for idx in range(count):
            _r_off, r_info, _add = struct.unpack_from("<QQq", self.data, relaf + idx * dyn[9])
            out[0x20 + idx * 0x10] = syms[r_info >> 32][0]
        self._plt_cache = out
        return out

    def plt_name(self, va: int) -> str | None:
        return self.plt_map().get(va)

    # ---------- search ----------
    def xrefs(self, target: int, insns=None) -> list[str]:
        """Find control-flow references to target across all executable segments."""
        hits = []
        if insns is None:
            insns = []
            for s in self.exec_segs:
                va, n = int(s["p_vaddr"]), int(s["p_filesz"])
                insns.extend(self.insns(va, n))
        for i in insns:
            if i.mnemonic in ("bl", "b", "b.eq", "b.ne", "b.cs", "b.hs", "b.cc", "b.lo",
                              "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls", "b.ge",
                              "b.lt", "b.gt", "b.le", "cbz", "cbnz", "tbz", "tbnz"):
                nums = re.findall(r"#?(0x[0-9a-f]+)", i.op_str)
                for n_ in nums:
                    if int(n_, 16) == target:
                        hits.append(f"  {i.address:06x}  {i.mnemonic:<6} {i.op_str}")
                        break
        return hits

    def adrp_pairs(self, target: int) -> list[str]:
        """Find ADRP+ADD/LDR materialisations of an address within all exec segs."""
        page = target & ~0xFFF
        lo12 = target & 0xFFF
        hits = []
        for s in self.exec_segs:
            va, n = int(s["p_vaddr"]), int(s["p_filesz"])
            insns = self.insns(va, n)
            for k, i in enumerate(insns):
                m = re.search(r"#(0x[0-9a-f]+)", i.op_str)
                if i.mnemonic == "adrp" and m and int(m.group(1), 16) == page:
                    chunk = insns[k : k + 3]
                    body = " | ".join(f"{c.mnemonic} {c.op_str}" for c in chunk)
                    # a matching add with our lo12 within 2 insns
                    ok = any(
                        re.search(rf"#0x{lo12:x}\b", c.op_str) or f"#{lo12}]" in c.op_str
                        or f",#{lo12}]" in c.op_str or f"#0x{lo12:x}]" in c.op_str
                        for c in chunk[1:]
                    )
                    if ok:
                        hits.append(f"  {i.address:06x}  {body}")
        return hits

    def find_bytes(self, needle: bytes) -> list[tuple[int | None, int]]:
        res, cur = [], 0
        while True:
            cur = self.data.find(needle, cur)
            if cur < 0:
                break
            try:
                res.append((self.file_to_va(cur), cur))
            except ValueError:
                res.append((None, cur))
            cur += 1
        return res

    def cstring_at(self, va: int, limit: int = 256) -> str:
        off = self.va_to_file(va)
        end = self.data.find(b"\0", off, off + limit)
        if end < 0:
            end = off + limit
        return self.data[off:end].decode("ascii", "backslashreplace")


def hexdump(ta: Trustlet, va: int, n: int) -> list[str]:
    try:
        off = ta.va_to_file(va)
    except ValueError:
        return [f"  VA 0x{va:x} not file-backed"]
    lines = []
    for base in range(0, n, 16):
        chunk = ta.data[off + base : off + base + 16]
        if not chunk:
            break
        hexs = " ".join(f"{c:02x}" for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"  {va + base:06x} f{off + base:06x}  {hexs:<47}  {asc}")
    return lines


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    img = DEFAULT_IMAGE
    # allow --image X anywhere
    if "--image" in args:
        img = Path(args[args.index("--image") + 1])
        args = args[: args.index("--image")] + args[args.index("--image") + 2 :]
    ta = Trustlet(img)

    def num(s, default=None):
        return int(s, 0) if s else default

    if cmd == "d":
        va, n = num(args[1]), num(args[2], 0x100)
        print(f"; VA 0x{va:x} file 0x{ta.va_to_file(va):x}")
        print("\n".join(ta.disasm(va, n)))
    elif cmd == "df":
        off, n = num(args[1]), num(args[2], 0x100)
        print("\n".join(ta.disasm(ta.file_to_va(off), n)))
    elif cmd == "fn":
        va = num(args[1])
        # disassemble up to 0x2000 bytes but stop 1 insn after first ret
        insns = ta.insns(va, num(args[2] if len(args) > 2 else "0x2000", 0x2000))
        for k, i in enumerate(insns):
            line = f"  {i.address:06x}  f{ta.va_to_file(i.address):06x}  {i.mnemonic:<8} {i.op_str}"
            note = ta._annotate(i)
            if note:
                line += f"   ; {note}"
            print(line.rstrip())
            if i.mnemonic == "ret":
                break
    elif cmd == "x":
        print(f"; VA 0x{num(args[1]):x} file 0x{ta.va_to_file(num(args[1])):x}")
        print("\n".join(hexdump(ta, num(args[1]), num(args[2], 0x80))))
    elif cmd == "xf":
        print("\n".join(hexdump(ta, ta.file_to_va(num(args[1])), num(args[2], 0x80))))
    elif cmd == "v2f":
        print(f"0x{ta.va_to_file(num(args[1])):x}")
    elif cmd == "f2v":
        print(f"0x{ta.file_to_va(num(args[1])):x}")
    elif cmd == "str":
        needle = args[1].encode().decode("unicode_escape").encode("latin1")
        hits = ta.find_bytes(needle)
        print(f"; {len(hits)} hit(s)")
        for va, off in hits:
            ctx = ""
            if va is not None:
                try:
                    ctx = f"  '{ta.cstring_at(va)}'"
                except Exception:
                    pass
                print(f"; VA=0x{va:x} file=0x{off:x}{ctx}")
            else:
                print(f"; (not in PT_LOAD) file=0x{off:x}")
    elif cmd == "xref":
        tgt = num(args[1])
        hits = ta.xrefs(tgt)
        print(f"; {len(hits)} xref(s) to 0x{tgt:x}")
        print("\n".join(hits) if hits else "  (none)")
    elif cmd == "adr":
        tgt = num(args[1])
        hits = ta.adrp_pairs(tgt)
        print(f"; {len(hits)} ADRP materialisation(s) of 0x{tgt:x}")
        print("\n".join(hits) if hits else "  (none)")
    elif cmd in ("u32", "u64", "sb"):
        va, count = num(args[1]), num(args[2], 16)
        fmt = {"u32": "<I", "u64": "<Q", "sb": "<b"}[cmd]
        sz = struct.calcsize(fmt)
        for k in range(count):
            v = struct.unpack_from(fmt, ta.bytes_at(va + k * sz, sz))[0]
            extra = ""
            if cmd == "u64" and ta.readable(v, 4):
                extra = f"  *0x{v:x}"
            print(f"  [{k:3d}] 0x{va + k * sz:06x} = 0x{v:x} ({v}){extra}")
    elif cmd == "sym":
        needle = args[1] if len(args) > 1 else None
        plt = ta.plt_map()
        for va in sorted(plt):
            if needle is None or needle.lower() in plt[va].lower():
                print(f"  PLT 0x{va:06x}  {plt[va]}")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
