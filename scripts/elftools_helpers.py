"""Shared ELF helpers: symbol/reloc/section loading + capstone disassembly."""
import struct, sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_ARCH_ARM, CS_MODE_THUMB


class Bin:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        self.f = ELFFile(open(path, 'rb'))
        self.arch = self.f.get_machine_arch()
        self.is64 = self.f.elfclass == 64
        self.syms = {}          # name -> (va, size, shndx, info)
        self.syms_by_va = {}    # va -> name
        self.relocs = []        # (offset, sym_name, type)
        self._load_syms()
        self._load_relocs()
        # text segment (vaddr, file offset, size)
        self.segs = []
        for seg in self.f.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                self.segs.append((seg['p_vaddr'], seg['p_offset'], seg['p_filesz'], seg['p_memsz'], seg['p_flags']))
        self.md = self._mk_md()

    def _mk_md(self):
        if self.arch == 'AArch64':
            return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        return Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def _load_syms(self):
        for sec in self.f.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for s in sec.iter_symbols():
                    if not s.name:
                        continue
                    e = s.entry
                    self.syms.setdefault(s.name, (e.st_value, e.st_size, e.st_shndx, e.st_info))
                    if e.st_value and e.st_value not in self.syms_by_va:
                        self.syms_by_va[e.st_value] = s.name

    def _load_relocs(self):
        for sec in self.f.iter_sections():
            if sec.header.sh_type in ('SHT_RELA', 'SHT_REL'):
                symtab = self.f.get_section(sec.header.sh_link)
                for r in sec.iter_relocations():
                    name = ''
                    try:
                        name = symtab.get_symbol(r['r_info_sym']).name
                    except Exception:
                        pass
                    self.relocs.append((r['r_offset'], name, r['r_info_type']))

    def v2o(self, va):
        for vaddr, off, fsz, msz, fl in self.segs:
            if vaddr <= va < vaddr + fsz:
                return off + (va - vaddr)
        return None

    def o2v(self, off):
        for vaddr, o, fsz, msz, fl in self.segs:
            if o <= off < o + fsz:
                return vaddr + (off - o)
        return None

    def code(self, va, size):
        """Read `size` bytes of code starting at virtual address va."""
        off = self.v2o(va)
        if off is None:
            return b''
        return self.data[off:off + size]

    def dis(self, va, size, maxins=100000):
        c = self.code(va, size)
        out = []
        n = 0
        for i in self.md.disasm(c, va):
            out.append((i.address, i.bytes.hex(), i.mnemonic, i.op_str))
            n += 1
            if n >= maxins:
                break
        return out

    def find_func_end(self, va, maxsize=0x2000):
        """Heuristic: scan for RET / unconditional-branch-to-outside to end a function.
        Returns (end_va_exclusive, instructions)."""
        ins = self.dis(va, maxsize)
        last = va
        end_idx = len(ins)
        for idx, (addr, raw, mn, op) in enumerate(ins):
            last = addr + len(bytes.fromhex(raw)) // 2
            if mn == 'ret':
                end_idx = idx + 1
                break
        return ins[:end_idx]

    def reloc_near(self, va, span=0x4000):
        return [(o, n, t) for (o, n, t) in self.relocs if va <= self.o2v(o) or True]

    def sym(self, name):
        return self.syms.get(name, (None,))[0]

    def nearest_sym(self, va):
        best = None
        for v, n in self.syms_by_va.items():
            if v <= va and (best is None or v > best[0]):
                best = (v, n)
        return best

    def strings(self, minlen=4):
        import re
        return [(m.start(), m.group().decode('latin1'))
                for m in re.finditer(rb'[ -~]{%d,}' % minlen, self.data)]


def fmt(ins, b=None, show_reloc=False):
    out = []
    for (addr, raw, mn, op) in ins:
        line = f"{addr:08x}: {raw:<16} {mn:<8} {op}"
        out.append(line)
    return "\n".join(out)
