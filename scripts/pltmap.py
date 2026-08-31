"""Build PLT index -> symbol name map and annotate disassembly with call targets."""
import sys, struct
sys.path.insert(0, 'scripts')
from elftools_helpers import Bin


def plt_map(b):
    """Return dict: call-stub-va -> symbol name, and index->name."""
    plt = None
    relaplt = None
    for s in b.f.iter_sections():
        if s.name == '.plt':
            plt = s.header
        if s.name == '.rela.plt':
            relaplt = s
    out = {}
    data = b.data
    ro, rs = relaplt.header.sh_offset, relaplt.header.sh_size
    n = rs // 24
    symtab = b.f.get_section(relaplt.header.sh_link)
    for i in range(n):
        off, info, add = struct.unpack_from('<QQq', data, ro + 24 * i)
        name = symtab.get_symbol(info >> 32).name
        # PLT0 is 24 bytes, then each entry is 24 bytes with the adrp at block+8
        stub = plt.sh_addr + 0x18 + 8 + 0x18 * i
        out[stub] = name
    return out


def func_bounds(b):
    """Return sorted list of (va, size, name) for defined functions."""
    fns = []
    for n, (va, sz, shndx, info) in b.syms.items():
        if va and sz:
            fns.append((va, sz, n))
    return sorted(fns)


def enclosing(fns, va):
    best = None
    for (v, sz, n) in fns:
        if v <= va < v + sz:
            if best is None or v > best[0]:
                best = (v, sz, n)
    return best


def annotate(b, ins, pm):
    lines = []
    for (addr, raw, mn, op) in ins:
        extra = ''
        if mn in ('bl', 'b', 'b.eq', 'b.ne', 'cbz', 'cbnz', 'tbz', 'tbnz'):
            try:
                tgt = int(op.split('#')[-1], 16)
            except Exception:
                tgt = None
            if tgt is not None:
                if tgt in pm:
                    extra = f'   ; PLT->{pm[tgt]}'
                else:
                    ns = b.nearest_sym(tgt)
                    if ns and ns[0] == tgt:
                        extra = f'   ; ->{ns[1]}'
        lines.append(f"{addr:08x}: {raw:<16} {mn:<8} {op}{extra}")
    return "\n".join(lines)
