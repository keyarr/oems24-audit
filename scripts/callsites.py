"""Generic call-site finder: scan .text of an ELF for BL/B to a set of target
PLT stubs or direct addresses, and report enclosing function."""
import sys, struct, re
sys.path.insert(0, 'scripts')
from elftools_helpers import Bin
from pltmap import func_bounds, enclosing


def text_span(b):
    for s in b.f.iter_sections():
        if s.name == '.text':
            return s.header.sh_addr, s.header.sh_size, s.header.sh_offset
    return None


def plt_stubs(b):
    plt = rela = None
    for s in b.f.iter_sections():
        if s.name == '.plt':
            plt = s.header
        if s.name == '.rela.plt':
            rela = s
    out = {}
    if not rela:
        return out
    symtab = b.f.get_section(rela.header.sh_link)
    n = rela.header.sh_size // 24
    for i in range(n):
        o, info, add = struct.unpack_from('<QQq', b.data, rela.header.sh_offset + 24 * i)
        out[plt.sh_addr + 0x18 + 8 + 0x18 * i] = symtab.get_symbol(info >> 32).name
    return out


def find_sites(b, pred):
    """pred(name)->bool over PLT stub names and direct symbol VAs."""
    stubs = plt_stubs(b)
    targets = {va: nm for va, nm in stubs.items() if pred(nm)}
    for nm, (va, sz, sh, info) in b.syms.items():
        if va and pred(nm):
            targets[va] = nm
    a, sz, o = text_span(b)
    words = struct.unpack_from('<%dI' % (sz // 4), b.data, o)
    fns = func_bounds(b)
    sites = []
    for i, w in enumerate(words):
        kind = None
        if (w >> 26) == 0b100101:
            kind = 'bl'
        elif (w >> 26) == 0b000101:
            kind = 'b'
        else:
            continue
        imm = w & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        tgt = a + 4 * i + 4 * imm
        if tgt in targets:
            at = a + 4 * i
            enc = enclosing(fns, at)
            sites.append((at, kind, targets[tgt], enc[2] if enc else '?'))
    return sites
