"""Full annotated disassembly of libengmode_tlc.so, using the authoritative
APS2-resolved GOT map (decompiled/tlc-got-map.txt)."""
import sys, struct, re
sys.path.insert(0, 'scripts')
from elftools_helpers import Bin, fmt
from pltmap import plt_map

B = Bin('binaries/libengmode_tlc.so')
PM = plt_map(B)

# GOT slot -> symbol
GOT = {}
for line in open('decompiled/tlc-got-map.txt'):
    if line.startswith('#'):
        continue
    p = line.split('\t')
    GOT[int(p[0], 16)] = (p[1], int(p[2], 16), int(p[3]))

# section->(addr,size)
SECS = [(s.header.sh_addr, s.header.sh_size, s.name) for s in B.f.iter_sections()]


def attr(va):
    for (a, sz, n) in SECS:
        if a <= va < a + sz:
            return n, va - a
    return '?', None


def str_at(va):
    o = B.v2o(va)
    if o is None:
        return None
    e = B.data.index(b'\x00', o)
    try:
        return B.data[o:e].decode('latin1')
    except Exception:
        return None


def ro_strings():
    """(va, text) for printable runs in .rodata"""
    out = []
    for (a, sz, n) in SECS:
        if n != '.rodata':
            continue
        o = B.v2o(a)
        for m in re.finditer(rb'[ -~]{4,}\x00', B.data[o:o + sz]):
            out.append((a + m.start(), m.group()[:-1].decode('latin1')))
    return out


RO = ro_strings()


def ro_near(va, span=0x40):
    return [(v, t) for (v, t) in RO if abs(v - va) <= span]


def annotate(va, size, title):
    print('=' * 100)
    print(f'### {title}   VA={va:#x} size={size}')
    print('=' * 100)
    ins = B.dis(va, size)
    # pre-pass: track adrp results
    reg_page = {}
    for (addr, raw, mn, op) in ins:
        line = f'{addr:06x}: {raw:<10} {mn:<7} {op}'
        note = []
        # PLT call
        if mn in ('bl', 'b'):
            try:
                t = int(op.split('#')[-1], 16)
            except Exception:
                t = None
            if t in PM:
                note.append(f'PLT->{PM[t]}')
        # adrp
        if mn == 'adrp':
            m = re.match(r'([wx]\d+), #(0x[0-9a-f]+)', op)
            if m:
                reg_page[m.group(1)] = int(m.group(2), 16)
        # ldr/str with [reg, #imm] where reg has a known page
        m = re.match(r'([wx]\d+), \[([wx]\d+)(?:, #(0x[0-9a-f]+))?\]', op)
        if m and m.group(2) in reg_page:
            tgt = reg_page[m.group(2)] + (int(m.group(3), 16) if m.group(3) else 0)
            if tgt in GOT:
                nm, bv, sz2 = GOT[tgt]
                note.append(f'GOT[{tgt:#x}]=&{nm} (bss 0x{bv:04x})')
            elif tgt in PM:
                note.append(f'GOTPLT->{PM[tgt]}')
            else:
                s = str_at(tgt)
                sec, off = attr(tgt)
                if s:
                    note.append(f'{sec}+{off:#x} = "{s}"')
                elif sec != '?':
                    note.append(f'{sec}+{off:#x}')
        # add reg, reg, #imm building a literal address
        m = re.match(r'([wx]\d+), ([wx]\d+), #(0x[0-9a-f]+)', op)
        if m and m.group(2) in reg_page:
            tgt = reg_page[m.group(2)] + int(m.group(3), 16)
            s = str_at(tgt)
            if s:
                note.append(f'= "{s}"')
        # immediate constants worth flagging
        for imm in re.findall(r'#(0x[0-9a-f]{3,})', op):
            v = int(imm, 16)
            if v in (0x10000, 0x11000, 0x21c7d, 0x20936, 0x2c00, 0x1000, 0x40, 0x80):
                note.append(f'imm {imm} = {v}')
        if note:
            line += '    ; ' + ', '.join(note)
        print(line)


if __name__ == '__main__':
    print('### .rodata strings')
    for (v, t) in RO:
        print(f'  0x{v:04x}: "{t}"')
    print()
    for nm in ('_Z26em_tlc_thr_cleanup_handlerPv', '_Z21em_tlc_suicide_threadi', 'em_tlc_send'):
        va, sz = B.syms[nm][0], B.syms[nm][1]
        annotate(va, sz, nm)
        print()
