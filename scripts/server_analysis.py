"""Annotated disassembly helper for libengmode_server.so (and friends)."""
import sys, struct, re
sys.path.insert(0, 'scripts')
from elftools_helpers import Bin
from pltmap import plt_map

CACHE = {}


def load(name):
    if name not in CACHE:
        b = Bin(f'binaries/{name}')
        CACHE[name] = (b, plt_map(b))
    return CACHE[name]


SECCACHE = {}


def secs(b):
    if b.path not in SECCACHE:
        SECCACHE[b.path] = [(s.header.sh_addr, s.header.sh_size, s.name) for s in b.f.iter_sections()]
    return SECCACHE[b.path]


def attr(b, va):
    for (a, sz, n) in secs(b):
        if a <= va < a + sz:
            return n, va - a
    return '?', None


def str_at(b, va):
    o = b.v2o(va)
    if o is None:
        return None
    try:
        e = b.data.index(b'\x00', o)
    except ValueError:
        return None
    try:
        return b.data[o:e].decode('latin1')
    except Exception:
        return None


BIG = {0x10000, 0x11000, 0x21c7d, 0x20936, 0x2c00, 0x1000, 0x40, 0x80, 0x1ad,
       0x11611, 0x1f07d, 0xc801, 0x14136, 0x14132, 0x517, 0x19, 0x132, 0x200}


def annotate(b, va, size, title=None, pm=None):
    if pm is None:
        pm = plt_map(b)
    print('=' * 104)
    print(f'### {title or b.nearest_sym(va)}   VA={va:#x}+{size:#x}')
    print('=' * 104)
    reg_page = {}
    reg_val = {}
    for (addr, raw, mn, op) in b.dis(va, size):
        note = []
        if mn in ('bl', 'b'):
            try:
                t = int(op.split('#')[-1], 16)
            except Exception:
                t = None
            if t in pm:
                note.append(f'PLT->{pm[t]}')
            else:
                ns = b.nearest_sym(t)
                if ns and ns[0] == t:
                    note.append(f'->{ns[1]}')
        if mn == 'adrp':
            m = re.match(r'([wx]\d+), #(0x[0-9a-f]+)', op)
            if m:
                reg_page[m.group(1)] = int(m.group(2), 16)
                reg_val.pop(m.group(1), None)
        m = re.match(r'([wx]\d+), \[([wx]\d+)(?:, #(0x[0-9a-f]+))?\]', op)
        if m and m.group(2) in reg_page:
            tgt = reg_page[m.group(2)] + (int(m.group(3), 16) if m.group(3) else 0)
            s = str_at(b, tgt)
            sec, off = attr(b, tgt)
            if s and len(s) >= 3:
                note.append(f'[{sec}+{off:#x}] "{s}"')
            elif sec != '?':
                note.append(f'[{sec}+{off:#x}]')
        m = re.match(r'([wx]\d+), ([wx]\d+), #(0x[0-9a-f]+)', op)
        if m and m.group(2) in reg_page:
            tgt = reg_page[m.group(2)] + int(m.group(3), 16)
            s = str_at(b, tgt)
            if s and len(s) >= 3:
                note.append(f'"{s}"')
        # mov/movk immediate accumulation for 32-bit constants
        m = re.match(r'(w\d+), #(0x[0-9a-f]+)', op)
        if mn == 'mov' and m:
            reg_val[m.group(1)] = int(m.group(2), 16)
        m2 = re.match(r'(w\d+), #(0x[0-9a-f]+), lsl #16', op)
        if mn == 'movk' and m2:
            v = reg_val.get(m2.group(1), 0) | (int(m2.group(2), 16) << 16)
            reg_val[m2.group(1)] = v
            note.append(f'{m2.group(1)} = 0x{v:x} ({v})')
        for imm in re.findall(r'#(0x[0-9a-f]{3,})\b', op):
            if int(imm, 16) in BIG:
                note.append(f'{imm}={int(imm,16)}')
        line = f'{addr:06x}: {raw:<10} {mn:<7} {op}'
        if note:
            line += '    ; ' + ', '.join(note)
        print(line)
