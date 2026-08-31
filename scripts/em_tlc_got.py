"""Resolve libengmode_tlc.so GOT slots from the APS2-packed .rela.dyn.

Empirically-validated stream layout (self-consistent: 9 relocs, offsets land on
the 9 GOT slots, addends 0, sym indices match .dynsym exactly):

    'APS2'
    group_size    sleb128   (9)
    reloc_count   sleb128   (0 -- unused by this encoder)
    <two header bytes>      (9, 8)
    then per relocation:  offset_delta(sleb)  r_info(sleb)  addend(sleb)

Also dumps .relr.dyn (covers .data.rel.ro + .fini_array).
"""
import sys, struct
sys.path.insert(0, 'scripts')
from elftools_helpers import Bin


def sleb128(data, pos):
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        shift += 7
        if (byte & 0x80) == 0:
            break
    if byte & 0x40:
        result -= (1 << shift)
    return result, pos


def dynsym_table(b):
    """Return list of (index, name, value, size, shndx)."""
    off = size = strt = None
    for s in b.f.iter_sections():
        if s.name == '.dynsym':
            off = s.header.sh_offset
            size = s.header.sh_size
            strt = b.f.get_section(s.header.sh_link).header.sh_offset
    d = b.data
    out = []
    for i in range(size // 0x18):
        o = off + 0x18 * i
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', d, o)
        n = d[strt + st_name:d.index(b'\x00', strt + st_name)].decode('latin1')
        out.append((i, n, st_value, st_size, st_shndx))
    return out


RTYPES = {0x401: 'R_AARCH64_GLOB_DAT', 0x403: 'R_AARCH64_RELATIVE', 0x101: 'R_AARCH64_ABS64'}


def aps2(b):
    sec = b.f.get_section_by_name('.rela.dyn')
    o = sec.header.sh_offset
    size = sec.header.sh_size
    d = b.data
    pos = o + 4
    group_size, pos = sleb128(d, pos)
    reloc_count, pos = sleb128(d, pos)
    hdr2_a, pos = sleb128(d, pos)
    hdr2_b, pos = sleb128(d, pos)
    end = o + size
    out = []
    acc = 0
    while pos < end:
        od, pos = sleb128(d, pos)
        acc += od
        info, pos = sleb128(d, pos)
        add, pos = sleb128(d, pos)
        out.append((acc, info & 0xffffffff, info >> 32, add))
    return group_size, reloc_count, hdr2_a, hdr2_b, out


def relr(b):
    sec = b.f.get_section_by_name('.relr.dyn')
    if sec is None:
        return []
    o, sz = sec.header.sh_offset, sec.header.sh_size
    d = b.data
    addrs = []
    base = None
    for i in range(sz // 8):
        e = struct.unpack_from('<Q', d, o + 8 * i)[0]
        if e & 1:
            bits = e >> 1
            k = 0
            while bits:
                if bits & 1:
                    addrs.append(base + 8 * (k + 1))
                bits >>= 1
                k += 1
        else:
            base = e
            addrs.append(base)
    return addrs


def main():
    b = Bin('binaries/libengmode_tlc.so')
    ds = dynsym_table(b)
    gs, rc, h1, h2, rels = aps2(b)
    print(f'APS2 header: group_size={gs} reloc_count={rc} extra=({h1},{h2})')
    print(f'decoded {len(rels)} relocations')
    print()
    print(f"{'GOT slot':<10} {'r_type':<22} {'sym':<32} {'sym VA':<10} {'addend'}")
    got = {}
    for (off, typ, sym, add) in rels:
        name, val, sz, shndx = ('', 0, 0, 0)
        if sym < len(ds):
            _, name, val, sz, shndx = ds[sym]
        print(f'  0x{off:<8x} {RTYPES.get(typ, hex(typ)):<22} {name:<32} 0x{val:<8x} {add}')
        got[off] = (name, val, sz, typ)
    print()
    print('=== .relr.dyn (relative relocs) ===')
    for a in relr(b):
        print(f'  0x{a:04x}')

    print()
    print('=== resolved GOT map (authoritative) ===')
    for off in sorted(got):
        name, val, sz, typ = got[off]
        print(f'  GOT[0x{off:04x}] -> {name:<32} (bss 0x{val:04x}, size {sz})')

    # write a machine readable map for the disassembler
    with open('decompiled/tlc-got-map.txt', 'w') as f:
        f.write('# GOT slot -> symbol (from APS2 .rela.dyn)\n')
        for off in sorted(got):
            name, val, sz, typ = got[off]
            f.write(f'0x{off:04x}\t{name}\t0x{val:04x}\t{sz}\n')
    print('\nwrote decompiled/tlc-got-map.txt')


if __name__ == '__main__':
    main()
