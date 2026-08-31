#!/usr/bin/env python3
"""Deterministic aarch64 ELF/PE/Raw disassembly helper for offline audit.

Read-only. No patching. Produces RVA-based disassembly so reports are
reproducible by RVA/VA/file-offset.

RVA notation:
  VA  = runtime virtual address (within the module's load base)
  RVA = VA - module load base (0 for these ELF PIE images since base=0)
  FO  = file offset
We map RVA->FO via PT_LOAD segments.
"""
import sys
import struct
import argparse

try:
    import capstone
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM
except Exception as e:  # pragma: no cover
    print("capstone unavailable:", e, file=sys.stderr)
    sys.exit(2)


def load_elf_segments(data):
    """Return list of (vaddr, fo, filesz, memsz, flags)."""
    endian = '<' if data[5] == 1 else '>'
    assert data[:4] == b'\x7fELF'
    e_phoff = struct.unpack(endian + 'Q', data[0x20:0x28])[0]
    e_phentsize = struct.unpack(endian + 'H', data[0x36:0x38])[0]
    e_phnum = struct.unpack(endian + 'H', data[0x38:0x3a])[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
            struct.unpack(endian + 'IIQQQQQQ', data[off:off + 56])
        segs.append((p_type, p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
    return segs


def load_pe_sections(data):
    """Minimal PE section map (RVA->FO). Returns list of (vaddr,rva,fo,vsize)."""
    segs = []
    if data[:2] != b'MZ':
        return segs
    e_lfanew = struct.unpack('<I', data[0x3c:0x40])[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return segs
    # COFF header at e_lfanew+4, optional header follows
    (magic,) = struct.unpack('<H', data[e_lfanew + 24:e_lfanew + 26])
    if magic == 0x20b:  # PE32+
        nt_hdr = e_lfanew + 4
        num_sections = struct.unpack('<H', data[nt_hdr + 6:nt_hdr + 8])[0]
        opt_size = struct.unpack('<H', data[nt_hdr + 20:nt_hdr + 22])[0]
        sec_start = nt_hdr + 24 + opt_size
        for i in range(num_sections):
            so = sec_start + i * 40
            name = data[so:so + 8]
            vsize, rva, rawsize, rawoff = struct.unpack('<IIII', data[so + 8:so + 24])
            segs.append((name, rva, rawoff, rawsize))
    return segs


def rva_to_fo(segs, rva):
    """Map RVA to file offset using segment list (ELF PT_LOAD style)."""
    for s in segs:
        if len(s) == 6:  # ELF seg
            p_type, p_vaddr, p_offset, p_filesz, p_memsz, p_flags = s
            if p_type != 1:
                continue
            if p_vaddr <= rva < p_vaddr + p_filesz:
                return p_offset + (rva - p_vaddr)
        else:  # PE section
            name, rva0, fo, rawsize = s
            if rva0 <= rva < rva0 + rawsize:
                return fo + (rva - rva0)
    return None


def fo_to_rva(segs, fo):
    for s in segs:
        if len(s) == 6:
            p_type, p_vaddr, p_offset, p_filesz, p_memsz, p_flags = s
            if p_type != 1:
                continue
            if p_offset <= fo < p_offset + p_filesz:
                return p_vaddr + (fo - p_offset)
        else:
            name, rva0, fo0, rawsize = s
            if fo0 <= fo < fo0 + rawsize:
                return rva0 + (fo - fo0)
    return None


def disasm_range(data, segs, start_rva, end_rva, base=0):
    """Disassemble [start_rva,end_rva) into list of (rva, size, mnemonic, op_str)."""
    md = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    out = []
    rva = start_rva
    while rva < end_rva:
        fo = rva_to_fo(segs, rva)
        if fo is None:
            break
        chunk = data[fo:fo + (end_rva - rva)]
        if not chunk:
            break
        count = 0
        for ins in md.disasm(chunk, base + rva):
            out.append((ins.address - base, ins.size, ins.mnemonic, ins.op_str))
            count += 1
            if ins.address - base >= end_rva - 4:
                break
        if count == 0:
            break
        rva = out[-1][0] + out[-1][1]
    return out


def format_insns(insns, base=0):
    lines = []
    for rva, size, mn, op in insns:
        lines.append(f"  {rva:#08x}:  {mn} {op}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--rva", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--len", type=lambda x: int(x, 0), default=0x200)
    ap.add_argument("--base", type=lambda x: int(x, 0), default=0)
    args = ap.parse_args()
    data = open(args.image, 'rb').read()
    segs = load_elf_segments(data)
    if not segs or all(s[0] != 1 for s in segs):
        segs = load_pe_sections(data)
    insns = disasm_range(data, segs, args.rva, args.rva + args.len, args.base)
    print(f"# {args.image} RVA {args.rva:#x}..{args.rva + args.len:#x}")
    print(format_insns(insns, args.base))


if __name__ == "__main__":
    main()
