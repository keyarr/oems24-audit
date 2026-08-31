"""Read-only disasm helper for the audited LinuxLoader PE.

RVA == file offset (imagebase=0, no relocations, raw sizes match virtual sizes).
Uses capstone for aarch64. Strictly read-only: no file mutation, no follow calls.
"""
import sys
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


def disasm_at(pe_path, rva, size=0x200):
    with open(pe_path, "rb") as f:
        f.seek(rva)
        code = f.read(size)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    out = []
    for ins in md.disasm(code, rva):
        out.append(f"  0x{ins.address:06x}  {ins.mnemonic:8s} {ins.op_str}")
    return out


def read_at(pe_path, rva, size):
    with open(pe_path, "rb") as f:
        f.seek(rva)
        return f.read(size)


def read_string(pe_path, rva, max_len=256):
    b = read_at(pe_path, rva, max_len)
    nul = b.find(b"\x00")
    if nul >= 0:
        b = b[:nul]
    return b


def read_u32(pe_path, rva):
    return struct.unpack("<I", read_at(pe_path, rva, 4))[0]


def read_u64(pe_path, rva):
    return struct.unpack("<Q", read_at(pe_path, rva, 8))[0]


def main():
    if len(sys.argv) < 3:
        print("usage: pe_disasm.py <rva> <size>")
        return 2
    rva = int(sys.argv[1], 0)
    size = int(sys.argv[2], 0)
    pe = "decompiled/linuxloader-oneui8.pe"
    for line in disasm_at(pe, rva, size):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
