#!/usr/bin/env python3
"""
Inspect relocations and xrefs in UFSDxe for MemCardInfo and BlockIo.
"""

from pathlib import Path
import struct
import capstone

ROOT = Path(__file__).resolve().parent.parent
pe_path = ROOT / "decompiled" / "dxe_modules" / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi"
data = pe_path.read_bytes()

# Parse relocations (.reloc section)
e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
opt_hdr_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
sec_hdr_start = e_lfanew + 24 + opt_hdr_size

sections = []
for i in range(num_sections):
    s_name, s_vsize, s_vaddr, s_rawsize, s_rawoff, _, _, _, _, s_flags = struct.unpack_from('<8sIIIIIIHHI', data, sec_hdr_start + i * 40)
    s_name_str = s_name.decode('latin1').rstrip('\x00')
    sections.append({
        "name": s_name_str,
        "vaddr": s_vaddr,
        "vsize": s_vsize,
        "rawoff": s_rawoff,
        "rawsize": s_rawsize
    })

reloc_sec = next(s for s in sections if ".reloc" in s["name"])
reloc_data = data[reloc_sec["rawoff"] : reloc_sec["rawoff"] + reloc_sec["rawsize"]]

print(f".reloc section: 0x{reloc_sec['rawoff']:x}..0x{reloc_sec['rawoff']+reloc_sec['rawsize']:x}")

reloc_entries = []
off = 0
while off < len(reloc_data) - 8:
    page_rva, block_size = struct.unpack_from('<II', reloc_data, off)
    if block_size == 0 or off + block_size > len(reloc_data):
        break
    num_entries = (block_size - 8) // 2
    for j in range(num_entries):
        val = struct.unpack_from('<H', reloc_data, off + 8 + j * 2)[0]
        rtype = val >> 12
        rofs = val & 0xfff
        if rtype != 0:
            target_rva = page_rva + rofs
            reloc_entries.append((rtype, target_rva))
    off += block_size

print(f"Total base relocation entries: {len(reloc_entries)}")

# Search if any pointer in data or text references 0x21228 (MemCardInfo) or 0x211a8 (BlockIo)
print("\nScanning for pointers to 0x21228 (MemCardInfo) and 0x211a8 (BlockIo)...")
for offset in range(0, len(data) - 8, 8):
    val = struct.unpack_from('<Q', data, offset)[0]
    if val in (0x21228, 0x211a8, 0x212d8):
        print(f"  Pointer at file offset 0x{offset:x} (RVA 0x{offset:x}): points to 0x{val:x}")

# Let's also check all literal 32-bit and 64-bit occurrences
for offset in range(0, len(data) - 4, 4):
    val = struct.unpack_from('<I', data, offset)[0]
    if val in (0x21228, 0x211a8):
        print(f"  32-bit word at file offset 0x{offset:x}: 0x{val:x}")
