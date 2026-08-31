#!/usr/bin/env python3
"""
Examine how UFSDxe accesses gBS table and installs protocols.
"""

from pathlib import Path
import struct
import capstone

ROOT = Path(__file__).resolve().parent.parent
pe_path = ROOT / "decompiled" / "dxe_modules" / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi"
data = pe_path.read_bytes()

# Find entry point
e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
entry_rva = struct.unpack_from('<I', data, e_lfanew + 40)[0]
print(f"Entry point RVA: 0x{entry_rva:x}")

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

# Disassemble from entry point
entry_offset = entry_rva # rawoff == vaddr for .text (0x1000)
chunk = data[entry_offset : entry_offset + 0x400]
print("\nDisassembly of Entry Point (DriverEntryPoint):")
for insn in md.disasm(chunk, entry_rva):
    print(f"  0x{insn.address:08x}: {insn.mnemonic:<10s} {insn.op_str}")
