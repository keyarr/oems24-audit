#!/usr/bin/env python3
"""
Follow Entry Point jump to 0x1148 and disassemble main initialization logic of UFSDxe.
"""

from pathlib import Path
import struct
import capstone

ROOT = Path(__file__).resolve().parent.parent
pe_path = ROOT / "decompiled" / "dxe_modules" / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi"
data = pe_path.read_bytes()

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

# Disassemble 0x1148..0x1600
chunk = data[0x1148 : 0x1600]
print("\nDisassembly of 0x1148 (UFSDxe Main Init):")
for insn in md.disasm(chunk, 0x1148):
    print(f"  0x{insn.address:08x}: {insn.mnemonic:<10s} {insn.op_str}")
