#!/usr/bin/env python3
"""
Find how UFSDxe installs BlockIo and MemCardInfo protocols.
Check all BL/BLR in 0x3dc4..0x5000 and all references to .data GUID table.
"""

from pathlib import Path
import struct
import capstone

ROOT = Path(__file__).resolve().parent.parent
pe_path = ROOT / "decompiled" / "dxe_modules" / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi"
data = pe_path.read_bytes()

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

# Search for all ADRP instructions that reference page 0x21000
text_data = data[0x1000:0x21000]
insns = list(md.disasm(text_data, 0x1000))

print("Scanning for ADRP to 0x21000 (.data):")
for i, insn in enumerate(insns):
    if insn.mnemonic == 'adrp' and '#0x21000' in insn.op_str:
        reg = insn.op_str.split(',')[0].strip()
        # Look for instructions using this reg in the next 5 instructions
        for j in range(i+1, min(len(insns), i+6)):
            next_insn = insns[j]
            if reg in next_insn.op_str and ('add' in next_insn.mnemonic or 'ldr' in next_insn.mnemonic):
                # extract offset
                print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str} -> 0x{next_insn.address:x}: {next_insn.mnemonic} {next_insn.op_str}")
