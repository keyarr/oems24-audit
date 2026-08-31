#!/usr/bin/env python3
"""
Correctly calculate ADRP PC-relative target addresses in UFSDxe.
"""

from pathlib import Path
import struct
import capstone

ROOT = Path(__file__).resolve().parent.parent
pe_path = ROOT / "decompiled" / "dxe_modules" / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi"
data = pe_path.read_bytes()

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

text_data = data[0x1000:0x21000]
insns = list(md.disasm(text_data, 0x1000))

print("Scanning for ADRP targets pointing to 0x21000..0x22000 (.data):")
for i, insn in enumerate(insns):
    if insn.mnemonic == 'adrp':
        # parse target address
        target_str = insn.op_str.split(',')[-1].strip().lstrip('#')
        target_addr = int(target_str, 16)
        if 0x21000 <= target_addr <= 0x24000:
            reg = insn.op_str.split(',')[0].strip()
            # check next 5 instructions
            for j in range(i+1, min(len(insns), i+6)):
                next_insn = insns[j]
                if reg in next_insn.op_str:
                    print(f"  0x{insn.address:06x}: {insn.mnemonic:<6s} {insn.op_str:<20s}  -->  0x{next_insn.address:06x}: {next_insn.mnemonic:<6s} {next_insn.op_str}")
                    break
