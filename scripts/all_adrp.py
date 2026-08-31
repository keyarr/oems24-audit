#!/usr/bin/env python3
"""
Print ALL ADRP instructions in UFSDxe text section.
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

adrp_targets = set()
for insn in insns:
    if insn.mnemonic == 'adrp':
        target = insn.op_str.split(',')[-1].strip()
        adrp_targets.add(target)

print("Unique ADRP targets in UFSDxe:")
for t in sorted(adrp_targets):
    print(" ", t)
