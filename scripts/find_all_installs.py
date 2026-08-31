#!/usr/bin/env python3
"""
Trace all callers and protocol installation sites in UFSDxe (0x3dc4..0x5000).
"""

from pathlib import Path
import struct
import capstone

ROOT = Path(__file__).resolve().parent.parent
pe_path = ROOT / "decompiled" / "dxe_modules" / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi"
data = pe_path.read_bytes()

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

# Search all occurrences of InstallMultipleProtocolInterfaces (gBS+0x148) or InstallProtocolInterface (gBS+0x80) across the entire text section
text_data = data[0x1000:0x21000]

print("Scanning for all gBS protocol installation calls across UFSDxe:")
insns = list(md.disasm(text_data, 0x1000))
for i, insn in enumerate(insns):
    # check for InstallMultipleProtocolInterfaces / InstallProtocolInterface call pattern
    if insn.mnemonic == 'ldr' and ('#0x148' in insn.op_str or '#0x80' in insn.op_str):
        # find matching blr
        for j in range(i+1, min(len(insns), i+6)):
            if insns[j].mnemonic == 'blr':
                print(f"\n[PROTOCOL INSTALL CALL] at 0x{insns[j].address:x} (via {insn.op_str}):")
                start_k = max(0, i - 12)
                end_k = min(len(insns), j + 6)
                for k in range(start_k, end_k):
                    marker = "=>" if k in (i, j) else "  "
                    print(f"  {marker} 0x{insns[k].address:08x}: {insns[k].mnemonic:<10s} {insns[k].op_str}")
                break
