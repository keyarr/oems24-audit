#!/usr/bin/env python3
"""
Scan .data and .text in UFSDxe for GUID references and disassemble functions.
"""

from pathlib import Path
import struct
import capstone

ROOT = Path(__file__).resolve().parent.parent
pe_path = ROOT / "decompiled" / "dxe_modules" / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi"
data = pe_path.read_bytes()

# Find occurrences of GUID bytes in data
g_memcard = bytes.fromhex("d2f7c185e6bc314f8f4dd37e03d05eaa")
g_blockio = bytes.fromhex("215b4e965964d2118e3900a0c969723b")

print(f"MemCardInfo bytes pos in file: 0x{data.find(g_memcard):x}")
print(f"BlockIo bytes pos in file: 0x{data.find(g_blockio):x}")

# Let's inspect bytes in .data around 0x21000..0x21400
print("\nHexdump .data around 0x21180..0x21300:")
for off in range(0x21180, 0x21300, 16):
    print(f"  0x{off:x}: {data[off:off+16].hex()}  {data[off:off+16]}")

# Let's disassemble the text section to find where InstallMultipleProtocolInterfaces or InstallProtocolInterface or LocateProtocol is called
# In UEFI, gBS pointers:
# InstallProtocolInterface: gBS + 0x80
# ReinstallProtocolInterface: gBS + 0x88
# UninstallProtocolInterface: gBS + 0x90
# HandleProtocol: gBS + 0x98
# RegisterProtocolNotify: gBS + 0xa0
# LocateHandle: gBS + 0xa8
# LocateDevicePath: gBS + 0xb0
# InstallMultipleProtocolInterfaces: gBS + 0x148
# UninstallMultipleProtocolInterfaces: gBS + 0x150
# LocateProtocol: gBS + 0x140

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
md.detail = True

text_data = data[0x1000:0x21000]
print("\nScanning text for calls to InstallProtocolInterface (gBS+0x80) or InstallMultipleProtocolInterfaces (gBS+0x148)...")

insns = list(md.disasm(text_data, 0x1000))
for i, insn in enumerate(insns):
    # check for ldr to register with offset 0x80 or 0x148 or 0x140
    if insn.mnemonic == 'ldr' and any(off in insn.op_str for off in ['#0x80', '#0x148', '#0x140', '#0x98', '#0x138']):
        # check if subsequent instruction is blr
        for j in range(i+1, min(len(insns), i+5)):
            if insns[j].mnemonic == 'blr':
                target_reg = insn.op_str.split(',')[0].strip()
                call_reg = insns[j].op_str.strip()
                if target_reg == call_reg:
                    print(f"\n[CALL] at 0x{insns[j].address:x} ({insn.op_str}):")
                    start_k = max(0, i - 8)
                    end_k = min(len(insns), j + 4)
                    for k in range(start_k, end_k):
                        marker = "=>" if k in (i, j) else "  "
                        print(f"  {marker} 0x{insns[k].address:08x}: {insns[k].mnemonic:<10s} {insns[k].op_str}")
                    break
