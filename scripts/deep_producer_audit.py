#!/usr/bin/env python3
"""
Deep reverse engineering of protocol installation in UFSDxe, VerifiedBootDxe, and PartitionDxe.
"""

from pathlib import Path
import struct
import capstone

ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = ROOT / "decompiled" / "dxe_modules"

def analyze_verified_boot_dxe():
    pe_path = MODULES_DIR / "DXE_FV_MAIN_fd975fb5-92c3-40b3-b05c-9c434326ab64.efi"
    data = pe_path.read_bytes()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    print("=================================================================")
    print("VERIFIEDBOOTDXE DETAILED PROTOCOL PRODUCER AUDIT")
    print("=================================================================")

    # Entry point of VerifiedBootDxe
    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    entry_rva = struct.unpack_from('<I', data, e_lfanew + 40)[0]
    print(f"VerifiedBootDxe Entry Point: 0x{entry_rva:x}")

    # Let's inspect function at 0x283c where Samsung VB protocol is installed:
    # At 0x284c: ADRP x1, #0xd000; ADD x1, x1, #0xb8 (Samsung VB GUID)
    # 0x2850: ADRP x2, #0xd000; ADD x2, x2, #0x180 (Interface pointer table)
    # 0x285c: ADD x0, sp, #8 (Handle pointer)
    # 0x2860: LDR x8, [x8, #0x370] (gBS)
    # 0x286c: LDR x8, [x8, #0x148] (InstallMultipleProtocolInterfaces)
    # 0x2870: BLR x8

    print("\nSamsung VB Protocol Installer function at 0x283c:")
    chunk = data[0x283c : 0x283c + 0x60]
    for insn in md.disasm(chunk, 0x283c):
        print(f"  0x{insn.address:08x}: {insn.mnemonic:<10s} {insn.op_str}")

    # Let's inspect what is in the interface table at RVA 0xd180:
    print(f"\nInterface table at RVA 0xd180:")
    for i in range(8):
        ptr = struct.unpack_from('<Q', data, 0xd180 + i * 8)[0]
        print(f"  Interface[{i}]: 0x{ptr:x}")

    # Who calls 0x283c?
    print("\nSearching callers of 0x283c:")
    text_data = data[0x1000:0xd000]
    for insn in md.disasm(text_data, 0x1000):
        if insn.mnemonic in ('bl', 'b') and '0x283c' in insn.op_str:
            print(f"  Call at 0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")

def analyze_ufsdxe_protocol_install():
    pe_path = MODULES_DIR / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi"
    data = pe_path.read_bytes()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    print("\n=================================================================")
    print("UFSDXE DETAILED PROTOCOL PRODUCER AUDIT")
    print("=================================================================")

    # Find where 0x3dc4 (called from main init 0x1204) goes
    print("\nDisassembling 0x3dc4 (UFSDxe Device/Protocol Init):")
    chunk = data[0x3dc4 : 0x3dc4 + 0x200]
    for insn in md.disasm(chunk, 0x3dc4):
        print(f"  0x{insn.address:08x}: {insn.mnemonic:<10s} {insn.op_str}")

def main():
    analyze_verified_boot_dxe()
    analyze_ufsdxe_protocol_install()

if __name__ == "__main__":
    main()
