#!/usr/bin/env python3
"""
Detailed Protocol Producer Analysis for UFSDxe, SdccDxe, and VerifiedBootDxe.
"""

from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = ROOT / "decompiled" / "dxe_modules"

GUIDS = {
    "EFI_MEM_CARDINFO_PROTOCOL": bytes.fromhex("d2f7c185e6bc314f8f4dd37e03d05eaa"),
    "SAMSUNG_VB_PROTOCOL": bytes.fromhex("91ff5e8eb621d347af2bc15a01e020ec"),
    "EFI_BLOCK_IO_PROTOCOL": bytes.fromhex("215b4e965964d2118e3900a0c969723b"),
    "EFI_SIMPLE_FILE_SYSTEM": bytes.fromhex("225b4e965964d2118e3900a0c969723b"),
}

TARGET_PE_FILES = {
    "UFSDxe": MODULES_DIR / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi",
    "VerifiedBootDxe": MODULES_DIR / "DXE_FV_MAIN_fd975fb5-92c3-40b3-b05c-9c434326ab64.efi",
    "SdccDxe": MODULES_DIR / "DXE_FV_AUX_f10f76db-42c1-533f-34a8-69be24653110.efi",
}

def analyze_pe(name: str, pe_path: Path):
    print(f"\n=======================================================")
    print(f"ANALYSIS OF {name}: {pe_path.name}")
    print(f"=======================================================")
    if not pe_path.exists():
        print("File does not exist!")
        return

    data = pe_path.read_bytes()
    print(f"File size: 0x{len(data):x} ({len(data)} bytes)")

    # Check GUID offsets
    for gname, gbytes in GUIDS.items():
        idx = 0
        matches = []
        while True:
            pos = data.find(gbytes, idx)
            if pos == -1:
                break
            matches.append(pos)
            idx = pos + 1
        print(f"GUID {gname}: {len(matches)} match(es) at offsets: {[hex(p) for p in matches]}")

    # Check interesting strings
    strs = re.findall(b'[\x20-\x7e]{4,}', data)
    print(f"\nInteresting Strings in {name}:")
    for s in strs:
        st = s.decode('latin1')
        if any(k in st.lower() for k in ["protocol", "install", "memcard", "cardinfo", "blockio", "vbrw", "devinfo", "lun", "ufs", "status", "error", "fail", "failed", "devicepath", "handle"]):
            if len(st) < 120:
                print("  ", st)

def main():
    for name, path in TARGET_PE_FILES.items():
        analyze_pe(name, path)

if __name__ == "__main__":
    main()
