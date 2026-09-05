#!/usr/bin/env python3
"""
DXE Firmware Volume Provenance and Protocol Producer Analysis Script
Deterministic analysis for Qualcomm / Samsung S928B (Snapdragon 8 Gen 3) UEFI DXE environment.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import struct
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Protocol GUIDs in raw EFI mixed-endian format
GUIDS = {
    "EFI_MEM_CARDINFO_PROTOCOL": bytes.fromhex("d2f7c185e6bc314f8f4dd37e03d05eaa"),  # 85c1f7d2-bce6-4f31-8f4d-d37e03d05eaa
    "SAMSUNG_VB_PROTOCOL": bytes.fromhex("91ff5e8eb621d347af2bc15a01e020ec"),        # 8e5eff91-21b6-47d3-af2b-c15a01e020ec
    "EFI_BLOCK_IO_PROTOCOL": bytes.fromhex("215b4e965964d2118e3900a0c969723b"),      # 964e5b21-6459-11d2-8e39-00a0c969723b
    "EFI_SIMPLE_FILE_SYSTEM": bytes.fromhex("225b4e965964d2118e3900a0c969723b"),     # 964e5b22-6459-11d2-8e39-00a0c969723b
    "EFI_LOADED_IMAGE_PROTOCOL": bytes.fromhex("a1311b5b6295d2118e3f00a0c969723b"), # 5b1b31a1-9562-11d2-8e3f-00a0c969723b
    "EFI_DEVICE_PATH_PROTOCOL": bytes.fromhex("916e57093f6dd2118e3900a0c969723b"),  # 09576e91-6d3f-11d2-8e39-00a0c969723b
    "LZMA_CUSTOM_DECOMPRESS": bytes.fromhex("e91f301d79be534391c2d23bc959ae0c"),    # 1d301fe9-be79-4353-91c2-d23bc959ae0c (GZIP in QC)
}

def parse_fv(fv_bytes: bytes, fv_name: str = "FV") -> list[dict]:
    """Parse a PI Firmware Volume and return list of FFS files."""
    if len(fv_bytes) < 0x48:
        return []

    # Check _FVH signature at offset 0x28 (40)
    if fv_bytes[40:44] != b'_FVH':
        return []

    hdr_len = struct.unpack_from('<H', fv_bytes, 48)[0]
    offset = hdr_len
    files = []

    while offset <= len(fv_bytes) - 24:
        # Align to 8 bytes
        offset = (offset + 7) & ~7
        if offset + 24 > len(fv_bytes):
            break

        name_bytes = fv_bytes[offset:offset+16]
        if name_bytes == b'\xff' * 16:
            # Free space
            # Skip till non-FF
            while offset < len(fv_bytes) and fv_bytes[offset:offset+8] == b'\xff' * 8:
                offset += 8
            continue

        integ, ftype, fattr = struct.unpack_from('<HBB', fv_bytes, offset+16)
        size_bytes = fv_bytes[offset+20:offset+23]
        fsize = size_bytes[0] | (size_bytes[1] << 8) | (size_bytes[2] << 16)
        state = fv_bytes[offset+23]

        if fsize < 24 or offset + fsize > len(fv_bytes):
            # Invalid or corrupt FFS
            break

        guid_str = str(uuid.UUID(bytes_le=name_bytes))

        # Parse sections within FFS
        sec_off = offset + 24
        ui_name = ""
        pe_payload = b""
        sections = []

        while sec_off + 4 <= offset + fsize:
            sec_len_bytes = fv_bytes[sec_off:sec_off+3]
            sec_len = sec_len_bytes[0] | (sec_len_bytes[1] << 8) | (sec_len_bytes[2] << 16)
            sec_type = fv_bytes[sec_off+3]

            if sec_len < 4 or sec_off + sec_len > offset + fsize:
                break

            sec_data = fv_bytes[sec_off:sec_off+sec_len]
            sections.append({
                "type": sec_type,
                "size": sec_len,
                "offset": sec_off
            })

            if sec_type == 0x14:  # UI
                try:
                    ui_name = sec_data[4:].decode('utf-16le').rstrip('\x00')
                except Exception:
                    pass
            elif sec_type in (0x10, 0x11, 0x12):  # PE32, PIC, TE
                pe_payload = sec_data[4:]

            sec_off = (sec_off + sec_len + 3) & ~3

        files.append({
            "fv": fv_name,
            "offset": offset,
            "size": fsize,
            "type": ftype,
            "state": state,
            "guid": guid_str,
            "ui_name": ui_name,
            "pe_size": len(pe_payload),
            "pe_bytes": pe_payload,
            "sections": sections
        })

        offset = (offset + fsize + 7) & ~7

    return files

def main():
    uefi_path = ROOT / "uefi.img"
    if not uefi_path.exists():
        uefi_path = ROOT / "uefioneui8.5.img"  # same dump, tree name
    if not uefi_path.exists():
        print("ERROR: uefi.img not found", file=sys.stderr)
        return 1

    uefi_data = uefi_path.read_bytes()
    uefi_hash = hashlib.sha256(uefi_data).hexdigest()
    print(f"uefi.img SHA-256: {uefi_hash}")

    # Outer FV at 0x1000..0x2f1000
    outer_fv = uefi_data[0x1000:0x2f1000]

    # FFS2 GZIP payload at file offset 0x51fb0 (0x50f98 + 0x18 in FV)
    payload2 = outer_fv[0x50f98+0x18:0x50f98+0x171269]
    dec2 = gzip.decompress(payload2)
    dec2_fv = dec2[8:]  # strip 8-byte container header

    # FFS3 GZIP payload at file offset 0x1c3238 (0x1c2220 + 0x18 in FV)
    payload3 = outer_fv[0x1c2220+0x18:0x1c2220+0x128b4d]
    dec3 = gzip.decompress(payload3)
    dec3_fv = dec3[8:]  # strip 8-byte container header

    print(f"Decompressed DXE FV 1 (DEC2): {len(dec2_fv)} bytes, hash={hashlib.sha256(dec2_fv).hexdigest()}")
    print(f"Decompressed DXE FV 2 (DEC3): {len(dec3_fv)} bytes, hash={hashlib.sha256(dec3_fv).hexdigest()}")

    files2 = parse_fv(dec2_fv, "DXE_FV_MAIN")
    files3 = parse_fv(dec3_fv, "DXE_FV_AUX")

    print(f"\nParsed {len(files2)} FFS modules in DXE_FV_MAIN")
    print(f"Parsed {len(files3)} FFS modules in DXE_FV_AUX")

    all_files = files2 + files3

    # Search for target modules
    print("\n=== Storage and Security Drivers in DXE FVs ===")
    for f in all_files:
        name = f["ui_name"] or f["guid"]
        # check GUID matches in pe_bytes
        guid_hits = {}
        for gname, gbytes in GUIDS.items():
            cnt = f["pe_bytes"].count(gbytes)
            if cnt > 0:
                guid_hits[gname] = cnt

        if any(k in name.lower() for k in ["ufs", "sdcc", "disk", "part", "mem", "card", "block", "vb", "sec", "devinfo", "fat"]) or guid_hits:
            print(f"[{f['fv']}] {name:<30s} GUID={f['guid']} PE_size=0x{f['pe_size']:x}")
            for gname, cnt in guid_hits.items():
                print(f"    -> {gname}: {cnt} hits")

if __name__ == "__main__":
    main()
