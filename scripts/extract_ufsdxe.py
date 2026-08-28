#!/usr/bin/env python3
"""
Read-only extraction of the UFSDxe.efi PE image from the
decompressed DXE Core FV.

The DXE Core FV is a Samsung/Qualcomm custom container where:
  - 63 PE/COFF headers (MZ+PE) are spaced 0x7000 apart
  - Each PE has the same .text stub but unique .data/.reloc
  - .debug sections (PDB paths) are interleaved

The UFSDxe.efi PE is identified by searching the .data
section of each PE for the "UFSDxe.dll" PDB path string.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FV = ROOT / "decompiled_extra" / "dxe_core_fv.bin"
OUT = ROOT / "decompiled_extra" / "ufsdxe_efi_extracted.pe"

EXPECTED_HASHES = {
    "decompiled_extra/dxe_core_fv.bin":
        "b805f343a58b906624528dd9d13504f8371996db8c9d18166cd7316ee6f8e929",
    "decompiled_extra/ufsdxe_efi_extracted.pe":
        "e3bc6c784aaa40c1350718c526fd12fb6849ce8d10d1eebb2dbea8ce454ab2a8",
}

UFSDXE_PDB = b"UFSDxe.dll"
PE_SPACING = 0x7000


def find_ufsdxe_pe(fv: bytes) -> tuple[int, int] | None:
    """Walk the FV looking for the UFSDxe.efi PE."""
    import re
    for mz_match in re.finditer(b"MZ", fv):
        mz = mz_match.start()
        if mz + 0x40 > len(fv):
            continue
        pe_off = int.from_bytes(fv[mz + 0x3C:mz + 0x40], "little")
        if not (0x40 <= pe_off <= 0x1000):
            continue
        if mz + pe_off + 4 > len(fv):
            continue
        if fv[mz + pe_off:mz + pe_off + 4] != b"PE\x00\x00":
            continue
        machine = int.from_bytes(fv[mz + pe_off + 4:mz + pe_off + 6], "little")
        if machine != 0xAA64:
            continue

        opt_off = mz + pe_off + 0x18
        if opt_off + 0xF0 > len(fv):
            continue
        opt_magic = int.from_bytes(fv[opt_off:opt_off + 2], "little")
        if opt_magic != 0x20B:
            continue

        num_sec = int.from_bytes(fv[mz + pe_off + 6:mz + pe_off + 8], "little")
        opt_size = int.from_bytes(fv[mz + pe_off + 0x14:mz + pe_off + 0x16], "little")
        sec_table = mz + pe_off + 0x18 + opt_size

        for i in range(num_sec):
            sec_off = sec_table + i * 40
            if sec_off + 40 > len(fv):
                break
            sec_name = fv[sec_off:sec_off + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
            if sec_name != ".data":
                continue
            raw_ptr = int.from_bytes(fv[sec_off + 0x14:sec_off + 0x18], "little")
            raw_size = int.from_bytes(fv[sec_off + 0x10:sec_off + 0x14], "little")
            data_off = mz + raw_ptr
            if data_off + raw_size > len(fv):
                continue
            data = fv[data_off : data_off + raw_size]
            if UFSDXE_PDB in data:
                return mz, pe_off
    return None


def extract_ufsdxe(fv: bytes, mz: int, pe_off: int) -> bytes:
    """Reconstruct the UFSDxe.efi PE from the FV."""
    opt_off = mz + pe_off + 0x18
    opt_size = int.from_bytes(fv[mz + pe_off + 0x14:mz + pe_off + 0x16], "little")
    num_sec = int.from_bytes(fv[mz + pe_off + 6:mz + pe_off + 8], "little")
    sec_table = mz + pe_off + 0x18 + opt_size

    sections = []
    max_raw_end = 0
    for i in range(num_sec):
        sec_off = sec_table + i * 40
        if sec_off + 40 > len(fv):
            break
        name = fv[sec_off:sec_off + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
        virt_size = int.from_bytes(fv[sec_off + 8:sec_off + 0xC], "little")
        virt_addr = int.from_bytes(fv[sec_off + 0xC:sec_off + 0x10], "little")
        raw_size = int.from_bytes(fv[sec_off + 0x10:sec_off + 0x14], "little")
        raw_ptr = int.from_bytes(fv[sec_off + 0x14:sec_off + 0x18], "little")
        sections.append((name, virt_addr, virt_size, raw_ptr, raw_size))
        if raw_ptr + raw_size > max_raw_end:
            max_raw_end = raw_ptr + raw_size

    pe = bytearray(max_raw_end)
    for name, va, vs, rp, rs in sections:
        if rp + rs > len(fv) - mz:
            continue
        pe[rp:rp + rs] = fv[mz + rp:mz + rp + rs]
    return bytes(pe)


def main() -> int:
    print("Verifying inputs...")
    for rel, expected in EXPECTED_HASHES.items():
        path = ROOT / rel
        if not path.exists():
            print(f"  MISSING: {rel}")
            return 1
        # For the output file, we may need to regenerate it, so skip hash check
        if rel.endswith("ufsdxe_efi_extracted.pe"):
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            print(f"  HASH MISMATCH: {rel}")
            print(f"    expected {expected}")
            print(f"    actual   {actual}")
            return 1
        print(f"  OK: {rel}")

    fv = FV.read_bytes()
    print(f"\nSearching for UFSDxe.efi in {FV.name}...")
    result = find_ufsdxe_pe(fv)
    if result is None:
        print("  UFSDxe.efi NOT FOUND")
        return 1
    mz, pe_off = result
    print(f"  Found at MZ=0x{mz:x} (PE at +0x{pe_off:x})")

    pe = extract_ufsdxe(fv, mz, pe_off)
    actual = hashlib.sha256(pe).hexdigest()
    print(f"  Extracted {len(pe)} bytes")
    print(f"  SHA256: {actual}")

    expected = EXPECTED_HASHES["decompiled_extra/ufsdxe_efi_extracted.pe"]
    if actual != expected:
        print(f"  HASH MISMATCH (expected {expected})")
        return 1

    OUT.write_bytes(pe)
    print(f"  Saved: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
