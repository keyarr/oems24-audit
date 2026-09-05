#!/usr/bin/env python3
"""
Read-only extraction of the DXE FVs embedded as gzip streams in the
Samsung/Qualcomm XBL Core (uefi.img).

The XBL Core binary on S928B OneUI8 contains TWO compressed EFI FVs
that are decompressed at boot and handed to DxeCore:
  - DXE Core FV (4.4 MB uncompressed, contains DxeCore.efi and ~30 early drivers)
  - UEFI Aux FV (3.4 MB uncompressed, contains ~70 later drivers including UFSDxe)

Each compressed blob has the layout:
    4 bytes: 0x04 0x00 0x00 0x19   (Samsung blob magic, fixed)
    4 bytes: uncompressed size in 0x10000 units, big-endian
    N bytes: gzip-compressed EFI_FIRMWARE_VOLUME (preceded by 16 zero_vector bytes)

The decompressed data begins with 8 bytes of Samsung header (alignment),
then the standard EFI_FV_HEADER with _FVH at offset 0x30 from the start of
the compressed stream.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# the XBL core dump lives at uefioneui8.5.img in this tree (sha256-identical
# to the uefi.img name older revisions used); accept either.
UEFI_IMG = ROOT / "uefi.img"
if not UEFI_IMG.exists():
    UEFI_IMG = ROOT / "uefioneui8.5.img"

# gzip streams at fixed offsets discovered by static analysis of uefi.img
GZIP_STREAMS = [
    ("dxe_core_fv", 0x51FB0, "DXE Core FV (contains DxeCore.efi + early drivers)"),
    ("uefi_aux_fv", 0x1C3238, "UEFI Aux FV (contains UFSDxe.efi + later drivers)"),
]

EXPECTED_HASHES = {
    "uefi.img": "7cb98e7804f76f27d0b9d5487a13d0cd7354c4ef4d4c6b7b5582befcc4eb727f",
    # Full decompressed data INCLUDING the Samsung 8-byte header.
    # The header is 0x04 0x00 0x00 0x19 <uncompressed_size_in_0x10000_units_BE>
    # and is what the XBL Core reads first, then the EFI_FV_HEADER follows.
    "decompiled_extra/dxe_core_fv.bin": "b805f343a58b906624528dd9d13504f8371996db8c9d18166cd7316ee6f8e929",
    "decompiled_extra/uefi_aux_fv.bin": "fc528dd229a8719ee6c69a2b9b96967f4295d0a12422dfb3b51d2d1685a7839e",
}


def verify_hash(path: Path, expected: str) -> bool:
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        print(f"HASH MISMATCH: {path}")
        print(f"  expected {expected}")
        print(f"  actual   {actual}")
        return False
    return True


def extract_dxe_fvs(uefi_path: Path, out_dir: Path) -> int:
    if not uefi_path.exists():
        print(f"ERROR: {uefi_path} not found")
        return 1

    data = uefi_path.read_bytes()
    print(f"uefi.img size: 0x{len(data):x}")

    for name, off, desc in GZIP_STREAMS:
        if off >= len(data):
            print(f"  {name}: offset 0x{off:x} past file end, skip")
            continue
        if data[off:off+3] != b"\x1f\x8b\x08":
            print(f"  {name}: no gzip magic at 0x{off:x}, skip")
            continue

        dec = zlib.decompressobj(31)
        try:
            out = dec.decompress(data[off:off + 0x1000000], max_length=0x10000000)
        except Exception as e:
            print(f"  {name}: decompression failed: {e}")
            continue

        # The decompressed data has:
        # 0x00..0x07: Samsung 8-byte header
        # 0x08..0x17: zero_vector (16 bytes)
        # 0x18..0x27: FileSystemGuid
        # 0x28..0x2f: FvLength
        # 0x30..0x33: _FVH
        fv = out[0x08:]
        fv_len = int.from_bytes(fv[0x20:0x28], "little")
        sig = fv[0x28:0x2C]
        if sig != b"_FVH":
            print(f"  {name}: bad signature {sig!r}")
            continue

        fs = fv[0x10:0x20]
        print(f"  {name}: {len(fv)} bytes (FV length 0x{fv_len:x})")
        print(f"    FileSystemGuid: {fs.hex()}")
        print(f"    Description: {desc}")

        out_path = out_dir / f"{name}.bin"
        # Save the FULL decompressed output (including Samsung 8-byte header)
        # so the hash matches the previously-computed baseline.
        out_path.write_bytes(out)
        actual = hashlib.sha256(out).hexdigest()
        print(f"    saved: {out_path.relative_to(ROOT)}")
        print(f"    sha256: {actual}")

        expected = EXPECTED_HASHES.get(str(out_path.relative_to(ROOT)))
        if expected and actual != expected:
            print(f"    HASH MISMATCH (expected {expected})")
            return 1

    return 0


def main() -> int:
    print("Verifying uefi.img hash...")
    if not verify_hash(UEFI_IMG, EXPECTED_HASHES["uefi.img"]):
        return 1
    print("OK")

    out_dir = ROOT / "decompiled_extra"
    out_dir.mkdir(exist_ok=True)

    print("\nExtracting DXE FVs from uefi.img...")
    rc = extract_dxe_fvs(UEFI_IMG, out_dir)

    if rc == 0:
        print("\nExtraction complete.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
