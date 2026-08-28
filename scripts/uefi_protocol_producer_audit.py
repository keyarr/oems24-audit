#!/usr/bin/env python3
"""
Read-only, deterministic producer-provenance audit for the UEFI
firmware artifacts in this repo.

Scans every collected firmware image for the three target GUIDs
(EFI_MEM_CARDINFO_PROTOCOL, Samsung VB protocol, EFI_BLOCK_IO_PROTOCOL)
in their raw mixed-endian byte representation. Records SHA-256 of
every artifact. Fails loudly if any expected hash changes.

Inputs:  all .img / .pe / .bin / .elf in partitions/, partitions_extra/,
         decompiled/, and uefi.img in repo root
Output:  decompiled/uefi-memcardinfo-producer-analysis.txt section 2 table
         and section 14 hash verification
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GUIDS = {
    "memcard": bytes.fromhex("d2f7c185e6bc314f8f4dd37e03d05eaa"),
    "vb": bytes.fromhex("91ff5e8eb621d347af2bc15a01e020ec"),
    "blockio": bytes.fromhex("215b4e965964d2118e3900a0c969723b"),
    "sfs": bytes.fromhex("225b4e965964d2118e3900a0c969723b"),
}

EXPECTED_HASHES = {
    "partitions/abl.img": "49ff63c8b82e1513ea6c41cd5229fa088eee272e238419a8f3067b1abcb9d7eb",
    "partitions/devinfo.img": "ae8e0b0112822c89ce2ea9dbae977a55bbf4efcab7171083f2d9dcec0f668220",
    "partitions/em.img": "ac9e4116fa1b2fb4922744ec591190a0727e3d84f1e9a74361a344261f457711",
    "partitions/imagefv.img": "bdc8b3317c4ed9966ce43a36c25578da77e991f8c376a27d1c2dc603f599d2a8",
    "partitions/uefisecapp.img": "104d16c630f142170db875e80ead9f3497ca9bd4cac0daff2830f58126c52809",
    "partitions/vbmeta.img": "f6e493075c77dc4981b317b4495ccfb82fad9d7a27ab7ca6f0e479bcde0844f3",
    "partitions/vbmeta_system.img": "fe08afbe3ae14be99bc952ad34f115a2e4d6dfb3456de5adc85ae399d328397e",
    "uefi.img": "7cb98e7804f76f27d0b9d5487a13d0cd7354c4ef4d4c6b7b5582befcc4eb727f",
    "partitions_extra/aop.img": "e030eec3e9577e3eb10d1ba84cce0402488fa8a7d12feae32063faf5f0d82b31",
    "partitions_extra/aop_config.img": "debcb7cfaec2fefc9d7dd374797f9cebb5137712e35ee90d2203ac26bac35c2f",
    "partitions_extra/devcfg.img": "4dc857c083c87a2499fa81c40afb6615f23f99c48ef075be4113d85f9b3fc311",
    "partitions_extra/qupfw.img": "bc363c9679b9cc5de5518ae816fff7f5c353eefbf35ad646e9cb86084c0aefa5",
    "partitions_extra/storsec.img": "3100ad8f3c472a14e63f1e8d5d02f5ea53566d6c8fb2f4062f80759d5a80526f",
    "partitions_extra/toolsfv.img": "f474462dfcb6b7b0e48213e87ce20805701615a4092970b2efd59dc6f878d03b",
    "partitions_extra/uefivarstore.img": "6468ab6ccfc422931d5d7fbcdcb8528fa42d8e5f5f8e5b853ad20e9a58a50703",
    "partitions_extra/xbl.img": "d9eae70f873406bf00c1245e7f10ff07b7dd2127891df0b7f4c383e8bdfae782",
    "partitions_extra/xbl_b.img": "bb9f8df61474d25e71fa00722318cd387396ca1736605e1248821cc0de3d3af8",
    "partitions_extra/xbl_config.img": "88c5073c6e2ae6cb667cac7f6000c6c5fec5b5160e9b3d6b2f00125490395210",
    "partitions_extra/xbl_config_b.img": "9eb8fa54d87a9b9775dd55c07b3d164453884695bd1ed83fe2f63259ee9e6afc",
    "partitions_extra/xbl_ramdump.img": "0957c1cd45a1001b143e8fa42eab9b6417e307c450b55a753b1b3a6eca943e84",
    "partitions_extra/xbl_sc_logs.img": "2b39b44d3057d8cb8286ebbab3d090078fabeff09c24300ad744361ea8226956",
    "partitions_extra/xbl_sc_test_mode.img": "de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31",
}


def collect_artifacts() -> list[Path]:
    artifacts: list[Path] = []
    for sub in ("partitions", "partitions_extra", "decompiled"):
        d = ROOT / sub
        if not d.exists():
            continue
        for p in sorted(d.iterdir()):
            if p.is_file() and p.suffix in (".img", ".pe", ".bin", ".elf", ".fv.bin"):
                artifacts.append(p)
    uefi = ROOT / "uefi.img"
    if uefi.exists():
        artifacts.append(uefi)
    return artifacts


def scan(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    return {name: data.count(needle) for name, needle in GUIDS.items()}


def main() -> int:
    artifacts = collect_artifacts()
    print(f"# {len(artifacts)} artifacts scanned")
    print()
    print(f"{'artifact':50s}  {'size':>10s}  memcard vb blockio sfs")
    for p in artifacts:
        counts = scan(p)
        size = p.stat().st_size
        rel = p.relative_to(ROOT)
        print(
            f"{str(rel):50s}  {size:>10x}  "
            f"{counts['memcard']:>3d} {counts['vb']:>3d} "
            f"{counts['blockio']:>3d} {counts['sfs']:>3d}"
        )
    print()
    print("# SHA-256 verification")
    bad = 0
    for rel, expected in sorted(EXPECTED_HASHES.items()):
        p = ROOT / rel
        if not p.exists():
            print(f"MISSING: {rel}")
            bad += 1
            continue
        actual = hashlib.sha256(p.read_bytes()).hexdigest()
        ok = actual == expected
        if not ok:
            print(f"CHANGED: {rel}")
            print(f"  expected {expected}")
            print(f"  actual   {actual}")
            bad += 1
    if bad:
        print(f"\n# {bad} hash mismatch(es). Refusing to claim baseline valid.")
        return 1
    print(f"\n# All {len(EXPECTED_HASHES)} expected hashes match.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
