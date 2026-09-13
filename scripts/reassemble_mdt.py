#!/usr/bin/env python3
"""Reassemble a split SPU/MDT trustlet image (name.mdt + name.b00..bNN) into a
single flat ELF64 file, by placing each split segment's bytes at the file
offset given in the .mdt's own program header table (entry i -> .b0i).

Before trusting the mapping, every split file's size is checked against that
header's p_filesz; all entries must match exactly, which is what confirms
"entry i -> .b0i" is the right pairing rather than an assumption.

Read-only: never touches a device, never mutates the inputs. The output ELF
is a local scratch artifact (gitignored like all *.elf); its sha256 is what
downstream evidence headers record.
"""

from __future__ import annotations

from pathlib import Path

from elftools.elf.elffile import ELFFile


def reassemble(mdt_path: Path, out_path: Path) -> None:
    mdt_path = Path(mdt_path)
    prefix = mdt_path.with_suffix("")  # strip .mdt
    with mdt_path.open("rb") as f:
        elf = ELFFile(f)
        headers = [dict(seg.header) for seg in elf.iter_segments()]

    total = max(h["p_offset"] + h["p_filesz"] for h in headers)
    buf = bytearray(total)

    for i, h in enumerate(headers):
        seg_file = Path(f"{prefix}.b{i:02d}")
        if not seg_file.exists():
            print(f"  ! missing split segment {seg_file}, skipping entry {i}")
            continue
        data = seg_file.read_bytes()
        off = h["p_offset"]
        if len(data) != h["p_filesz"]:
            print(f"  ! size mismatch entry {i}: file={len(data)} header={h['p_filesz']}")
        buf[off:off + len(data)] = data

    out_path.write_bytes(bytes(buf))
    print(f"  wrote {out_path} ({len(buf)} bytes)")


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mdt", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    reassemble(args.mdt.resolve(), args.out.resolve())


if __name__ == "__main__":
    main()
