#!/usr/bin/env python3
"""Import and verify the One UI 7 ABL from Samsung's BL tar.md5 archive."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import tarfile

import lz4.frame


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("metadata", type=pathlib.Path)
    args = parser.parse_args()

    archive_bytes = args.archive.read_bytes()
    with tarfile.open(args.archive, mode="r:*") as archive:
        member = archive.getmember("abl.elf.lz4")
        stream = archive.extractfile(member)
        if stream is None:
            raise RuntimeError("abl.elf.lz4 is not a regular archive member")
        compressed = stream.read()

    decompressed = lz4.frame.decompress(compressed)
    if len(decompressed) < 0x1000 or decompressed[:4] != b"\x7fELF":
        raise RuntimeError("decompressed ABL does not start with an ELF header")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.metadata.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(decompressed)
    record = {
        "collected_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": str(args.archive.resolve()),
        "source_size": len(archive_bytes),
        "source_sha256": digest(archive_bytes),
        "archive_member": member.name,
        "member_size": len(compressed),
        "member_sha256": digest(compressed),
        "decompression": "LZ4 frame",
        "destination": str(args.output.resolve()),
        "destination_size": len(decompressed),
        "destination_sha256": digest(decompressed),
    }
    args.metadata.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

