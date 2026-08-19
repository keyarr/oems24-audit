#!/usr/bin/env python3
"""Locate a GUID-defined UEFI section and extract the ARM64 LinuxLoader PE."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import lzma
import pathlib
import struct

from uefi_firmware.uefi import FirmwareVolume, sguid


MARKERS = (
    b"IsUnlocked",
    b"IsUnlockCritical",
    b"GetUnlockCount",
    b"Device is unlocked",
    b"Skipping boot verification",
    b"BLInitToken",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_arm64_pe(data: bytes) -> bool:
    if len(data) < 0x100 or data[:2] != b"MZ":
        return False
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 6 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return False
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    return machine == 0xAA64


def outer_candidates(source: bytes):
    for offset in range(0, len(source) - 24, 4):
        size = int.from_bytes(source[offset : offset + 3], "little")
        section_type = source[offset + 3]
        if section_type != 0x02 or size < 25 or offset + size > len(source):
            continue
        data_offset = int.from_bytes(source[offset + 20 : offset + 22], "little")
        if not 24 <= data_offset < size:
            continue
        compressed = source[offset + data_offset : offset + size]
        if not compressed or compressed[0] not in (0x5D, 0x6D, 0x7D):
            continue
        try:
            payload = lzma.decompress(compressed, format=lzma.FORMAT_ALONE)
        except lzma.LZMAError:
            continue
        magic_offset = payload.find(b"_FVH")
        if magic_offset < 0x28:
            continue
        volume_offset = magic_offset - 0x28
        volume = FirmwareVolume(payload[volume_offset:])
        if not volume.process():
            continue
        modules = []
        for filesystem in volume.firmware_filesystems:
            for firmware_file in filesystem.files:
                ui_names = [section.name for section in firmware_file.sections if section.type == 0x15]
                pe_sections = [section.data for section in firmware_file.sections if section.type == 0x10]
                if "LinuxLoader" not in ui_names:
                    continue
                for pe_data in pe_sections:
                    if is_arm64_pe(pe_data):
                        modules.append((sguid(firmware_file.guid), pe_data))
        if len(modules) != 1:
            continue
        module_guid, pe_data = modules[0]
        marker_offsets = {m.decode(): pe_data.find(m) for m in MARKERS if m in pe_data}
        yield (
            offset,
            size,
            data_offset,
            compressed,
            payload,
            volume_offset,
            module_guid,
            pe_data,
            marker_offsets,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("metadata", type=pathlib.Path)
    parser.add_argument("--outer-volume-output", type=pathlib.Path)
    args = parser.parse_args()

    source = args.source.read_bytes()
    matches = list(outer_candidates(source))
    strong = [match for match in matches if len(match[-1]) >= 4]
    if len(strong) != 1:
        summary = [(hex(m[0]), len(m[-1]), list(m[-1])) for m in matches]
        raise RuntimeError(f"expected exactly one LinuxLoader candidate, found {summary}")

    (
        section_offset,
        section_size,
        data_offset,
        compressed,
        outer_payload,
        volume_offset,
        module_guid,
        payload,
        marker_offsets,
    ) = strong[0]
    pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
    machine = struct.unpack_from("<H", payload, pe_offset + 4)[0]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.metadata.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    if args.outer_volume_output:
        args.outer_volume_output.parent.mkdir(parents=True, exist_ok=True)
        args.outer_volume_output.write_bytes(outer_payload)
    record = {
        "extracted_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": str(args.source.resolve()),
        "source_size": len(source),
        "source_sha256": sha256(source),
        "uefi_section_offset": section_offset,
        "uefi_section_offset_hex": hex(section_offset),
        "uefi_section_size": section_size,
        "uefi_data_offset": data_offset,
        "compressed_size": len(compressed),
        "compressed_sha256": sha256(compressed),
        "compression": "LZMA-alone",
        "outer_volume_offset": volume_offset,
        "outer_volume_size": len(outer_payload),
        "outer_volume_sha256": sha256(outer_payload),
        "outer_volume_destination": (
            str(args.outer_volume_output.resolve()) if args.outer_volume_output else None
        ),
        "linuxloader_ffs_guid": module_guid,
        "destination": str(args.output.resolve()),
        "destination_size": len(payload),
        "destination_sha256": sha256(payload),
        "pe_machine": machine,
        "pe_machine_hex": hex(machine),
        "marker_offsets": marker_offsets,
    }
    args.metadata.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
