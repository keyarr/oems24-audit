#!/usr/bin/env python3
"""Read-only, generic extractor + module inventory for an ABL inner firmware volume.

`scripts/abl_inner_fv_analysis.py` is pinned to the audited DZDP artifact and asserts
exact input hashes, so it cannot be reused on a second build. This module keeps the
same parsing rules (verified against the DZDP artifact) but takes any ABL ELF and
emits:

  * the decompressed inner FV as a .bin next to the other decompiled artifacts
  * a JSON inventory of every FFS file with per-module hashes, UI name, entry RVA,
    PE timestamp and CodeView PDB path

The inventory is what a patch-diff should compare. Whole-image byte diff of the
inner FV is not usable as a change signal (see notes/vuln-research-map.md section 9).

No state-changing operation is performed and no external service is contacted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import uuid
from pathlib import Path

import lzma

ROOT = Path(__file__).resolve().parents[1]

FILE_TYPES = {
    0x01: "RAW",
    0x02: "FREEFORM",
    0x03: "SECURITY_CORE",
    0x04: "PEI_CORE",
    0x05: "DXE_CORE",
    0x06: "PEIM",
    0x07: "DRIVER",
    0x08: "COMBINED_PEIM_DRIVER",
    0x09: "APPLICATION",
    0x0B: "FV_IMAGE",
    0x0C: "COMBINED_SMM_DXE",
    0xF0: "PAD",
}

SECTION_TYPES = {
    0x01: "COMPRESSION",
    0x02: "GUID_DEFINED",
    0x10: "PE32",
    0x11: "PIC",
    0x12: "TE",
    0x13: "DXE_DEPEX",
    0x14: "VERSION",
    0x15: "UI",
    0x16: "COMPATIBILITY16",
    0x17: "FV_IMAGE",
    0x18: "FREEFORM_SUBTYPE_GUID",
    0x19: "RAW",
    0x1B: "PEI_DEPEX",
    0x1C: "SMM_DEPEX",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def align(value: int, amount: int) -> int:
    return (value + amount - 1) & ~(amount - 1)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def guid_text(raw: bytes) -> str:
    require(len(raw) == 16, "GUID must be 16 bytes")
    return str(uuid.UUID(bytes_le=raw))


def section_header(data: bytes, offset: int, limit: int) -> dict:
    require(offset + 4 <= limit, f"truncated section header at 0x{offset:x}")
    size = int.from_bytes(data[offset : offset + 3], "little")
    section_type = data[offset + 3]
    header_size = 4
    if size == 0xFFFFFF:
        require(offset + 8 <= limit, f"truncated extended section at 0x{offset:x}")
        size = struct.unpack_from("<I", data, offset + 4)[0]
        header_size = 8
    require(size >= header_size, f"invalid section size 0x{size:x} at 0x{offset:x}")
    require(offset + size <= limit, f"section at 0x{offset:x} exceeds its container")
    return {
        "offset": offset,
        "size": size,
        "type": section_type,
        "type_name": SECTION_TYPES.get(section_type, "UNKNOWN"),
        "header_size": header_size,
        "payload_offset": offset + header_size,
        "payload_size": size - header_size,
    }


def rva_to_file(sections: list[dict], rva: int) -> int | None:
    for section in sections:
        if section["rva"] <= rva < section["rva"] + max(section["raw_size"], section["virtual_size"]):
            return section["file_offset"] + (rva - section["rva"])
    return None


def parse_pe(image: bytes) -> dict:
    """Minimal PE32/PE32+ header parse. Returns {} when the image is not a PE."""
    if len(image) < 0x40 or image[:2] != b"MZ":
        return {}
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    if pe_offset + 24 > len(image) or image[pe_offset : pe_offset + 4] != b"PE\0\0":
        return {}
    coff = pe_offset + 4
    machine, section_count, timestamp = struct.unpack_from("<HHI", image, coff)
    optional = coff + 20
    optional_size = struct.unpack_from("<H", image, coff + 16)[0]
    magic = struct.unpack_from("<H", image, optional)[0]
    if magic not in (0x10B, 0x20B):
        return {}
    entry_rva = struct.unpack_from("<I", image, optional + 16)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", image, optional + 24)[0]
        data_directory = optional + 112
    else:
        image_base = struct.unpack_from("<I", image, optional + 28)[0]
        data_directory = optional + 96
    image_size = struct.unpack_from("<I", image, optional + 56)[0]
    subsystem = struct.unpack_from("<H", image, optional + 68)[0]
    sections = []
    section_table = optional + optional_size
    for index in range(section_count):
        pos = section_table + index * 40
        if pos + 40 > len(image):
            break
        name = image[pos : pos + 8].rstrip(b"\0").decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", image, pos + 8
        )
        flags = struct.unpack_from("<I", image, pos + 36)[0]
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "rva": virtual_address,
                "raw_size": raw_size,
                "file_offset": raw_offset,
                "executable": bool(flags & 0x20000000),
            }
        )

    pdb_path = None
    if data_directory + 8 * 7 <= optional + optional_size:
        debug_rva, debug_size = struct.unpack_from("<II", image, data_directory + 8 * 6)
        if debug_rva and debug_size >= 28:
            debug_file = rva_to_file(sections, debug_rva)
            if debug_file is not None and debug_file + 28 <= len(image):
                _, _, _, _, debug_type, data_size, _, data_pointer = struct.unpack_from(
                    "<IIHHIIII", image, debug_file
                )
                if debug_type == 2 and data_pointer + data_size <= len(image):
                    codeview = image[data_pointer : data_pointer + data_size]
                    if codeview.startswith(b"RSDS") and len(codeview) > 24:
                        pdb_path = codeview[24:].split(b"\0", 1)[0].decode("utf-8", "replace")

    return {
        "format": "PE32+" if magic == 0x20B else "PE32",
        "machine": machine,
        "timestamp": timestamp,
        "entry_point_rva": entry_rva,
        "image_base": image_base,
        "image_size": image_size,
        "subsystem": subsystem,
        "section_count": section_count,
        "sections": sections,
        "pdb_path": pdb_path,
    }


def parse_te(image: bytes) -> dict:
    if len(image) < 0x28 or image[:2] != b"VZ":
        return {}
    machine, _, _, entry, _ = struct.unpack_from("<HBBHH", image, 4)
    return {"format": "TE", "machine": machine, "entry_point_rva": entry}


def decompress_inner(abl: bytes) -> tuple[bytes, dict]:
    """Return (inner_fv_bytes, origin_metadata) for an ABL ELF."""
    require(abl[:4] == b"\x7fELF", "ABL is not an ELF")
    require(abl[4:6] == b"\x01\x01", "ABL is not ELF32 little-endian")
    program_offset = struct.unpack_from("<I", abl, 0x1C)[0]
    program_entry_size, program_count = struct.unpack_from("<HH", abl, 0x2A)
    loads = []
    for index in range(program_count):
        pos = program_offset + index * program_entry_size
        ptype, file_offset, va, _pa, file_size, mem_size = struct.unpack_from("<IIIIII", abl, pos)
        if ptype == 1:
            loads.append({"file_offset": file_offset, "virtual_address": va, "file_size": file_size})
    require(len(loads) == 1, f"expected one ABL PT_LOAD, found {len(loads)}")
    load = loads[0]
    fv_base = load["file_offset"]
    require(abl[fv_base + 0x28 : fv_base + 0x2C] == b"_FVH", "ABL outer FV missing")
    fv_size = struct.unpack_from("<Q", abl, fv_base + 0x20)[0]
    fv_header = struct.unpack_from("<H", abl, fv_base + 0x30)[0]
    ffs_offset = fv_base + fv_header
    ffs_size = int.from_bytes(abl[ffs_offset + 20 : ffs_offset + 23], "little")
    section_offset = ffs_offset + 24
    guided = section_header(abl, section_offset, ffs_offset + ffs_size)
    require(guided["type"] == 0x02, "ABL payload is not GUID-defined")
    guided_guid = guid_text(abl[guided["payload_offset"] : guided["payload_offset"] + 16])
    data_offset, attributes = struct.unpack_from("<HH", abl, guided["payload_offset"] + 16)
    compressed = abl[section_offset + data_offset : section_offset + guided["size"]]
    inner = lzma.decompress(compressed, format=lzma.FORMAT_ALONE)
    origin = {
        "fv_base": fv_base,
        "outer_fv_size": fv_size,
        "outer_fv_sha256": sha256(abl[fv_base : fv_base + fv_size]),
        "pt_load_sha256": sha256(abl[load["file_offset"] : load["file_offset"] + load["file_size"]]),
        "ffs_guid": guid_text(abl[ffs_offset : ffs_offset + 16]),
        "guided_section_guid": guided_guid,
        "guided_attributes": attributes,
        "compression": "LZMA-alone",
        "compressed_size": len(compressed),
        "compressed_sha256": sha256(compressed),
        "decompressed_size": len(inner),
    }
    return inner, origin


def inventory(inner: bytes) -> tuple[dict, list[dict]]:
    """Parse the inner FV into FFS files. Returns (fv_metadata, files)."""
    cursor = 0
    top_sections = []
    while cursor + 4 <= len(inner):
        section = section_header(inner, cursor, len(inner))
        top_sections.append(section)
        cursor = align(cursor + section["size"], 4)
        if cursor == len(inner):
            break
    require(cursor == len(inner), "top-level section stream has trailing bytes")
    fv_base = top_sections[-1]["payload_offset"]
    require(inner[fv_base + 0x28 : fv_base + 0x2C] == b"_FVH", "inner FV signature missing")
    fv_length = struct.unpack_from("<Q", inner, fv_base + 0x20)[0]
    fv_attributes = struct.unpack_from("<I", inner, fv_base + 0x2C)[0]
    erase_polarity = bool(fv_attributes & 0x00000800)
    header_length, checksum, ext_header_offset = struct.unpack_from("<HHH", inner, fv_base + 0x30)
    fv_end = fv_base + fv_length
    require(fv_end == len(inner), "inner FV length does not cover input")

    ffs_start = align(fv_base + header_length, 8)
    ext = None
    if ext_header_offset:
        ext_offset = fv_base + ext_header_offset
        ext_size = struct.unpack_from("<I", inner, ext_offset + 16)[0]
        ext = {
            "offset": ext_offset,
            "fv_name_guid": guid_text(inner[ext_offset : ext_offset + 16]),
            "size": ext_size,
        }

    files: list[dict] = []
    cursor = ffs_start
    while cursor + 24 <= fv_end and inner[cursor : cursor + 24] != b"\xff" * 24:
        ffs_guid = guid_text(inner[cursor : cursor + 16])
        file_checksum = inner[cursor + 17]
        file_type = inner[cursor + 18]
        attributes = inner[cursor + 19]
        size = int.from_bytes(inner[cursor + 20 : cursor + 23], "little")
        header_size = 24
        if size == 0xFFFFFF:
            size = struct.unpack_from("<Q", inner, cursor + 24)[0]
            header_size = 32
        require(size >= header_size and cursor + size <= fv_end, f"invalid FFS size at 0x{cursor:x}")

        sections: list[dict] = []
        ui_name = None
        executable = None
        image_sha256 = None
        image_size = None
        if file_type != 0xF0:
            section_cursor = cursor + header_size
            while section_cursor + 4 <= cursor + size:
                section = section_header(inner, section_cursor, cursor + size)
                if section["type"] == 0x15:
                    raw = inner[section["payload_offset"] : section_cursor + section["size"]]
                    ui_name = raw.decode("utf-16le", "strict").rstrip("\0")
                elif section["type"] in (0x10, 0x12):
                    image = inner[section["payload_offset"] : section_cursor + section["size"]]
                    image_sha256 = sha256(image)
                    image_size = len(image)
                    executable = parse_pe(image) if section["type"] == 0x10 else parse_te(image)
                    if executable:
                        executable = dict(executable)
                        executable.pop("sections", None)
                sections.append(
                    {
                        "type": section["type_name"],
                        "offset": section["offset"],
                        "size": section["size"],
                    }
                )
                section_cursor = align(section_cursor + section["size"], 4)

        files.append(
            {
                "guid": ffs_guid,
                "ui_name": ui_name,
                "type": FILE_TYPES.get(file_type, "UNKNOWN"),
                "offset": cursor,
                "size": size,
                "attributes": attributes,
                "state": (~inner[cursor + 23] & 0xFF) if erase_polarity else inner[cursor + 23],
                "file_sha256": sha256(inner[cursor : cursor + size]),
                "image_sha256": image_sha256,
                "image_size": image_size,
                "executable": executable,
                "sections": sections,
            }
        )
        cursor = align(cursor + size, 8)

    fv = {
        "file_offset": fv_base,
        "size": fv_length,
        "filesystem_guid": guid_text(inner[fv_base + 16 : fv_base + 32]),
        "header_length": header_length,
        "attributes": fv_attributes,
        "erase_polarity": erase_polarity,
        "revision": inner[fv_base + 0x37],
        "extension_header": ext,
        "ffs_start_offset": ffs_start,
        "free_space_offset": cursor,
        "file_count": len(files),
        "inner_fv_sha256": sha256(inner),
    }
    return fv, files


def build(elf_path: Path, fv_out: Path, json_out: Path) -> dict:
    elf_path = elf_path.resolve()
    fv_out = fv_out.resolve()
    json_out = json_out.resolve()
    abl = elf_path.read_bytes()
    inner, origin = decompress_inner(abl)
    fv, files = inventory(inner)
    fv_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    fv_out.write_bytes(inner)
    record = {
        "source": str(elf_path.relative_to(ROOT)),
        "source_sha256": sha256(abl),
        "inner_fv_output": str(fv_out.relative_to(ROOT)),
        "origin": origin,
        "firmware_volume": fv,
        "files": files,
    }
    json_out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("fv_out", type=Path)
    parser.add_argument("json_out", type=Path)
    args = parser.parse_args()
    record = build(args.elf, args.fv_out, args.json_out)
    print(f"{args.elf.name}: inner FV {record['origin']['decompressed_size']} bytes "
          f"sha256={record['firmware_volume']['inner_fv_sha256']}")
    print(f"  FFS files: {record['firmware_volume']['file_count']}")
    print(f"  wrote {args.fv_out.name} and {args.json_out.name}")


if __name__ == "__main__":
    main()
