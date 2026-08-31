#!/usr/bin/env python3
"""Read-only, deterministic inventory and protocol audit for the ABL inner FV."""

from __future__ import annotations

import hashlib
import json
import lzma
import re
import struct
import uuid
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG


ROOT = Path(__file__).resolve().parent.parent
INNER_PATH = ROOT / "decompiled" / "abl-inner-oneui8.fv.bin"
ABL_PATH = ROOT / "partitions" / "abl.img"
OUT_MODULES = ROOT / "decompiled" / "abl-inner-fv-modules.json"
OUT_GRAPH = ROOT / "decompiled" / "abl-inner-fv-protocol-graph.json"
OUT_REPORT = ROOT / "decompiled" / "abl-inner-fv-protocol-analysis.txt"

EXPECTED_INPUT_HASHES = {
    INNER_PATH: "ccffba2ae2632ec5f3097f2094f6bf9c3629848078ddf2f433e13c9f1aa057f0",
    ABL_PATH: "49ff63c8b82e1513ea6c41cd5229fa088eee272e238419a8f3067b1abcb9d7eb",
}

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

MACHINE_TYPES = {
    0x014C: "I386",
    0x8664: "X86_64",
    0x01C2: "ARM",
    0xAA64: "AARCH64",
    0x5032: "RISCV32",
    0x5064: "RISCV64",
}

PROTOCOLS = {
    "EFI_MEM_CARDINFO_PROTOCOL": {
        "guid": "85c1f7d2-bce6-4f31-8f4d-d37e03d05eaa",
        "raw": "d2f7c185e6bc314f8f4dd37e03d05eaa",
        "role": "card information protocol checked by LinuxLoader before EM synchronization",
    },
    "VB_PROTOCOL": {
        "guid": "8e5eff91-21b6-47d3-af2b-c15a01e020ec",
        "raw": "91ff5e8eb621d347af2bc15a01e020ec",
        "role": "protocol called VBRwDevice by LinuxLoader; DeviceInfo persistence transport",
    },
    "EFI_BLOCK_IO_PROTOCOL": {
        "guid": "964e5b21-6459-11d2-8e39-00a0c969723b",
        "raw": "215b4e965964d2118e3900a0c969723b",
        "role": "standard block protocol used for partition handles",
    },
    "EFI_SIMPLE_FILE_SYSTEM_PROTOCOL": {
        "guid": "964e5b22-6459-11d2-8e39-00a0c969723b",
        "raw": "225b4e965964d2118e3900a0c969723b",
        "role": "standard filesystem protocol; included to prevent the old BlockIo GUID mix-up",
    },
}

GBS_SLOTS = {
    0x80: "InstallProtocolInterface",
    0x88: "ReinstallProtocolInterface",
    0x90: "UninstallProtocolInterface",
    0x98: "HandleProtocol",
    0x118: "OpenProtocol",
    0x138: "LocateHandleBuffer",
    0x140: "LocateProtocol",
    0x148: "InstallMultipleProtocolInterfaces",
    0x150: "UninstallMultipleProtocolInterfaces",
}

EXPECTED_MODULES = [
    {
        "name": "Odin",
        "ffs_guid": "aba3b456-5469-414a-9f79-47cecbd7c04e",
        "ffs_offset": 0x80,
        "pe_offset": 0xAC,
        "pe_size": 0xEC000,
        "sha256": "c05b772ce3715b0df0ae7cc876c0825d366c3506b660389e2dc44d8725abf135",
    },
    {
        "name": "LinuxLoader",
        "ffs_guid": "f536d559-459f-48fa-8bbc-43b554ecae8d",
        "ffs_offset": 0xEC0B0,
        "pe_offset": 0xEC0E8,
        "pe_size": 0x190000,
        "sha256": "1e57583c18bd1aaac855becf87cc6286d702e703fd8122bf9c3808f625e6da4a",
    },
    {
        "name": "Cryptest",
        "ffs_guid": "fb925ac7-192a-9567-8586-7c6f5f710607",
        "ffs_offset": 0x27C0E8,
        "pe_offset": 0x27C11C,
        "pe_size": 0xA0000,
        "sha256": "56271dba1de2d58df5b8a1f17027d8209fcafb4902cd6273a3f531948fec88a2",
    },
    {
        "name": "QuestSOD",
        "ffs_guid": "1f6ee9c8-82e8-4dff-8b57-f9281bc18517",
        "ffs_offset": 0x31C120,
        "pe_offset": 0x31C154,
        "pe_size": 0xC000,
        "sha256": "75b27cc6544dfd92dc30f2a3b0a4e126a27f6faf13a21884dfd6154a3d30abfa",
    },
    {
        "name": "QuestUSB",
        "ffs_guid": "9a70e61c-f392-4aa1-8b48-3f84009885e0",
        "ffs_offset": 0x328158,
        "pe_offset": 0x32818C,
        "pe_size": 0xC000,
        "sha256": "6fa98affdf034236388ebfafa456629d35d98597b0b3c2ec7af522a9890ca19e",
    },
]

RELEVANT_STRING = re.compile(
    r"memcard|cardinfo|blockio|device info|devinfo|vbrwdevice|vb protocol|"
    r"partition|\bufs\b|emmc|storage|linuxloader|odin|quest|cryptest",
    re.IGNORECASE,
)


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


def all_offsets(data: bytes, needle: bytes) -> list[int]:
    result = []
    start = 0
    while True:
        found = data.find(needle, start)
        if found < 0:
            return result
        result.append(found)
        start = found + 1


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


def parse_pe(image: bytes) -> dict:
    require(len(image) >= 0x40 and image[:2] == b"MZ", "PE image has no MZ header")
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    require(pe_offset + 24 <= len(image), "PE header is outside image")
    require(image[pe_offset : pe_offset + 4] == b"PE\0\0", "missing PE signature")
    coff = pe_offset + 4
    machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", image, coff
    )
    optional = coff + 20
    require(optional + optional_size <= len(image), "truncated PE optional header")
    magic = struct.unpack_from("<H", image, optional)[0]
    require(magic in (0x10B, 0x20B), f"unsupported PE optional magic 0x{magic:x}")
    entry_rva = struct.unpack_from("<I", image, optional + 16)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", image, optional + 24)[0]
        data_directory = optional + 112
    else:
        image_base = struct.unpack_from("<I", image, optional + 28)[0]
        data_directory = optional + 96
    section_alignment, file_alignment = struct.unpack_from("<II", image, optional + 32)
    image_size, header_size = struct.unpack_from("<II", image, optional + 56)
    subsystem = struct.unpack_from("<H", image, optional + 68)[0]
    sections = []
    section_table = optional + optional_size
    for index in range(section_count):
        pos = section_table + index * 40
        require(pos + 40 <= len(image), "truncated PE section table")
        name = image[pos : pos + 8].rstrip(b"\0").decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", image, pos + 8
        )
        flags = struct.unpack_from("<I", image, pos + 36)[0]
        require(raw_offset + raw_size <= len(image), f"section {name} exceeds PE image")
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "rva": virtual_address,
                "raw_size": raw_size,
                "file_offset": raw_offset,
                "characteristics": flags,
                "executable": bool(flags & 0x20000000),
            }
        )

    pdb_path = None
    if data_directory + 8 * 7 <= optional + optional_size:
        debug_rva, debug_size = struct.unpack_from("<II", image, data_directory + 8 * 6)
        if debug_rva and debug_size >= 28:
            debug_file = rva_to_file_from_sections(sections, debug_rva)
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
        "pe_header_file_offset": pe_offset,
        "machine": machine,
        "machine_name": MACHINE_TYPES.get(machine, "UNKNOWN"),
        "timestamp": timestamp,
        "characteristics": characteristics,
        "section_count": section_count,
        "entry_point_rva": entry_rva,
        "image_base": image_base,
        "image_size": image_size,
        "header_size": header_size,
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "subsystem": subsystem,
        "pdb_path": pdb_path,
        "sections": sections,
    }


def parse_te(image: bytes) -> dict:
    require(len(image) >= 40 and image[:2] == b"VZ", "TE image has no VZ header")
    machine = struct.unpack_from("<H", image, 2)[0]
    section_count = image[4]
    subsystem = image[5]
    stripped_size = struct.unpack_from("<H", image, 6)[0]
    entry_rva, base_of_code = struct.unpack_from("<II", image, 8)
    image_base = struct.unpack_from("<Q", image, 16)[0]
    return {
        "format": "TE",
        "machine": machine,
        "machine_name": MACHINE_TYPES.get(machine, "UNKNOWN"),
        "section_count": section_count,
        "subsystem": subsystem,
        "stripped_size": stripped_size,
        "entry_point_rva": entry_rva,
        "base_of_code": base_of_code,
        "image_base": image_base,
    }


def rva_to_file_from_sections(sections: list[dict], rva: int) -> int | None:
    for section in sections:
        span = max(section["virtual_size"], section["raw_size"])
        if section["rva"] <= rva < section["rva"] + span:
            delta = rva - section["rva"]
            if delta < section["raw_size"]:
                return section["file_offset"] + delta
    return rva if rva < min((s["file_offset"] for s in sections), default=0) else None


def file_to_rva(pe: dict, file_offset: int) -> int | None:
    for section in pe["sections"]:
        if section["file_offset"] <= file_offset < section["file_offset"] + section["raw_size"]:
            return section["rva"] + file_offset - section["file_offset"]
    if file_offset < pe["header_size"]:
        return file_offset
    return None


def extract_relevant_strings(image: bytes, pe: dict, fv_image_offset: int) -> list[dict]:
    records = []
    seen = set()
    for encoding, pattern in (
        ("ASCII", re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{5,}\x00")),
        ("UTF-16LE", re.compile(rb"(?:[\x20-\x7e]\x00){5,}")),
    ):
        for match in pattern.finditer(image):
            if encoding == "ASCII":
                value = match.group()[:-1].decode("ascii", "replace")
            else:
                value = match.group().decode("utf-16le", "replace")
            if not RELEVANT_STRING.search(value):
                continue
            key = (match.start(), encoding, value)
            if key in seen:
                continue
            seen.add(key)
            rva = file_to_rva(pe, match.start())
            records.append(
                {
                    "encoding": encoding,
                    "value": value,
                    "pe_file_offset": match.start(),
                    "pe_rva": rva,
                    "radare2_va": rva + 0x10000 if rva is not None else None,
                    "fv_file_offset": fv_image_offset + match.start(),
                }
            )
    return sorted(records, key=lambda item: (item["pe_file_offset"], item["encoding"]))


def disassemble(image: bytes, pe: dict, start_rva: int, end_rva: int) -> list[dict]:
    start_file = rva_to_file_from_sections(pe["sections"], start_rva)
    require(start_file is not None, f"RVA 0x{start_rva:x} is not file-backed")
    code = image[start_file : start_file + end_rva - start_rva]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    records = []
    for instruction in md.disasm(code, start_rva):
        records.append(
            {
                "rva": instruction.address,
                "pe_file_offset": start_file + instruction.address - start_rva,
                "radare2_va": instruction.address + 0x10000,
                "bytes": instruction.bytes.hex(),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
            }
        )
    require(records and records[0]["rva"] == start_rva, f"cannot disassemble RVA 0x{start_rva:x}")
    return records


def direct_guid_refs(image: bytes, pe: dict, target: int) -> list[dict]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    result = []
    for section in pe["sections"]:
        if not section["executable"]:
            continue
        raw = image[section["file_offset"] : section["file_offset"] + section["raw_size"]]
        instructions = list(md.disasm(raw, section["rva"]))
        for index, first in enumerate(instructions):
            if first.mnemonic != "adrp" or len(first.operands) < 2:
                continue
            if first.operands[0].type != ARM64_OP_REG or first.operands[1].type != ARM64_OP_IMM:
                continue
            register = first.operands[0].reg
            register_name = first.reg_name(register)
            page = first.operands[1].imm
            register_family = register_name.lstrip("xw") if register_name[:1] in ("x", "w") else register_name
            for second in instructions[index + 1 : index + 65]:
                if second.mnemonic != "add" or len(second.operands) < 3:
                    _, written = second.regs_access()
                else:
                    is_reference = (
                        second.operands[0].type == ARM64_OP_REG
                        and second.operands[1].type == ARM64_OP_REG
                        and second.operands[2].type == ARM64_OP_IMM
                        and second.operands[0].reg == register
                        and second.operands[1].reg == register
                        and page + second.operands[2].imm == target
                    )
                    if is_reference:
                        result.append(
                            {
                                "adrp_rva": first.address,
                                "add_rva": second.address,
                                "register": register_name,
                                "target_pe_rva": target,
                            }
                        )
                    _, written = second.regs_access()
                written_families = {
                    second.reg_name(item).lstrip("xw")
                    if second.reg_name(item)[:1] in ("x", "w")
                    else second.reg_name(item)
                    for item in written
                }
                if register_family in written_families:
                    break
    unique = {(item["adrp_rva"], item["add_rva"]): item for item in result}
    return [unique[key] for key in sorted(unique)]


def parse_inner(data: bytes) -> tuple[dict, list[dict], dict[str, bytes]]:
    top_sections = []
    cursor = 0
    while cursor + 4 <= len(data):
        section = section_header(data, cursor, len(data))
        top_sections.append(section)
        cursor = align(cursor + section["size"], 4)
        if cursor == len(data):
            break
    require(cursor == len(data), "top-level section stream has trailing bytes")
    require(
        [(item["type"], item["offset"]) for item in top_sections] == [(0x19, 0), (0x17, 4)],
        "unexpected wrapper around inner FV",
    )
    fv_base = top_sections[1]["payload_offset"]
    require(data[fv_base + 0x28 : fv_base + 0x2C] == b"_FVH", "inner FV signature missing")
    fv_length = struct.unpack_from("<Q", data, fv_base + 0x20)[0]
    fv_attributes = struct.unpack_from("<I", data, fv_base + 0x2C)[0]
    erase_polarity = bool(fv_attributes & 0x00000800)
    header_length, checksum, ext_header_offset = struct.unpack_from("<HHH", data, fv_base + 0x30)
    require(fv_base + fv_length == len(data), "inner FV length does not cover input")
    require(header_length % 2 == 0, "odd FV header length")
    header_words = struct.unpack_from(f"<{header_length // 2}H", data, fv_base)
    require(sum(header_words) & 0xFFFF == 0, "invalid FV header checksum")
    block_map = []
    block_cursor = fv_base + 0x38
    while block_cursor + 8 <= fv_base + header_length:
        count, block_size = struct.unpack_from("<II", data, block_cursor)
        block_cursor += 8
        if (count, block_size) == (0, 0):
            break
        block_map.append({"count": count, "block_size": block_size})
    require(
        sum(item["count"] * item["block_size"] for item in block_map) == fv_length,
        "FV block map does not match FV length",
    )
    ext = None
    ffs_start = align(fv_base + header_length, 8)
    if ext_header_offset:
        ext_offset = fv_base + ext_header_offset
        require(ext_offset + 20 <= fv_base + fv_length, "truncated FV extension header")
        ext_size = struct.unpack_from("<I", data, ext_offset + 16)[0]
        require(ext_size >= 20, "invalid FV extension header size")
        ext = {
            "offset": ext_offset,
            "fv_name_guid": guid_text(data[ext_offset : ext_offset + 16]),
            "size": ext_size,
        }

    files = []
    images: dict[str, bytes] = {}
    cursor = ffs_start
    fv_end = fv_base + fv_length
    while cursor + 24 <= fv_end and data[cursor : cursor + 24] != b"\xff" * 24:
        ffs_guid = guid_text(data[cursor : cursor + 16])
        header_checksum = data[cursor + 16]
        file_checksum = data[cursor + 17]
        file_type = data[cursor + 18]
        attributes = data[cursor + 19]
        size = int.from_bytes(data[cursor + 20 : cursor + 23], "little")
        header_size = 24
        if size == 0xFFFFFF:
            require(attributes & 0x01, f"large FFS file without attribute at 0x{cursor:x}")
            require(cursor + 32 <= fv_end, "truncated large FFS header")
            size = struct.unpack_from("<Q", data, cursor + 24)[0]
            header_size = 32
        require(size >= header_size and cursor + size <= fv_end, f"invalid FFS size at 0x{cursor:x}")
        header = bytearray(data[cursor : cursor + header_size])
        header[17] = 0
        header[23] = 0
        require(sum(header) & 0xFF == 0, f"invalid FFS header checksum at 0x{cursor:x}")
        if attributes & 0x40:
            require(sum(data[cursor : cursor + size]) & 0xFF == 0, f"invalid FFS data checksum at 0x{cursor:x}")
        else:
            require(file_checksum == 0xAA, f"unexpected fixed FFS checksum at 0x{cursor:x}")

        sections = []
        section_cursor = cursor + header_size
        ui_name = None
        if file_type == 0xF0:
            require(ext is not None, "unexpected FFS padding file")
            require(
                cursor + header_size <= ext["offset"]
                and ext["offset"] + ext["size"] <= cursor + size,
                "FV extension header is not contained in the padding file",
            )
        else:
            while section_cursor + 4 <= cursor + size:
                section = section_header(data, section_cursor, cursor + size)
                if section["type"] == 0x15:
                    raw_name = data[section["payload_offset"] : section_cursor + section["size"]]
                    ui_name = raw_name.decode("utf-16le", "strict").rstrip("\0")
                    section["ui_name"] = ui_name
                elif section["type"] == 0x10:
                    image = data[section["payload_offset"] : section_cursor + section["size"]]
                    pe = parse_pe(image)
                    section["executable"] = pe
                    images[ui_name or ffs_guid] = image
                elif section["type"] == 0x12:
                    image = data[section["payload_offset"] : section_cursor + section["size"]]
                    section["executable"] = parse_te(image)
                    images[ui_name or ffs_guid] = image
                sections.append(section)
                section_cursor = align(section_cursor + section["size"], 4)
            require(section_cursor == cursor + size, f"FFS section alignment mismatch at 0x{cursor:x}")
        state_raw = data[cursor + 23]
        files.append(
            {
                "guid": ffs_guid,
                "offset": cursor,
                "size": size,
                "header_size": header_size,
                "header_checksum": header_checksum,
                "file_checksum": file_checksum,
                "type": file_type,
                "type_name": FILE_TYPES.get(file_type, "UNKNOWN"),
                "attributes": attributes,
                "state_raw": state_raw,
                "state_logical": (~state_raw & 0xFF) if erase_polarity else state_raw,
                "ui_name": ui_name,
                "sections": sections,
            }
        )
        cursor = align(cursor + size, 8)

    require(all(byte == 0xFF for byte in data[cursor:fv_end]), "non-erased bytes after final FFS file")
    fv = {
        "file_offset": fv_base,
        "size": fv_length,
        "filesystem_guid": guid_text(data[fv_base + 16 : fv_base + 32]),
        "header_length": header_length,
        "checksum": checksum,
        "checksum_valid": True,
        "attributes": fv_attributes,
        "erase_polarity": erase_polarity,
        "revision": data[fv_base + 0x37],
        "block_map": block_map,
        "extension_header": ext,
        "ffs_start_offset": ffs_start,
        "free_space_offset": cursor,
        "free_space_size": fv_end - cursor,
    }
    return {"top_level_sections": top_sections, "firmware_volume": fv}, files, images


def parse_abl_origin(abl: bytes, inner: bytes) -> dict:
    require(abl[:4] == b"\x7fELF" and abl[4:6] == b"\x01\x01", "ABL is not ELF32 little-endian")
    entry = struct.unpack_from("<I", abl, 0x18)[0]
    program_offset = struct.unpack_from("<I", abl, 0x1C)[0]
    program_entry_size, program_count = struct.unpack_from("<HH", abl, 0x2A)
    programs = []
    for index in range(program_count):
        pos = program_offset + index * program_entry_size
        values = struct.unpack_from("<IIIIIIII", abl, pos)
        programs.append(
            {
                "index": index,
                "type": values[0],
                "file_offset": values[1],
                "virtual_address": values[2],
                "physical_address": values[3],
                "file_size": values[4],
                "memory_size": values[5],
                "flags": values[6],
                "alignment": values[7],
                "sha256": sha256(abl[values[1] : values[1] + values[4]]) if values[4] else sha256(b""),
            }
        )
    loads = [program for program in programs if program["type"] == 1]
    require(len(loads) == 1, "expected one ABL PT_LOAD segment")
    load = loads[0]
    fv_base = load["file_offset"]
    require(abl[fv_base + 0x28 : fv_base + 0x2C] == b"_FVH", "ABL outer FV missing")
    fv_size = struct.unpack_from("<Q", abl, fv_base + 0x20)[0]
    fv_header = struct.unpack_from("<H", abl, fv_base + 0x30)[0]
    require(fv_size == load["file_size"], "ABL FV does not match PT_LOAD")
    ffs_offset = fv_base + fv_header
    ffs_size = int.from_bytes(abl[ffs_offset + 20 : ffs_offset + 23], "little")
    section_offset = ffs_offset + 24
    guided = section_header(abl, section_offset, ffs_offset + ffs_size)
    require(guided["type"] == 0x02, "ABL payload is not GUID-defined")
    guided_guid = guid_text(abl[guided["payload_offset"] : guided["payload_offset"] + 16])
    data_offset, attributes = struct.unpack_from("<HH", abl, guided["payload_offset"] + 16)
    compressed_offset = section_offset + data_offset
    compressed_end = section_offset + guided["size"]
    compressed = abl[compressed_offset:compressed_end]
    decompressed = lzma.decompress(compressed, format=lzma.FORMAT_ALONE)
    require(decompressed == inner, "ABL LZMA payload does not equal analyzed inner FV stream")

    signature_programs = [
        program
        for program in programs
        if program["file_offset"] >= load["file_offset"] + load["file_size"]
        and program["file_size"]
    ]
    signature_strings = []
    for program in signature_programs:
        block = abl[program["file_offset"] : program["file_offset"] + program["file_size"]]
        for match in re.finditer(rb"[\x20-\x7e]{8,}", block):
            value = match.group().decode("ascii", "replace")
            if re.search(r"SignerVer|Samsung|S928B|SM-S928B|QKEY|SRPW", value):
                signature_strings.append(
                    {"file_offset": program["file_offset"] + match.start(), "value": value}
                )
    require(
        any("Samsung Electronics" in item["value"] for item in signature_strings),
        "ABL certificate metadata marker disappeared",
    )
    return {
        "elf_entry": entry,
        "program_headers": programs,
        "outer_fv": {
            "file_offset": fv_base,
            "size": fv_size,
            "ffs_guid": guid_text(abl[ffs_offset : ffs_offset + 16]),
            "ffs_offset": ffs_offset,
            "ffs_size": ffs_size,
            "ffs_type": abl[ffs_offset + 18],
            "guided_section_offset": section_offset,
            "guided_section_size": guided["size"],
            "guided_section_guid": guided_guid,
            "guided_data_offset": data_offset,
            "guided_attributes": attributes,
            "compression": "LZMA-alone",
            "compressed_offset": compressed_offset,
            "compressed_size": len(compressed),
            "compressed_sha256": sha256(compressed),
            "decompressed_size": len(decompressed),
            "decompressed_sha256": sha256(decompressed),
        },
        "signature_metadata_strings": signature_strings,
        "inner_payload_exact_match": True,
    }


def build_modules(inner: bytes, files: list[dict], images: dict[str, bytes]) -> list[dict]:
    modules = []
    executable_sections = []
    for ffs in files:
        for section in ffs["sections"]:
            if "executable" in section:
                executable_sections.append((ffs, section))
    require(len(executable_sections) == len(EXPECTED_MODULES), "unexpected executable count")
    for expected, (ffs, section) in zip(EXPECTED_MODULES, executable_sections, strict=True):
        name = ffs["ui_name"]
        image = images[name]
        require(name == expected["name"], f"unexpected module name {name}")
        require(ffs["type"] == 0x09, f"{name}: expected an FFS application")
        require(section["type"] == 0x10, f"{name}: expected a PE32 section")
        require(ffs["guid"] == expected["ffs_guid"], f"{name}: unexpected FFS GUID")
        require(ffs["offset"] == expected["ffs_offset"], f"{name}: unexpected FFS offset")
        require(section["payload_offset"] == expected["pe_offset"], f"{name}: unexpected PE offset")
        require(len(image) == expected["pe_size"], f"{name}: unexpected PE size")
        require(sha256(image) == expected["sha256"], f"{name}: unexpected PE hash")
        pe = section["executable"]
        require(pe["machine"] == 0xAA64, f"{name}: expected AARCH64")
        require(pe["entry_point_rva"] == 0x1000, f"{name}: unexpected entry point")
        protocols = {}
        for protocol_name, protocol in PROTOCOLS.items():
            raw = bytes.fromhex(protocol["raw"])
            literal_offsets = all_offsets(image, raw)
            protocols[protocol_name] = {
                "guid": protocol["guid"],
                "raw_bytes": protocol["raw"],
                "literal_pe_file_offsets": literal_offsets,
                "literal_pe_rvas": [file_to_rva(pe, item) for item in literal_offsets],
                "literal_fv_file_offsets": [section["payload_offset"] + item for item in literal_offsets],
                "direct_code_xrefs": [
                    {
                        **xref,
                        "adrp_pe_file_offset": rva_to_file_from_sections(pe["sections"], xref["adrp_rva"]),
                        "add_pe_file_offset": rva_to_file_from_sections(pe["sections"], xref["add_rva"]),
                        "adrp_radare2_va": xref["adrp_rva"] + 0x10000,
                        "add_radare2_va": xref["add_rva"] + 0x10000,
                    }
                    for xref in direct_guid_refs(image, pe, literal_offsets[0])
                ]
                if literal_offsets
                else [],
            }
        modules.append(
            {
                "name": name,
                "ffs_guid": ffs["guid"],
                "ffs_file_type": ffs["type_name"],
                "ffs_file_offset": ffs["offset"],
                "ffs_file_size": ffs["size"],
                "section_type": section["type_name"],
                "section_header_offset": section["offset"],
                "extracted_file_offset": section["payload_offset"],
                "extracted_size": len(image),
                "sha256": sha256(image),
                "image": pe,
                "relevant_strings": extract_relevant_strings(image, pe, section["payload_offset"]),
                "relevant_guid_constants": protocols,
            }
        )
    return modules


def excerpt(module_by_name: dict, name: str, start: int, end: int) -> list[dict]:
    module = module_by_name[name]
    return disassemble(module["_bytes"], module["image"], start, end)


def evidence_records(module_by_name: dict) -> list[dict]:
    specs = [
        {"id": "odin_memcard_handleprotocol", "module": "Odin", "protocol": "EFI_MEM_CARDINFO_PROTOCOL", "function_rva": None, "call_rva": 0xC3C4, "boot_service_slot": 0x98, "operation": "CONSUME_HANDLE_PROTOCOL", "ranges": [(0xC3A4, 0xC3CC)], "result_handling": "cbz x0 at 0xc3c8"},
        {"id": "odin_memcard_locate_1", "module": "Odin", "protocol": "EFI_MEM_CARDINFO_PROTOCOL", "function_rva": 0xD1B8, "call_rva": 0xD340, "boot_service_slot": 0x140, "operation": "CONSUME_LOCATE_PROTOCOL", "ranges": [(0xD314, 0xD34C)], "result_handling": "cbz x0 at 0xd344"},
        {"id": "odin_memcard_locate_2", "module": "Odin", "protocol": "EFI_MEM_CARDINFO_PROTOCOL", "function_rva": 0x10284, "call_rva": 0x102D4, "boot_service_slot": 0x140, "operation": "CONSUME_LOCATE_PROTOCOL", "ranges": [(0x102B4, 0x102DC)], "result_handling": "tbnz EFI_ERROR bit at 0x102d8"},
        {"id": "linuxloader_memcard_edge_b", "module": "LinuxLoader", "protocol": "EFI_MEM_CARDINFO_PROTOCOL", "function_rva": 0x9240, "call_rva": 0x93E4, "boot_service_slot": 0x140, "operation": "CONSUME_LOCATE_PROTOCOL", "ranges": [(0x93C4, 0x93F8)], "result_handling": "tbnz x0,#63 at 0x93f0 branches to 0x9420 on EFI_ERROR"},
        {"id": "linuxloader_memcard_secondary", "module": "LinuxLoader", "protocol": "EFI_MEM_CARDINFO_PROTOCOL", "function_rva": 0x12AD4, "call_rva": 0x12B24, "boot_service_slot": 0x140, "operation": "CONSUME_LOCATE_PROTOCOL", "ranges": [(0x12B04, 0x12B30)], "result_handling": "tbnz EFI_ERROR bit at 0x12b28"},
        {"id": "questusb_memcard_locate", "module": "QuestUSB", "protocol": "EFI_MEM_CARDINFO_PROTOCOL", "function_rva": 0x6114, "call_rva": 0x633C, "boot_service_slot": 0x140, "operation": "CONSUME_LOCATE_PROTOCOL", "ranges": [(0x631C, 0x6348)], "result_handling": "tbnz EFI_ERROR bit at 0x6340"},
        {"id": "linuxloader_vb_deviceinfo_rw", "module": "LinuxLoader", "protocol": "VB_PROTOCOL", "function_rva": 0xFF30, "call_rva": 0xFF74, "boot_service_slot": 0x140, "operation": "CONSUME_LOCATE_PROTOCOL_THEN_VBRWDEVICE_PLUS_8", "ranges": [(0x425F8, 0x42628), (0xFF40, 0xFFC0), (0x10AAC, 0x10AB8)], "result_handling": "DeviceInfoInit passes op=0, live buffer, size=0xcd0 at 0x4261c; interface+8 called at 0xffb4"},
        {"id": "linuxloader_vb_direct_locate", "module": "LinuxLoader", "protocol": "VB_PROTOCOL", "function_rva": 0x140DC, "call_rva": 0x14A4C, "boot_service_slot": 0x140, "operation": "CONSUME_LOCATE_PROTOCOL", "ranges": [(0x14A2C, 0x14A54)], "result_handling": "cbz status at 0x14a50"},
        {"id": "linuxloader_blockio_enumeration", "module": "LinuxLoader", "protocol": "EFI_BLOCK_IO_PROTOCOL", "function_rva": 0xF520, "call_rva": 0xF5B4, "boot_service_slot": 0x138, "operation": "CONSUME_LOCATE_HANDLE_BUFFER", "ranges": [(0xF55C, 0xF5BC), (0x11090, 0x110D4)], "result_handling": "LocateHandleBuffer selects BlockIo or SimpleFileSystem by flags; HandleProtocol resolves BlockIo at 0x110ac"},
    ]
    records = []
    for spec in specs:
        ranges = spec.pop("ranges")
        disassembly = [
            {"start_rva": start, "end_rva": end, "instructions": excerpt(module_by_name, spec["module"], start, end)}
            for start, end in ranges
        ]
        records.append({**spec, "boot_service": GBS_SLOTS[spec["boot_service_slot"]], "disassembly": disassembly})
    return records


def verify_protocol_evidence(modules: list[dict], evidence: list[dict]) -> None:
    by_name = {module["name"]: module for module in modules}
    expected_memcard_direct = {"Odin": [0xC3C0, 0xD33C, 0x102D0], "LinuxLoader": [0x93E0, 0x12B20], "Cryptest": [], "QuestSOD": [], "QuestUSB": [0x6338]}
    expected_vb_direct = {"Odin": [], "LinuxLoader": [0x14A48], "Cryptest": [], "QuestSOD": [], "QuestUSB": []}
    expected_blockio_direct = {
        "Odin": [0xF4E4, 0xF554],
        "LinuxLoader": [0xF5A4, 0xF614, 0x10C10, 0x110A8],
        "Cryptest": [],
        "QuestSOD": [0x55DC],
        "QuestUSB": [0x6938, 0x69A8],
    }
    expected_literal_modules = {
        "EFI_MEM_CARDINFO_PROTOCOL": {"Odin", "LinuxLoader", "QuestUSB"},
        "VB_PROTOCOL": {"Odin", "LinuxLoader"},
        "EFI_BLOCK_IO_PROTOCOL": {"Odin", "LinuxLoader", "QuestSOD", "QuestUSB"},
    }
    for protocol, expected_names in expected_literal_modules.items():
        actual = {module["name"] for module in modules if module["relevant_guid_constants"][protocol]["literal_pe_file_offsets"]}
        require(actual == expected_names, f"{protocol}: literal module set changed: {actual}")
    for name, expected in expected_memcard_direct.items():
        refs = by_name[name]["relevant_guid_constants"]["EFI_MEM_CARDINFO_PROTOCOL"]["direct_code_xrefs"]
        actual = [item["add_rva"] for item in refs]
        require(actual == expected, f"{name}: MemCardInfo direct xrefs changed: {actual}")
    for name, expected in expected_vb_direct.items():
        refs = by_name[name]["relevant_guid_constants"]["VB_PROTOCOL"]["direct_code_xrefs"]
        actual = [item["add_rva"] for item in refs]
        require(actual == expected, f"{name}: VB direct xrefs changed: {actual}")
    for name, expected in expected_blockio_direct.items():
        refs = by_name[name]["relevant_guid_constants"]["EFI_BLOCK_IO_PROTOCOL"]["direct_code_xrefs"]
        actual = [item["add_rva"] for item in refs]
        require(actual == expected, f"{name}: BlockIo direct xrefs changed: {actual}")

    edge = next(item for item in evidence if item["id"] == "linuxloader_memcard_edge_b")
    text = "\n".join(f"{insn['mnemonic']} {insn['operands']}" for part in edge["disassembly"] for insn in part["instructions"])
    for required in ("ldr x8, [x8, #0x140]", "add x0, x0, #0xe40", "blr x8", "tbnz x0, #0x3f, #0x9420"):
        require(required in text, f"Edge B instruction disappeared: {required}")

    vb = next(item for item in evidence if item["id"] == "linuxloader_vb_deviceinfo_rw")
    text = "\n".join(f"{insn['mnemonic']} {insn['operands']}" for part in vb["disassembly"] for insn in part["instructions"])
    for required in (
        "mov w2, #0xcd0",
        "mov w0, wzr",
        "bl #0xff30",
        "ldr x8, [x8, #0x140]",
        "add x0, x0, #0xf80",
        "ldr x8, [x0, #8]",
        "blr x8",
    ):
        require(required in text, f"DeviceInfo VB instruction disappeared: {required}")
    strings = {item["value"] for item in by_name["LinuxLoader"]["relevant_strings"]}
    require("Unable to locate VB protocol: %r\n" in strings, "VB protocol error string disappeared")
    require("VBRwDevice failed with: %r\n" in strings, "VBRwDevice error string disappeared")

    blockio = next(item for item in evidence if item["id"] == "linuxloader_blockio_enumeration")
    text = "\n".join(
        f"{insn['mnemonic']} {insn['operands']}"
        for part in blockio["disassembly"]
        for insn in part["instructions"]
    )
    for required in (
        "ldr x8, [x9, #0x138]",
        "add x11, x11, #0xdb0",
        "csel x1, x11, x10, eq",
        "ldr x8, [x8, #0x98]",
        "add x1, x1, #0xdb0",
    ):
        require(required in text, f"BlockIo consumer instruction disappeared: {required}")


def format_disassembly(parts: list[dict], indent: str = "    ") -> list[str]:
    lines = []
    for part in parts:
        lines.append(f"{indent}range actual PE RVA 0x{part['start_rva']:x}..0x{part['end_rva']:x}")
        for insn in part["instructions"]:
            lines.append(
                f"{indent}  RVA 0x{insn['rva']:06x} PE+0x{insn['pe_file_offset']:06x} "
                f"r2VA 0x{insn['radare2_va']:06x}  {insn['mnemonic']:<8} {insn['operands']}"
            )
    return lines


def render_report(inner: bytes, abl: bytes, inventory: dict, files: list[dict], modules: list[dict], evidence: list[dict], origin: dict) -> str:
    by_id = {item["id"]: item for item in evidence}
    certificate_program = next(
        item
        for item in origin["program_headers"]
        if item["file_offset"] >= origin["outer_fv"]["file_offset"] + origin["outer_fv"]["size"]
        and item["file_size"]
    )
    certificate_marker = next(
        item for item in origin["signature_metadata_strings"] if "Samsung Electronics" in item["value"]
    )
    lines = []

    def heading(number: int, title: str) -> None:
        lines.extend(["=" * 80, f"{number}. {title}", "=" * 80, ""])

    heading(1, "EXECUTIVE CONCLUSION")
    lines.extend([
        "Static answer: NOT ESTABLISHED by this artifact.",
        "",
        "The inner FV contains five EFI applications and zero DXE/UEFI drivers. Every",
        "code xref to EFI_MEM_CARDINFO_PROTOCOL is a HandleProtocol or LocateProtocol",
        "consumer. No target InstallProtocolInterface, ReinstallProtocolInterface, or",
        "InstallMultipleProtocolInterfaces call is present. The VB protocol used for",
        "DeviceInfo is also consumed, not produced, here.",
        "",
        "LinuxLoader can consume a pre-existing protocol registry state in which",
        "MemCardInfo is absent and the VB protocol remains present. The code explicitly",
        "handles that state. The inner FV does not show whether the earlier UEFI firmware",
        "can actually create it. Producer initialization, ordering, and failure branches",
        "are outside this FV. The signed abl.img contains no other loadable payload.",
        "",
        "Important correction: 8e5eff91-21b6-47d3-af2b-c15a01e020ec is evidenced as",
        "the VB protocol used by VBRwDevice, not EFI_BLOCK_IO_PROTOCOL. Standard BlockIo",
        "is a separate GUID, 964e5b21-6459-11d2-8e39-00a0c969723b, and is used for",
        "partition handles. This leaves the availability relationship unresolved rather",
        "than proving that both protocols fail together.",
        "",
        "No persistent HLOS-writable condition controlling MemCardInfo publication was",
        "found. Edge B and Chain A therefore remain THEORETICAL.",
        "",
    ])

    heading(2, "INPUT HASHES")
    lines.extend([
        f"decompiled/abl-inner-oneui8.fv.bin size=0x{len(inner):x}",
        f"  sha256={sha256(inner)}",
        f"partitions/abl.img size=0x{len(abl):x}",
        f"  sha256={sha256(abl)}",
        "",
        "The analyzer refuses to run if either hash changes.",
        "",
    ])

    heading(3, "FIRMWARE-VOLUME INVENTORY")
    for section in inventory["top_level_sections"]:
        lines.append(f"input section file=0x{section['offset']:x} type=0x{section['type']:02x} {section['type_name']} size=0x{section['size']:x} payload=0x{section['payload_offset']:x}")
    fv = inventory["firmware_volume"]
    ext = fv["extension_header"]
    lines.extend([
        "",
        f"FV file offset=0x{fv['file_offset']:x} size=0x{fv['size']:x}",
        f"  filesystem GUID={fv['filesystem_guid']}",
        f"  header length=0x{fv['header_length']:x} checksum valid={fv['checksum_valid']}",
        f"  extension header=0x{ext['offset']:x}+0x{ext['size']:x} name GUID={ext['fv_name_guid']}",
        f"  FFS start=0x{fv['ffs_start_offset']:x}",
        f"  free space=0x{fv['free_space_offset']:x}+0x{fv['free_space_size']:x}",
        "",
        f"FFS files={len(files)} PE32 sections={len(modules)} TE sections=0",
        "raw FFS sections=0 GUID-defined FFS sections=0 compressed FFS sections=0",
        "nested firmware volumes inside this FV=0",
        "",
    ])
    for ffs in files:
        lines.append(f"FFS file=0x{ffs['offset']:x} size=0x{ffs['size']:x} guid={ffs['guid']} type=0x{ffs['type']:02x} {ffs['type_name']} UI={ffs['ui_name']}")
        for section in ffs["sections"]:
            lines.append(f"  section=0x{section['offset']:x} type=0x{section['type']:02x} {section['type_name']} size=0x{section['size']:x} payload=0x{section['payload_offset']:x}+0x{section['payload_size']:x}")
    lines.append("")

    heading(4, "DXE/FFS MODULE MAP")
    lines.append("All five executables are EFI applications. None is an FFS DRIVER or DXE_DRIVER.")
    lines.append("")
    for module in modules:
        image = module["image"]
        lines.extend([
            f"{module['name']}",
            f"  FFS GUID={module['ffs_guid']} file=0x{module['ffs_file_offset']:x}",
            f"  file type={module['ffs_file_type']} section={module['section_type']}",
            f"  extracted=0x{module['extracted_file_offset']:x}+0x{module['extracted_size']:x}",
            f"  machine=0x{image['machine']:04x} {image['machine_name']} entry RVA=0x{image['entry_point_rva']:x}",
            f"  image base=0x{image['image_base']:x} sha256={module['sha256']}",
            f"  PDB={image['pdb_path']}",
        ])
        for section in image["sections"]:
            lines.append(f"  PE section {section['name']} file=0x{section['file_offset']:x}+0x{section['raw_size']:x} RVA=0x{section['rva']:x}+0x{section['virtual_size']:x} executable={section['executable']}")
        relevant = module["relevant_strings"][:16]
        if relevant:
            lines.append("  selected relevant strings:")
            for item in relevant:
                lines.append(f"    PE+0x{item['pe_file_offset']:x} FV+0x{item['fv_file_offset']:x} {item['encoding']} {item['value']!r}")
        else:
            lines.append("  selected relevant strings: none")
        lines.append("")

    heading(5, "EFI_MEM_CARDINFO_PROTOCOL PRODUCER")
    mem = PROTOCOLS["EFI_MEM_CARDINFO_PROTOCOL"]
    mem_offsets = all_offsets(inner, bytes.fromhex(mem["raw"]))
    lines.extend([
        f"GUID canonical={mem['guid']}",
        f"GUID raw EFI bytes={mem['raw']}",
        f"input offsets={', '.join(f'0x{x:x}' for x in mem_offsets)}",
        "",
        "Code xrefs:",
    ])
    for item in evidence:
        if item["protocol"] != "EFI_MEM_CARDINFO_PROTOCOL":
            continue
        lines.append(f"  {item['module']} function={hex(item['function_rva']) if item['function_rva'] is not None else 'boundary unresolved'} call=0x{item['call_rva']:x} {item['operation']} gBS+0x{item['boot_service_slot']:x} {item['boot_service']} result={item['result_handling']}")
    lines.extend([
        "",
        "Producer result: NOT PRESENT IN THE INNER FV.",
        "All six proven code references are consumers. No installation claim is inferred",
        "from the GUID literals alone. The Odin and LinuxLoader GUID arrays are linked",
        "constant tables, not protocol install tables.",
        "",
        "Independently checkable Edge B call site:",
    ])
    lines.extend(format_disassembly(by_id["linuxloader_memcard_edge_b"]["disassembly"]))
    lines.append("")

    heading(6, "DEVICEINFO STORAGE PROTOCOL PRODUCER")
    vb = PROTOCOLS["VB_PROTOCOL"]
    block = PROTOCOLS["EFI_BLOCK_IO_PROTOCOL"]
    simple = PROTOCOLS["EFI_SIMPLE_FILE_SYSTEM_PROTOCOL"]
    linuxloader = next(module for module in modules if module["name"] == "LinuxLoader")
    vb_strings = {
        item["value"]: item
        for item in linuxloader["relevant_strings"]
        if item["value"] in ("Unable to locate VB protocol: %r\n", "VBRwDevice failed with: %r\n")
    }
    lines.extend([
        "DeviceInfo persistence transport:",
        f"  canonical GUID={vb['guid']}",
        f"  raw EFI bytes={vb['raw']}",
        f"  input offsets={', '.join(f'0x{x:x}' for x in all_offsets(inner, bytes.fromhex(vb['raw'])))}",
        "  LinuxLoader strings name the interface as VB protocol and its method as VBRwDevice.",
        *(
            f"  string PE+0x{item['pe_file_offset']:x} FV+0x{item['fv_file_offset']:x} {value!r}"
            for value, item in sorted(vb_strings.items())
        ),
        "  Function 0xff30 locates it and calls interface+0x08 with operation, buffer, size.",
        "  DeviceInfoInit calls 0xff30 at 0x4261c with op=0, live buffer, size=0xcd0.",
        "",
        "Boot partition transport:",
        f"  EFI_BLOCK_IO_PROTOCOL canonical GUID={block['guid']}",
        f"  raw EFI bytes={block['raw']}",
        f"  input offsets={', '.join(f'0x{x:x}' for x in all_offsets(inner, bytes.fromhex(block['raw'])))}",
        f"  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL canonical GUID={simple['guid']}",
        f"  raw EFI bytes={simple['raw']}",
        f"  input offsets={', '.join(f'0x{x:x}' for x in all_offsets(inner, bytes.fromhex(simple['raw'])))}",
        "  GetBlkIOHandles at 0xf520 selects BlockIo or SimpleFileSystem and calls",
        "  gBS->LocateHandleBuffer at slot 0x138. Partition reads then use BlockIo handles.",
        "",
        "The old 225b4e96... raw value is SimpleFileSystem, not BlockIo. The actual",
        "BlockIo raw value starts 215b4e96....",
        "",
        "Producer result: neither VB protocol nor BlockIo is produced by this FV.",
        "Their exact producer modules, prerequisites, and common controller dependency",
        "cannot be recovered from these five applications.",
        "",
        "Reference classification:",
        "  VB: Odin contains a linked literal with no direct code xref. LinuxLoader uses",
        "  LocateProtocol at 0x14a4c and through the 0x10aac wrapper used by 0xff30.",
        "  BlockIo: Odin 0xf4e4/0xf554, LinuxLoader 0xf5a4/0xf614/0x10c10/0x110a8,",
        "  QuestSOD 0x55dc, and QuestUSB 0x6938/0x69a8 are LocateHandleBuffer or",
        "  HandleProtocol consumers. Cryptest has no literal. None feeds gBS+0x80,",
        "  gBS+0x88, or gBS+0x148.",
        "",
        "DeviceInfo LocateProtocol and VBRwDevice evidence:",
    ])
    lines.extend(format_disassembly(by_id["linuxloader_vb_deviceinfo_rw"]["disassembly"]))
    lines.extend(["", "BlockIo LocateHandleBuffer evidence:"])
    lines.extend(format_disassembly(by_id["linuxloader_blockio_enumeration"]["disassembly"]))
    lines.append("")

    heading(7, "PROTOCOL DEPENDENCY GRAPH")
    lines.extend([
        "[earlier UEFI firmware, producer binaries missing]",
        "  |",
        "  +-> installs EFI_MEM_CARDINFO_PROTOCOL ---------+",
        "  |                                                 |",
        "  +-> installs VB protocol ----------------+        |",
        "  |                                         |        |",
        "  +-> installs EFI_BLOCK_IO_PROTOCOL --+    |        |",
        "                                     |    |        |",
        "                                     v    v        v",
        "                              [LinuxLoader application]",
        "                                     |    |        |",
        "                                     |    |        +-> Edge B LocateProtocol gate",
        "                                     |    +-> VBRwDevice -> DeviceInfo",
        "                                     +-> BlockIo handles -> boot/vbmeta partitions",
        "",
        "The three protocol GUIDs and interfaces are distinct. The producer side cannot be",
        "expanded to UFS controller initialization because no producer driver is in the inner",
        "FV, and the containing abl.img has no other loadable payload.",
        "",
        "Architecture classification: UNRESOLVED.",
        "Inside this FV they are installed by neither the same path nor different paths.",
        "They are already expected to exist when the applications run.",
        "",
    ])

    heading(8, "MEMCARDINFO INSTALLATION CONDITIONS")
    lines.extend([
        "No MemCardInfo installation function exists in the audited inner FV. Therefore no valid",
        "predecessor list for MemCardInfo publication can be produced from this artifact.",
        "The following requested provenance classes are all unresolved at the producer:",
        "HARDWARE_ONLY, FIRMWARE_INTERNAL, UEFI_VARIABLE, PARTITION_DATA,",
        "GPT / STORAGE_METADATA, DEVICE_TREE / CONFIG, PERSISTENT_HLOS_WRITABLE.",
        "",
        "The only proven condition visible here is consumer-side:",
        "  function 0x9240, call 0x93e4, branch 0x93f0",
        "  control value: EFI_STATUS returned by gBS->LocateProtocol",
        "  provenance: UEFI protocol database and prior-firmware behavior",
        "  classification: UNKNOWN",
        "",
    ])

    heading(9, "MEMCARDINFO FAILURE PATHS")
    lines.extend([
        "Observed path MC-1:",
        "  gBS->LocateProtocol(EFI_MEM_CARDINFO_PROTOCOL_GUID, NULL, &interface)",
        "  returns any EFI_ERROR status at 0x93e4; 0x93f0 branches to 0x9420.",
        "  This prevents use, not installation. It does not reveal why publication failed.",
        "  controlling provenance: UNKNOWN / prior UEFI firmware.",
        "",
        "No inner-FV path calls UninstallProtocolInterface for this GUID. No branch in",
        "the inner FV conditionally installs it. Inventing descriptor, LUN, GPT, variable,",
        "or hardware failure branches without the producer would be fiction, so none are",
        "listed as findings.",
        "",
    ])

    heading(10, "STORAGE-SURVIVAL ANALYSIS FOR EACH FAILURE")
    lines.extend([
        "MC-1: LocateProtocol returns EFI_ERROR",
        "  VB protocol survival: UNKNOWN from producer-side evidence.",
        "  EFI_BLOCK_IO_PROTOCOL survival: UNKNOWN from producer-side evidence.",
        "  Consumer-level compatibility: YES. The branch does not uninstall or mutate",
        "  VB or BlockIo, and LinuxLoader's error path later calls DeviceInfoInit.",
        "  The code therefore admits MemCardInfo missing plus VB present.",
        "  Initialization reachability on this device: UNKNOWN.",
        "  required classification: UNKNOWN.",
        "",
        "BOTH_DEAD cannot be proved because MemCardInfo and VB are separate protocols and",
        "the producer graph is absent. MEMCARDINFO_ONLY_FAILURE cannot be proved for the",
        "same reason. No ORDERING_WINDOW_ONLY path is visible in this FV.",
        "",
    ])

    heading(11, "ROOT-STAGEABILITY")
    lines.extend([
        "No UEFI variable, GPT field, partition byte, device-tree property, or other",
        "persistent HLOS-writable value was found controlling MemCardInfo availability.",
        "That is a scope result, not proof that no such control exists in the missing",
        "producer firmware.",
        "",
        "MC-1 trigger classification: UNKNOWN.",
        "Temporary Android root has no demonstrated way to prepare it for the next boot.",
        "It is therefore not promoted to POTENTIALLY_ROOT_STAGEABLE or ROOT_STAGEABLE.",
        "",
        "Inner-FV patch side question:",
        f"  abl.img PT_LOAD/FV=0x{origin['outer_fv']['file_offset']:x}+0x{origin['outer_fv']['size']:x}",
        f"  guided LZMA section=0x{origin['outer_fv']['guided_section_offset']:x}",
        f"  decompressed payload sha256={origin['outer_fv']['decompressed_sha256']}",
        "  This payload exactly equals the analyzed inner FV stream.",
        f"  certificate/signature region=0x{certificate_program['file_offset']:x}+0x{certificate_program['file_size']:x}",
        f"  certificate marker=0x{certificate_marker['file_offset']:x} 'Samsung Electronics Co., Ltd.'",
        "  Patching the FV changes the signed ABL payload and is outside the threat model.",
        "  Classification: DEAD END.",
        "",
    ])

    heading(12, "REVISED CHAIN A VERDICT")
    lines.extend([
        "Edge A: ROOT-STAGEABLE (previously established)",
        "Edge B: THEORETICAL",
        "Edge C: CONFIRMED within audited LinuxLoader (previously established)",
        "",
        "Chain A: THEORETICAL",
        "",
        "The inner FV proves the consumer error route but contains no producer evidence",
        "that makes the required protocol state reachable, persistent, or root-stageable.",
        "",
    ])

    heading(13, "REMAINING EXTERNAL ASSUMPTIONS")
    lines.extend([
        "1. Earlier UEFI firmware installs MemCardInfo, VB, and BlockIo before launching",
        "   applications from the ABL guided FV during a normal boot.",
        "2. The missing producer firmware determines whether MemCardInfo can fail without",
        "   taking VB/VBRwDevice or BlockIo down.",
        "3. Static ABL artifacts do not prove which persistent inputs, if any, gate that",
        "   producer behavior.",
        "4. Signature enforcement for the signed ABL ELF occurs in the prior boot stage;",
        "   the artifact contains the signed metadata but that verifier is not collected.",
        "",
    ])

    heading(14, "HIGHEST-VALUE MISSING ARTIFACT")
    lines.extend([
        "First: the matching S928BXXU5DZDP uefi partition image. The device inventory",
        "records /dev/block/sdd21, size 0x500000, sha256",
        "7cb98e7804f76f27d0b9d5487a13d0cd7354c4ef4d4c6b7b5582befcc4eb727f,",
        "but the partition bytes were not collected. It is the narrowest firmware artifact",
        "named for the missing UEFI environment.",
        "",
        "If uefi.img lacks the producers, collect the matching active-slot xbl and",
        "xbl_config images next. The device inventory has their block-device symlinks but",
        "the repository contains neither image.",
        "",
        "The required next audit is narrow: locate the three exact GUID byte sequences in",
        "the missing firmware volumes, recover their installer call sites, and compare every",
        "MemCardInfo-skipping predecessor against VB and BlockIo publication. Until then,",
        "the critical state remains UNKNOWN and Chain A remains THEORETICAL.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    inputs = {}
    for path, expected_hash in EXPECTED_INPUT_HASHES.items():
        data = path.read_bytes()
        actual_hash = sha256(data)
        require(actual_hash == expected_hash, f"{path}: expected {expected_hash}, got {actual_hash}")
        inputs[path] = data
    inner = inputs[INNER_PATH]
    abl = inputs[ABL_PATH]

    inventory, files, images = parse_inner(inner)
    modules = build_modules(inner, files, images)
    module_by_name = {module["name"]: {**module, "_bytes": images[module["name"]]} for module in modules}
    evidence = evidence_records(module_by_name)
    verify_protocol_evidence(modules, evidence)
    origin = parse_abl_origin(abl, inner)

    protocol_occurrences = {}
    for name, protocol in PROTOCOLS.items():
        protocol_occurrences[name] = {**protocol, "input_file_offsets": all_offsets(inner, bytes.fromhex(protocol["raw"]))}

    modules_output = {
        "schema_version": 2,
        "address_notation": {
            "input_file_offset": "offset in decompiled/abl-inner-oneui8.fv.bin",
            "pe_file_offset": "offset from extracted PE image start",
            "pe_rva": "PE virtual address relative to ImageBase 0",
            "radare2_va": "repository radare2 convention: PE RVA + 0x10000",
        },
        "inputs": [{"path": str(path.relative_to(ROOT)), "size": len(data), "sha256": sha256(data)} for path, data in inputs.items()],
        "inventory": inventory,
        "ffs_files": files,
        "executables": modules,
    }
    graph_output = {
        "schema_version": 2,
        "inputs": modules_output["inputs"],
        "protocols": protocol_occurrences,
        "callsites": evidence,
        "additional_reference_classification": [
            {"module": "Odin", "protocol": "VB_PROTOCOL", "literal_pe_file_offset": 0x89D18, "operation": "NO_DIRECT_CODE_XREF"},
            {"module": "LinuxLoader", "protocol": "VB_PROTOCOL", "guid_add_rva": 0x10AB0, "operation": "LOCATE_PROTOCOL_WRAPPER", "callers": [0xFF74, 0x10614, 0x10708]},
            {"module": "Odin", "protocol": "EFI_BLOCK_IO_PROTOCOL", "guid_add_rvas": [0xF4E4, 0xF554], "operation": "LOCATE_HANDLE_BUFFER_OR_HANDLE_PROTOCOL"},
            {"module": "LinuxLoader", "protocol": "EFI_BLOCK_IO_PROTOCOL", "guid_add_rvas": [0xF5A4, 0xF614, 0x10C10, 0x110A8], "operation": "LOCATE_HANDLE_BUFFER_OR_HANDLE_PROTOCOL"},
            {"module": "QuestSOD", "protocol": "EFI_BLOCK_IO_PROTOCOL", "guid_add_rvas": [0x55DC], "operation": "LOCATE_HANDLE_BUFFER"},
            {"module": "QuestUSB", "protocol": "EFI_BLOCK_IO_PROTOCOL", "guid_add_rvas": [0x6938, 0x69A8], "operation": "LOCATE_HANDLE_BUFFER_OR_HANDLE_PROTOCOL"},
        ],
        "architecture": {"classification": "UNRESOLVED", "inner_fv_installers": [], "inner_fv_file_types": sorted({item["type_name"] for item in files}), "producer_scope": "earlier UEFI firmware, not collected"},
        "nodes": [
            {"id": "prior_uefi", "kind": "MISSING_PRODUCER_FIRMWARE"},
            {"id": "memcard", "kind": "PROTOCOL", "guid": PROTOCOLS["EFI_MEM_CARDINFO_PROTOCOL"]["guid"]},
            {"id": "vb", "kind": "PROTOCOL", "guid": PROTOCOLS["VB_PROTOCOL"]["guid"]},
            {"id": "blockio", "kind": "PROTOCOL", "guid": PROTOCOLS["EFI_BLOCK_IO_PROTOCOL"]["guid"]},
            {"id": "linuxloader", "kind": "EFI_APPLICATION"},
            {"id": "deviceinfo", "kind": "PERSISTED_DATA"},
            {"id": "boot_partitions", "kind": "PERSISTED_DATA"},
        ],
        "edges": [
            {"from": "prior_uefi", "to": "memcard", "relation": "installs", "status": "UNKNOWN"},
            {"from": "prior_uefi", "to": "vb", "relation": "installs", "status": "UNKNOWN"},
            {"from": "prior_uefi", "to": "blockio", "relation": "installs", "status": "UNKNOWN"},
            {"from": "linuxloader", "to": "memcard", "relation": "LocateProtocol", "status": "CONFIRMED"},
            {"from": "linuxloader", "to": "vb", "relation": "LocateProtocol/VBRwDevice", "status": "CONFIRMED"},
            {"from": "vb", "to": "deviceinfo", "relation": "read/write", "status": "CONFIRMED_AT_CONSUMER"},
            {"from": "linuxloader", "to": "blockio", "relation": "LocateHandleBuffer/HandleProtocol", "status": "CONFIRMED"},
            {"from": "blockio", "to": "boot_partitions", "relation": "read", "status": "CONFIRMED_AT_CONSUMER"},
        ],
        "memcard_failure_paths": [{"id": "MC-1", "condition": "LinuxLoader LocateProtocol returns EFI_ERROR", "function_rva": 0x9240, "call_rva": 0x93E4, "branch_rva": 0x93F0, "controller_provenance": "UNKNOWN_PRIOR_UEFI", "storage_survival": "UNKNOWN", "root_stageability": "UNKNOWN"}],
        "missing_artifacts": [
            {"priority": 1, "name": "uefi.img", "expected_size": 0x500000, "device_recorded_sha256": "7cb98e7804f76f27d0b9d5487a13d0cd7354c4ef4d4c6b7b5582befcc4eb727f"},
            {"priority": 2, "name": "xbl", "expected_size": None, "device_recorded_sha256": None},
            {"priority": 3, "name": "xbl_config", "expected_size": None, "device_recorded_sha256": None},
        ],
        "revised_chain_a_verdict": "THEORETICAL",
        "abl_origin": origin,
    }

    report = render_report(inner, abl, inventory, files, modules, evidence, origin)
    OUT_MODULES.write_text(json.dumps(modules_output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    OUT_GRAPH.write_text(json.dumps(graph_output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    OUT_REPORT.write_text(report, encoding="utf-8")
    for path in (OUT_MODULES, OUT_GRAPH, OUT_REPORT):
        payload = path.read_bytes()
        print(f"{path.relative_to(ROOT)} size={len(payload)} sha256={sha256(payload)}")


if __name__ == "__main__":
    main()
