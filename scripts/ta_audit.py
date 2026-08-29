#!/usr/bin/env python3
"""Emit reproducible, read-only evidence from the Engineering Mode TA.

The Qualcomm trustlet is an ELF without section headers.  This script maps
virtual addresses through PT_LOAD, decodes its SYSV dynamic symbol table and
prints selected AArch64 regions.  It never opens a device and never modifies
the input image.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IMAGE = ROOT / "partitions" / "em.img"
OUT = ROOT / "decompiled"
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def resolve_image() -> tuple[Path, Path]:
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--image", type=Path, default=DEFAULT_IMAGE)
    parser.add_argument("--out", type=Path, default=OUT)
    args, _ = parser.parse_known_args()
    return args.image.resolve(), args.out


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Trustlet:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            self.header = dict(elf.header)
            self.segments = [dict(segment.header) for segment in elf.iter_segments()]
        self.loads = [s for s in self.segments if s["p_type"] == "PT_LOAD"]
    def va_to_file(self, va: int) -> int:
        for segment in self.loads:
            start = int(segment["p_vaddr"])
            size = int(segment["p_filesz"])
            if start <= va < start + size:
                return int(segment["p_offset"]) + va - start
        raise ValueError(f"VA 0x{va:x} is not file-backed")

    def file_to_va(self, offset: int) -> int:
        for segment in self.loads:
            start = int(segment["p_offset"])
            size = int(segment["p_filesz"])
            if start <= offset < start + size:
                return int(segment["p_vaddr"]) + offset - start
        raise ValueError(f"file offset 0x{offset:x} is not in PT_LOAD")

    def unpack_va(self, fmt: str, va: int):
        return struct.unpack_from(fmt, self.data, self.va_to_file(va))

    def dynamic(self) -> dict[int, int]:
        dynamic = next(s for s in self.segments if s["p_type"] == "PT_DYNAMIC")
        result: dict[int, int] = {}
        offset = int(dynamic["p_offset"])
        end = offset + int(dynamic["p_filesz"])
        while offset + 16 <= end:
            tag, value = struct.unpack_from("<QQ", self.data, offset)
            offset += 16
            if tag == 0:
                break
            result[tag] = value
        return result

    def symbols_and_plt(self):
        # ELF tags: HASH=4, STRTAB=5, SYMTAB=6, SYMENT=11,
        # PLTRELSZ=2, JMPREL=23, RELAENT=9.
        dyn = self.dynamic()
        hash_file = self.va_to_file(dyn[4])
        _nbucket, nchain = struct.unpack_from("<II", self.data, hash_file)
        sym_file = self.va_to_file(dyn[6])
        str_file = self.va_to_file(dyn[5])
        syment = dyn[11]
        symbols = []
        for index in range(nchain):
            at = sym_file + index * syment
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                "<IBBHQQ", self.data, at
            )
            name_at = str_file + st_name
            name_end = self.data.find(b"\0", name_at)
            name = self.data[name_at:name_end].decode("ascii", "backslashreplace")
            symbols.append((name, st_value, st_size, st_info, st_shndx))

        rela_file = self.va_to_file(dyn[23])
        rela_count = dyn[2] // dyn[9]
        plt = []
        for index in range(rela_count):
            r_offset, r_info, r_addend = struct.unpack_from(
                "<QQq", self.data, rela_file + index * dyn[9]
            )
            sym_index = r_info >> 32
            # This sectionless trustlet has one 16-byte veneer per relocation,
            # beginning at VA 0x20 (verified against each veneer GOT offset).
            plt_va = 0x20 + index * 0x10
            plt.append((plt_va, r_offset, r_info & 0xFFFFFFFF, r_addend, symbols[sym_index][0]))
        return symbols, plt

    def disasm(self, start: int, end: int) -> list[str]:
        file_start = self.va_to_file(start)
        raw = self.data[file_start : file_start + (end - start)]
        return [
            (
                f"  VA 0x{insn.address:06x}  file 0x{self.va_to_file(insn.address):06x}  "
                f"{insn.mnemonic:<8} {insn.op_str}"
            ).rstrip()
            for insn in MD.disasm(raw, start)
        ]

    def string_offsets(self, needle: bytes) -> list[tuple[int | None, int]]:
        result = []
        cursor = 0
        while True:
            cursor = self.data.find(needle, cursor)
            if cursor < 0:
                break
            try:
                va = self.file_to_va(cursor)
            except ValueError:
                va = None
            result.append((va, cursor))
            cursor += 1
        return result


TA: Trustlet | None = None


def metadata(ta: Trustlet) -> list[str]:
    lines = [
        f"INPUT {ta.path.relative_to(ROOT)}",
        f"SIZE {ta.path.stat().st_size}",
        f"SHA256 {sha256(ta.path)}",
        "FORMAT ELF64 little-endian AArch64 ET_DYN; no section table",
        "ADDRESS_NOTATION VA is the trustlet virtual address; file is the byte offset in em.img",
        "PT_LOAD",
    ]
    for segment in ta.loads:
        flags = int(segment["p_flags"])
        lines.append(
            "  file=0x{off:x} VA=0x{va:x} filesz=0x{fs:x} memsz=0x{ms:x} flags={flags}".format(
                off=int(segment["p_offset"]),
                va=int(segment["p_vaddr"]),
                fs=int(segment["p_filesz"]),
                ms=int(segment["p_memsz"]),
                flags="{}{}{}".format("R" if flags & 4 else "-", "W" if flags & 2 else "-", "X" if flags & 1 else "-"),
            )
        )
    return lines


def region(ta: Trustlet, label: str, start: int, end: int) -> list[str]:
    return [
        "",
        f"REGION {label}",
        f"RANGE VA=0x{start:x}..0x{end:x} file=0x{ta.va_to_file(start):x}..0x{ta.va_to_file(end - 1) + 1:x}",
        *ta.disasm(start, end),
    ]


def strings(ta: Trustlet, needles: list[bytes]) -> list[str]:
    lines = ["", "STRING_OCCURRENCES (direct byte search)"]
    for needle in needles:
        hits = ta.string_offsets(needle)
        rendered = ", ".join(
            f"VA=0x{va:x}/file=0x{off:x}" if va is not None else f"file=0x{off:x}"
            for va, off in hits
        ) or "ABSENT"
        lines.append(f"  {needle.decode('ascii', 'backslashreplace')!r}: count={len(hits)} {rendered}")
    return lines


def command_storage_report(ta: Trustlet) -> str:
    _symbols, plt = ta.symbols_and_plt()
    wanted = {
        "qsee_stor_device_init",
        "qsee_stor_open_partition",
        "qsee_stor_device_get_info",
        "qsee_stor_add_partition",
        "qsee_stor_read_sectors",
        "qsee_stor_write_sectors",
        "qsee_kdf",
    }
    lines = [
        "ENGINEERING MODE TA: COMMAND DISPATCH AND SECURE STORAGE EVIDENCE",
        "",
        *metadata(ta),
        "",
        "DYNAMIC_IMPORTS_AND_PLT",
    ]
    for plt_va, got, rtype, addend, name in plt:
        if name in wanted:
            lines.append(
                f"  PLT VA=0x{plt_va:x} GOT=0x{got:x} reloc_type={rtype} addend={addend} symbol={name}"
            )
    lines += [
        "",
        "COMMAND_MAP recovered from the range-checked branch tables in the dispatcher:",
        "  1 GET_STATUS -> 0xd118",
        "  2 INSTALL_TOKEN -> 0xd830",
        "  3 TOKEN_IS_INSTALLED -> 0xce04",
        "  11 TOKEN_REQUEST -> 0x13940",
        "  12 ESS -> 0x14cec",
        "  16 GET_TUC -> 0x8900",
        "  20 GET_MODES -> 0xe248",
        "  21 GET_MODES_BIT -> 0xea8c",
        "  23 TIME_REQUEST -> 0x14128",
        "  24 TIME_CHECK -> 0xecb0",
        "  25 INIT -> 0x1183c",
        "  26 SUPPORT_ESS_V1 -> shared ESS dispatcher 0x14cec",
        "  27 GET_MODES_ESS_V1 -> shared ESS dispatcher 0x14cec",
        "  28 REQ_TOKEN_ESS_V1 -> shared ESS dispatcher 0x14cec",
        "  29 REQ_RECOVERY_ESS_V1 -> shared ESS dispatcher 0x14cec",
        "  30 DELETE_TOKEN_ESS_V1 -> shared ESS dispatcher 0x14cec",
        "  31 INSTALL_TOKEN_ESS_V1 -> shared ESS dispatcher 0x14cec",
        "  32 RECOVERY_ESS_V1 -> shared ESS dispatcher 0x14cec",
        "  33 INIT_CORE -> 0xf8c4",
        "  34 GET_MODES_FT -> 0xfa24",
        "  35 GET_INFO -> 0xfcd0",
        "  36 GET_INFO_ESS -> shared ESS dispatcher 0x14cec",
        "  37 SYNC_UP_CORE -> special dispatcher block",
        "",
        "INTERPRETATION",
        "  The entries are executable dispatcher targets, not an isolated string list.",
        "  qsee_stor_* calls initialize/open/add the logical engmode partition and read/write sectors.",
        "  qsee_kdf derives AES key/IV material; storage strings identify RPMB and AES-GCM.",
        "  Static evidence establishes an RPMB-backed encrypted persistence implementation; no write was invoked.",
    ]
    lines += strings(
        ta,
        [
            b"EM_CMD_GET_STATUS",
            b"EM_CMD_INSTALL_TOKEN",
            b"EM_CMD_GET_MODES_BIT",
            b"EM_CMD_SYNC_UP_CORE",
            b"Failed to init RPMB",
            b"em_qsee_init_rpmb",
            b"no partition engmode",
            b"em_qsee_rpmb_write",
            b"em_qsee_rpmb_read",
            b"AES256 GCM IV Label",
            b"em_crypto_aes_256_gcm_encrypt",
        ]
    )
    for args in [
        ("TA top-level command dispatcher and jump tables", 0x49B0, 0x53A0),
        ("KDF wrapper for storage AES key and IV", 0x08D0, 0x09D0),
        ("RPMB sector write wrapper with retry", 0x1340, 0x1408),
        ("RPMB sector read wrapper with retry", 0x1574, 0x1640),
        ("RPMB init/open/info/add/reopen flow", 0x1E14, 0x2040),
    ]:
        lines += region(ta, *args)
    return "\n".join(lines) + "\n"


def bitmap_token_report(ta: Trustlet) -> str:
    lines = [
        "ENGINEERING MODE TA: TOKEN, SIGNATURE, BINDING, AND BITMAP EVIDENCE",
        "",
        *metadata(ta),
        "",
        "KEY_FINDINGS",
        "  GET_MODES_BIT at VA 0xea8c reads a 16-bit mode count, caps it at 0x80,",
        "  caps each numeric mode at 0xff, computes word=(mode>>6), bit=(mode&63),",
        "  and emits four 64-bit words (32 bytes). Therefore numeric mode 3 is bitmap bit 3.",
        "  The token parser at VA 0xadb8 requires leading ASCII ENG. Its failure path builds",
        "  integer 0xf02d0010; service call prints that 32-bit Parcel word as f02d0010.",
        "  em_token_verify_token_signature at VA 0xa5cc incorporates (mode_count * 4) in",
        "  the authenticated-length calculation before calling the signature verifier at 0x3070.",
        "  Thus MODE data is inside the signed region and changing MODE invalidates the signature.",
        "  The INTE parser maps type 1 to the token signature and type 2 to the leaf certificate.",
        "  After certificate validation, 0x3070 applies the leaf RSA public key to type 1 with",
        "  PKCS#1 v1.5 type-1 padding, requires 32 recovered bytes, and compares them with",
        "  SHA-256 of the authenticated body. This is a second RSA authentication operation.",
        "  Certificate validator 0x3474 selects one of two anchor pairs, checks keyUsage when",
        "  present, and normally requires subject CN EngineeringMode. Its exceptional path",
        "  compares SHA-256 of the complete input certificate DER with a fixed digest at 0xf3caa;",
        "  that digest is a whole-certificate allowlist entry, not a leaf-SPKI pin.",
        "  The verifier compares a 16-byte device record; install checks nonce, singleId, model,",
        "  prior-use state, and expiration paths. Applicability can vary by token type/policy.",
    ]
    lines += strings(
        ta,
        [
            b"Unknown header magic",
            b"em_token_verify_token_signature",
            b"Installed token isn't for this device",
            b"Requested nonce isn't matched",
            b"already used",
            b"token is expired",
            b"MODE",
            b"VALIDITY",
            b"INTE",
            b"EngineeringMode",
            b"single id",
            b"nonce",
            b"imei",
        ]
    )
    lines += ["", "CERTIFICATE_ANCHOR_LAYOUT"]
    for slot, va in enumerate((0xF3CCA, 0xF3DF0, 0xF3F16, 0xF403C)):
        off = ta.va_to_file(va)
        raw = ta.data[off : off + 0x126]
        lines.append(
            f"  slot={slot} VA=0x{va:x} file=0x{off:x} size=0x126 "
            f"sha256={hashlib.sha256(raw).hexdigest()}"
        )
    for args in [
        ("token signature verification and signed-length construction", 0xA5CC, 0xA7A8),
        ("device-record binding loop and 16-byte comparison", 0xA7A8, 0xA920),
        ("token parser: ENG magic and error 0xf02d0010", 0xADB8, 0xAEF0),
        ("token parser MODE/validity/integrity sequence", 0xB900, 0xCA40),
        ("separate INTE signature/integrity verifier", 0x4514, 0x4890),
        ("token body SHA256", 0x30F4, 0x3108),
        ("certificate validation, RSA recovery, and digest compare", 0x3224, 0x32EC),
        ("certificate anchor selector: primary pair", 0x3550, 0x357C),
        ("certificate keyUsage extraction", 0x35F0, 0x362C),
        ("certificate anchor selector: alternate pair", 0x3758, 0x3784),
        ("certificate CN policy and whole-DER digest fallback", 0x38B8, 0x39B8),
        ("certificate subject CN extraction", 0x43D0, 0x44A4),
        ("RSA public recovery wrapper", 0x65DF8, 0x65EE8),
        ("RSA padding selector dispatch", 0x66338, 0x663D4),
        ("PKCS1 v1.5 type-1 unpadding", 0x62688, 0x627BC),
        ("GET_TUC caller copies signed prefix through INTE and verifies", 0x8C40, 0x8CF0),
        ("install-token nonce/singleId/model/used-state checks", 0xD830, 0xE0C8),
        ("expiration check", 0xACB0, 0xAD90),
        ("GET_MODES_BIT bitmap construction and 32-byte output", 0xEA8C, 0xECB0),
    ]:
        lines += region(ta, *args)
    return "\n".join(lines) + "\n"


def ess_report(ta: Trustlet) -> str:
    lines = [
        "ENGINEERING MODE TA: ESS V1 PARSING AND CERTIFICATE USE EVIDENCE",
        "",
        *metadata(ta),
        "",
        "KEY_FINDINGS",
        "  The type-1 parser requires ASCII version 01 and 11 nonempty tokens,",
        "  plus the empty component after the terminal ':'. After leading 01 and",
        "  the final certLength/certificate/SHA-256 triplet, seven opaque fields remain.",
        "  A twelfth nonempty token is rejected; the trailing empty component is not a field.",
        "  The parser hex-decodes the final field to exactly 32 bytes, hashes the prefix/body,",
        "  compares all 32 bytes, decodes the certificate, and checks declared vs decoded length.",
        "  The request path loads the stored ESS certificate and passes pointer+length to",
        "  em_ess_encrypt_message; its crypto call at 0x4024 consumes that certificate.",
        "  This certificate encrypts an outbound request. It is distinct from the token",
        "  signature/certificate verification at VA 0xa5cc -> 0x3070.",
        "  In the shared ESS dispatcher, subtype 1 reaches em_ess_make_token_request",
        "  (call 0x156e0 -> 0x172b8), while subtype 2 reaches em_ess_install_token_v1",
        "  (call 0x154e8 -> 0x1912c). These are active-TA mappings, not legacy names alone.",
        "  The remote authority and its issuance policy are not present in local artifacts.",
    ]
    lines += strings(
        ta,
        [
            b"em_ess_encrypt_message",
            b"em_ess_get_command_type",
            b"em_ess_make_token_request",
            b"em_ess_install_token_v1",
            b"em_ess_make_delete_request",
            b"em_ess_make_recovery_request",
            b"em_ess_recovery_esi_v1",
            b"em_ess_delete_token_offline",
            b"SHA256",
            b"certificate",
            b"cert length",
            b"ESS",
        ]
    )
    for args in [
        ("ESS shared dispatcher", 0x14CEC, 0x15120),
        ("ESS subtype 1/2 selection", 0x151B0, 0x15280),
        ("ESS subtype 2 reaches active install-token-v1 function", 0x15390, 0x15520),
        ("ESS subtype 1 reaches active make-token-request function", 0x15690, 0x15710),
        ("ESS type-1 version 01 and delimiter-count setup", 0x15E90, 0x16220),
        ("ESS SHA-256 decode/hash/32-byte compare", 0x16220, 0x16520),
        ("ESS certificate decode and declared-length check", 0x16520, 0x167F0),
        ("ESS request loads stored cert and calls encryption", 0x17880, 0x17910),
        ("em_ess_encrypt_message passes cert to crypto routine", 0x17AE0, 0x180B0),
    ]:
        lines += region(ta, *args)
    return "\n".join(lines) + "\n"


def main() -> None:
    global TA
    image, out_dir = resolve_image()
    TA = Trustlet(image)
    out_dir.mkdir(parents=True, exist_ok=True)
    if image == DEFAULT_IMAGE:
        # preserve historical filenames for the DZDP report
        reports = {
            out_dir / "ta-command-storage-evidence.txt": command_storage_report(TA),
            out_dir / "ta-bitmap-token-evidence.txt": bitmap_token_report(TA),
            out_dir / "ta-ess-evidence.txt": ess_report(TA),
        }
    else:
        # alternate image (e.g. CZD1): use namespaced names
        suffix = image.stem.replace("em-", "")
        reports = {
            out_dir / f"ta-{suffix}-command-storage-evidence.txt": command_storage_report(TA),
            out_dir / f"ta-{suffix}-bitmap-token-evidence.txt": bitmap_token_report(TA),
            out_dir / f"ta-{suffix}-ess-evidence.txt": ess_report(TA),
        }
    for destination, content in reports.items():
        destination.write_text(content, encoding="utf-8")
        print(f"wrote {destination.relative_to(ROOT)} ({len(content.encode('utf-8'))} bytes)")


if __name__ == "__main__":
    main()
