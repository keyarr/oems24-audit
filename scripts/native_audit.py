#!/usr/bin/env python3
"""Generate read-only, reproducible evidence from Engineering Mode HLOS ELFs."""

from __future__ import annotations

import hashlib
import re
import subprocess
from functools import lru_cache
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile


ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "audit" / "binaries"
DEC = ROOT / "audit" / "decompiled"
DEV = ROOT / "audit" / "device"
FW = ROOT / "audit" / "framework"
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=None)
def demangle(name: str) -> str:
    result = subprocess.run(
        ["c++filt", name], check=True, text=True, capture_output=True
    )
    return result.stdout.strip()


class NativeElf:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            self.header = dict(elf.header)
            self.loads = [
                dict(segment.header)
                for segment in elf.iter_segments()
                if segment.header.p_type == "PT_LOAD"
            ]
            dynamic = elf.get_section_by_name(".dynamic")
            self.needed = [
                tag.needed
                for tag in dynamic.iter_tags()
                if tag.entry.d_tag == "DT_NEEDED"
            ] if dynamic else []
            self.soname = next(
                (tag.soname for tag in dynamic.iter_tags() if tag.entry.d_tag == "DT_SONAME"),
                None,
            ) if dynamic else None
            self.symbols = []
            seen = set()
            for table_name in (".symtab", ".dynsym"):
                table = elf.get_section_by_name(table_name)
                if not table:
                    continue
                for symbol in table.iter_symbols():
                    key = (symbol.name, int(symbol.entry.st_value), int(symbol.entry.st_size))
                    if key in seen:
                        continue
                    seen.add(key)
                    self.symbols.append(
                        {
                            "name": symbol.name,
                            "value": int(symbol.entry.st_value),
                            "size": int(symbol.entry.st_size),
                            "type": symbol.entry.st_info.type,
                            "shndx": symbol.entry.st_shndx,
                        }
                    )

    def va_to_file(self, va: int) -> int:
        for segment in self.loads:
            start = int(segment["p_vaddr"])
            if start <= va < start + int(segment["p_filesz"]):
                return int(segment["p_offset"]) + va - start
        raise ValueError(f"VA 0x{va:x} is not file-backed in {self.path.name}")

    def symbol(self, fragment: str) -> dict:
        candidates = [
            symbol for symbol in self.symbols
            if symbol["value"] and fragment in demangle(symbol["name"])
        ]
        if not candidates:
            raise KeyError(f"symbol fragment {fragment!r} not found in {self.path.name}")
        candidates.sort(key=lambda s: (len(demangle(s["name"])), s["value"]))
        return candidates[0]

    def disasm(self, start: int, end: int) -> list:
        offset = self.va_to_file(start)
        raw = self.data[offset : offset + end - start]
        return list(MD.disasm(raw, start))

    def symbol_disasm(self, fragment: str):
        symbol = self.symbol(fragment)
        end = symbol["value"] + symbol["size"]
        return symbol, self.disasm(symbol["value"], end)

    def metadata(self) -> list[str]:
        return [
            f"FILE {self.path.relative_to(ROOT)}",
            f"SIZE {self.path.stat().st_size}",
            f"SHA256 {sha256(self.path)}",
            f"ELF {self.header['e_ident']['EI_CLASS']} {self.header['e_machine']} {self.header['e_type']}",
            f"SONAME {self.soname or '-'}",
            "DT_NEEDED " + (", ".join(self.needed) if self.needed else "-"),
        ]

    def string_hits(self, needle: bytes) -> list[int]:
        offsets = []
        cursor = 0
        while True:
            cursor = self.data.find(needle, cursor)
            if cursor < 0:
                break
            offsets.append(cursor)
            cursor += 1
        return offsets


def render_insns(elf: NativeElf, instructions) -> list[str]:
    return [
        f"  VA 0x{i.address:06x} file 0x{elf.va_to_file(i.address):06x} "
        f"{i.mnemonic:<8} {i.op_str}"
        for i in instructions
    ]


def render_symbol(elf: NativeElf, fragment: str, label: str | None = None) -> list[str]:
    symbol, instructions = elf.symbol_disasm(fragment)
    title = label or demangle(symbol["name"])
    return [
        "",
        f"SYMBOL {title}",
        f"MANGLED {symbol['name']}",
        f"RANGE VA=0x{symbol['value']:x}..0x{symbol['value'] + symbol['size']:x} size={symbol['size']}",
        *render_insns(elf, instructions),
    ]


def render_region(elf: NativeElf, label: str, start: int, end: int) -> list[str]:
    return [
        "",
        f"REGION {label}",
        f"RANGE VA=0x{start:x}..0x{end:x}",
        *render_insns(elf, elf.disasm(start, end)),
    ]


def render_strings(elf: NativeElf, needles: list[bytes]) -> list[str]:
    lines = ["", "STRING_OCCURRENCES (direct byte search; file offsets)"]
    for needle in needles:
        hits = elf.string_hits(needle)
        where = ", ".join(f"0x{x:x}" for x in hits) if hits else "ABSENT"
        lines.append(
            f"  {needle.decode('ascii', 'backslashreplace')!r}: count={len(hits)} offsets={where}"
        )
    return lines


def file_lines(path: Path, patterns: list[str], limit: int = 300) -> list[str]:
    if not path.exists():
        return [f"  MISSING {path.relative_to(ROOT)}"]
    regex = re.compile("|".join(patterns), re.IGNORECASE)
    result = []
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if regex.search(line):
            result.append(f"  {path.relative_to(ROOT)}:{number}: {line}")
            if len(result) == limit:
                result.append("  ... output capped ...")
                break
    return result or [f"  no matching lines in {path.relative_to(ROOT)}"]


def topology_report() -> str:
    names = [
        "vendor.samsung.hardware.security.engmode-service",
        "engmode-V1-ndk-vendor.so",
        "libengmode_client.so",
        "emservice",
        "libengmode_server.so",
        "libengmode_tlc.so",
        "libengmode2lite.so",
        "libengmode15.so",
        "lib.engmode.samsung.so",
        "lib.engmodejni.samsung.so",
    ]
    lines = [
        "ENGINEERING MODE HLOS TOPOLOGY EVIDENCE",
        "",
        "INTERPRETATION",
        "  Public vendor service: stable AIDL NDK -> libengmode_client.so.",
        "  Internal emservice: legacy libbinder service EngineeringModeService -> libengmode_server.so.",
        "  Current server directly needs libengmode2lite.so and libengmode_tlc.so; it does not need libengmode15.so.",
        "  libengmode_tlc.so imports QSEECom start/send/shutdown and names trustlet engmode.",
        "  Runtime /proc/maps and lsof corroborate the active service libraries and the absence of libengmode15.so.",
        "  Framework JNI dynamically opens /system/lib64/lib.engmode.samsung.so; it is not a DT_NEEDED edge.",
    ]
    for name in names:
        elf = NativeElf(BIN / name)
        lines += ["", "---", *elf.metadata()]
    lines += [
        "",
        "VINTF_MANIFEST",
        (DEV / "vintf-engmode-manifest.xml").read_text(errors="replace").strip(),
        "",
        "INIT_FILES",
        (DEV / "init-engmode-service.rc").read_text(errors="replace").strip(),
        (DEV / "init-emservice.rc").read_text(errors="replace").strip(),
        "",
        "RUNTIME_PROCESS_AND_SERVICE_EVIDENCE",
        *file_lines(DEV / "engmode-process-details.txt", [r"engmode", r"emservice"]),
        *file_lines(DEV / "engmode-services.txt", [r"engmode", r"SatsService"]),
        *file_lines(DEV / "engmode-maps.txt", [r"libengmode", r"engmode-V1", r"lib\.engmode"]),
        *file_lines(DEV / "engmode-lsof.txt", [r"libengmode", r"engmode-V1", r"lib\.engmode"]),
    ]
    tlc = NativeElf(BIN / "libengmode_tlc.so")
    lines += render_strings(
        tlc,
        [b"engmode", b"QSEECom_start_app", b"QSEECom_send_cmd", b"QSEECom_shutdown_app"],
    )
    jni = NativeElf(BIN / "lib.engmodejni.samsung.so")
    lines += render_strings(
        jni,
        [b"/system/lib64/lib.engmode.samsung.so", b"engmodeManager_hal_commandForESS"],
    )
    return "\n".join(lines) + "\n"


AIDL_TX = [
    (1, "getStatus"), (2, "installToken"), (3, "isTokenInstalled"),
    (4, "removeToken"), (5, "getNumOfModes"), (6, "sendFuseCmd"),
    (7, "getVersion"), (8, "getExpiryDate"), (9, "getId"),
    (10, "getRequestMsg"), (11, "makeTokenReq"), (12, "commandForEss"),
    (13, "getServerTime"), (14, "recoveryItl"), (15, "makeItlReq"),
    (16, "getToken"), (17, "getTuc"), (18, "setPriorityTime"),
    (19, "getPriorityTime"), (20, "getLastTokenStatus"),
    (21, "getStringModes"), (22, "getModesbit"),
    (23, "getTokenInfoForJanus"),
]


def aidl_report() -> str:
    elf = NativeElf(BIN / "engmode-V1-ndk-system.so")
    lines = [
        "PUBLIC ENGINEERING MODE STABLE-AIDL TRANSACTION EVIDENCE",
        "",
        *elf.metadata(),
        "",
        "INTERFACE",
        "  descriptor=vendor.samsung.hardware.security.engmode.ISehEngmode",
        "  VINTF format=aidl version=1 instance=default",
        "  interface_hash=40e3d24c35baf5b934a2515792ae8aae089da246",
        "  meta transactions: getInterfaceVersion=0x00ffffff; getInterfaceHash=0x00fffffe",
        "",
        "TRANSACTION_MAP (immediate passed as w1 to AIBinder_transact)",
    ]
    for expected, method in AIDL_TX:
        matches = [
            symbol for symbol in elf.symbols
            if symbol["value"] and f"BpSehEngmode::{method}(" in demangle(symbol["name"])
        ]
        if len(matches) != 1:
            raise RuntimeError(f"expected one Bp symbol for {method}, got {len(matches)}")
        symbol = matches[0]
        insns = elf.disasm(symbol["value"], symbol["value"] + symbol["size"])
        candidates = []
        for index, insn in enumerate(insns):
            if insn.mnemonic == "mov" and insn.op_str.startswith("w1, #"):
                following = insns[index + 1:index + 5]
                if any(i.mnemonic == "bl" and i.op_str == "#0xd3f8" for i in following):
                    candidates.append((index, int(insn.op_str.split("#", 1)[1], 0)))
        if not any(code == expected for _, code in candidates):
            raise RuntimeError(f"transaction extraction mismatch for {method}: {candidates}")
        signature = demangle(symbol["name"])
        where = next(insns[index].address for index, code in candidates if code == expected)
        lines.append(f"  {expected:2d} {method:<22} mov@0x{where:x}  {signature}")
    lines += [
        "",
        "CALLER_INFO_SCOPE",
        "  getStatus signature includes SehCallerInfo plus uid/pid-related arguments.",
        "  makeTokenReq and getModesbit signatures have no SehCallerInfo argument.",
        "  This establishes an API-shape distinction; it does not by itself remove SELinux, Binder, vendor-service, or TA checks.",
    ]
    for fragment, label in [
        ("BpSehEngmode::getStatus(", "getStatus: transaction 1 and SehCallerInfo serialization"),
        ("BpSehEngmode::makeTokenReq(", "makeTokenReq: transaction 11"),
        ("BpSehEngmode::getModesbit(", "getModesbit: transaction 22 and inout byte vector"),
        ("BpSehEngmode::getInterfaceVersion(", "stable AIDL interface-version meta transaction"),
        ("BpSehEngmode::getInterfaceHash(", "stable AIDL interface-hash meta transaction"),
    ]:
        lines += render_symbol(elf, fragment, label)
    return "\n".join(lines) + "\n"


def auth_status_report() -> str:
    system = NativeElf(BIN / "lib.engmode.samsung.so")
    server = NativeElf(BIN / "libengmode_server.so")
    lines = [
        "ENGINEERING MODE CALLER AUTHORIZATION AND STATUS EVIDENCE",
        "",
        *system.metadata(),
        "",
        *server.metadata(),
        "",
        "INTERPRETATION",
        "  lib.engmode.samsung.so performs a client-side allowlist/path/permission/signature check using calling UID/PID.",
        "  Its strings and code include a special system-client signature path, but not an unrestricted global bypass.",
        "  The internal legacy EngineeringModeHandler::callerCheck(int) is exactly mov w0,wzr; ret.",
        "  The onTransact default path logs Unknown Command and constructs integer 0xd01f0012.",
        "  The TA header parser constructs integer 0xf02d0010 for absent/invalid ENG magic.",
        "  Direct query-only AIDL calls returned those semantic backend values with Binder transport success.",
        "  The originally reported 0x12001fd0 and 0x10002df0 reverse words that service call had already rendered numerically.",
    ]
    lines += render_strings(
        system,
        [
            b"Caller UID invalid", b"system client", b"checking signature",
            b"UID permission error", b"system_server", b"auth failed",
            b"com.samsung.android.kgclient", b"/system/bin", b"/system_ext/bin",
        ],
    )
    lines += render_strings(server, [b"Unknown Command", b"EngineeringModeService"])
    for fragment in [
        "EngmodeManager::caller_check(", "client::checkSignature(",
        "client::checkClient(", "client::checkPath(", "client::checkPermission(",
    ]:
        lines += render_symbol(system, fragment)
    lines += render_symbol(server, "EngineeringModeHandler::callerCheck(")
    lines += render_region(
        server,
        "onTransact default/unknown-command return 0xd01f0012",
        0xBBC0,
        0xBC04,
    )
    lines += [
        "",
        "QUERY_ONLY_BINDER_PROBES (verbatim)",
        (DEV / "engmode-binder-readonly-probes.txt").read_text(errors="replace").rstrip(),
    ]
    return "\n".join(lines) + "\n"


def token_request_report() -> str:
    server = NativeElf(BIN / "libengmode_server.so")
    lines = [
        "ENGINEERING MODE HLOS TOKEN-REQUEST AND MODES-BIT EVIDENCE",
        "",
        *server.metadata(),
        "",
        "INTERPRETATION",
        "  EngineeringModeWorld::emGetTokenRequest reads a big-endian 16-bit count from the modes buffer,",
        "  requires count < 0x40 and sufficient bytes, byte-swaps every 16-bit numeric mode,",
        "  stores count at TA payload +0x2aa and modes at +0x2ac, then submits command 0x21c7d.",
        "  No filter rejects numeric mode 3: bytes 00 01 00 03 represent count=1, mode=3 and pass these structural checks.",
        "  This is a static serialization finding; the audit deliberately did not request a live nonce/token.",
        "  EngineeringModeWorld::emGetModesBit sends the corresponding modes-bit query and returns its byte payload.",
    ]
    lines += render_strings(
        server,
        [b"EM_CMD_GET_TOKEN_REQUEST", b"EM_CMD_GET_MODES_BIT", b"emGetTokenRequest", b"emGetModesBit"],
    )
    lines += render_symbol(server, "EngineeringModeWorld::emGetTokenRequest(")
    lines += render_symbol(server, "EngineeringModeWorld::emGetModesBit(")
    return "\n".join(lines) + "\n"


def sats_report() -> str:
    jni = NativeElf(BIN / "lib.engmodejni.samsung.so")
    lines = [
        "SATSERVICE / AT+ENGMODES / ESS JNI EVIDENCE",
        "",
        *jni.metadata(),
        "",
        "INTERPRETATION",
        "  SystemServer constructs SatsService; its constructor registers AuthUnlockATCmd (AT+FRPUNLCK)",
        "  and EngModesCmdHelper (AT+ENGMODES), then starts SATServiceAt and SATServiceData.",
        "  EngModesCmdHelper handles 0,5 fragments and FFF termination, reassembles the payload,",
        "  prefixes 0,2, and invokes native commandForESS.",
        "  Both framework and SatsService JNI exports tail into the same local commandForESS function.",
        "  That function maps command strings to operation IDs exactly as listed below and dynamically",
        "  resolves engmodeManager_hal_commandForESS from /system/lib64/lib.engmode.samsung.so.",
        "",
        "JNI_COMMAND_MAPPING",
        "  0,0,3,0 -> 9; 0,1, -> 1; 0,2, -> 2; 0,3, -> 3; 0,4, -> 4",
        "  1,1,0 -> 5; 1,2,0 -> 6; 1,3,1 -> 7; 2,2, -> 8; 0,0, -> 0; 9,0 -> 10; else 1000",
        "",
        "FRAMEWORK_STATIC_EVIDENCE_EXCERPTS",
        *file_lines(
            DEC / "framework-satsservice.txt",
            [r"EngModesCmdHelper", r"AuthUnlockATCmd", r"AT\+ENGMODES", r"AT\+FRPUNLCK", r"commandForESS", r"SATServiceAt", r"SATServiceData", r"FFF", r"0,5"],
            220,
        ),
        *file_lines(
            DEC / "services-systemserver-satsservice.txt",
            [r"SatsService", r"addService"],
            100,
        ),
    ]
    lines += render_strings(
        jni,
        [b"/system/lib64/lib.engmode.samsung.so", b"engmodeManager_hal_commandForESS"],
    )
    lines += render_symbol(jni, "commandForESS", "local shared commandForESS mapping and dynamic resolution")
    lines += render_symbol(jni, "Java_com_android_server_SatsService_commandForESS")
    return "\n".join(lines) + "\n"


def main() -> None:
    DEC.mkdir(parents=True, exist_ok=True)
    reports = {
        DEC / "native-topology-evidence.txt": topology_report(),
        DEC / "aidl-transaction-evidence.txt": aidl_report(),
        DEC / "native-auth-status-evidence.txt": auth_status_report(),
        DEC / "native-token-request-evidence.txt": token_request_report(),
        DEC / "native-sats-ess-evidence.txt": sats_report(),
    }
    for path, content in reports.items():
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)} ({len(content.encode('utf-8'))} bytes)")


if __name__ == "__main__":
    main()
