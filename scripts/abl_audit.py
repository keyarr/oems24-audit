#!/usr/bin/env python3
"""Produce reproducible, read-only ABL disassembly and CFG evidence."""

from __future__ import annotations

import collections
import hashlib
import json
import os
import subprocess
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import lief


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "decompiled"
CURRENT = OUT / "linuxloader-oneui8.pe"
OLD = OUT / "linuxloader-oneui7.pe"
DEVINFO = ROOT / "partitions" / "devinfo.img"
def _resolve_r2() -> str:
    bundled = ROOT / "tools" / "root" / "usr" / "bin" / "radare2"
    return str(bundled) if bundled.exists() else "radare2"


R2 = _resolve_r2()
R2_BIAS = 0x10000

MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pe_metadata(path: Path) -> list[str]:
    binary = lief.parse(str(path))
    lines = [
        f"FILE {path.relative_to(ROOT)}",
        f"SIZE {path.stat().st_size}",
        f"SHA256 {sha256(path)}",
        f"FORMAT PE32+ ARM64 EFI imagebase=0x{binary.optional_header.imagebase:x} entry_rva=0x{binary.optional_header.addressof_entrypoint:x}",
        "ADDRESS_NOTATION actual PE RVA/file offset; radare2 VA for this PE is actual+0x10000",
        "SECTIONS",
    ]
    for section in binary.sections:
        lines.append(
            f"  {section.name} RVA=0x{section.virtual_address:x} RAW=0x{section.pointerto_raw_data:x} "
            f"VSIZE=0x{section.virtual_size:x} SIZE=0x{section.size:x}"
        )
    return lines


def disasm(path: Path, start: int, end: int) -> list[str]:
    data = path.read_bytes()[start:end]
    result = []
    for insn in MD.disasm(data, start):
        result.append(
            f"  RVA/file 0x{insn.address:06x}  r2 0x{insn.address + R2_BIAS:06x}  "
            f"{insn.mnemonic:<8} {insn.op_str}"
        )
    return result


def string_hits(path: Path, needles: list[bytes]) -> list[str]:
    data = path.read_bytes()
    lines = ["STRING_OCCURRENCES (direct byte search; offsets are RVA/file offsets)"]
    for needle in needles:
        offsets = []
        at = 0
        while True:
            at = data.find(needle, at)
            if at < 0:
                break
            offsets.append(at)
            at += 1
        label = needle.decode("ascii", "backslashreplace")
        rendered = ", ".join(f"0x{x:x}" for x in offsets) if offsets else "ABSENT"
        lines.append(f"  {label!r}: count={len(offsets)} offsets={rendered}")
    return lines


CURRENT_REGIONS = [
    ("main boot: BLInitToken -> GetEMBit(3) -> dispatcher", 0x9968, 0x99B8),
    ("GetEMBit: index word and select bit from 256-bit global bitmap", 0xADAE0, 0xADB40),
    ("BLInitToken and GET_MODES_BIT initialization", 0xADE70, 0xADF50),
    ("GetUnlockCount / IsUnlocked / IsUnlockCritical", 0x41E70, 0x41F88),
    ("SetUnlock dispatcher; mode=0 reaches SetUnlocked", 0x41F88, 0x42170),
    ("SetUnlocked: counter, byte +0x0d, persistent write", 0x424CC, 0x42564),
    ("DeviceInfo load/default initializer", 0x425EC, 0x42720),
    ("libavb read_is_device_unlocked callback", 0x51048, 0x51094),
    ("AvbOps constructor stores callback at ops+0x48", 0x516C8, 0x51750),
    ("boot verification path reads IsUnlocked", 0x144C0, 0x145A0),
    ("verification skip function and unlocked log branch", 0x16238, 0x16400),
    ("lock/unlock UI branch with live IsUnlocked callsites", 0xACC60, 0xACD60),
    ("current OEM policy: log LOCK then return false", 0xA13B0, 0xA142C),
    ("current cmdline builder appends androidboot.other.locked=1", 0x4CFF0, 0x4D040),
]

OLD_REGIONS = [
    ("old boot location: BLInitToken but no GetEMBit(3) synchronization", 0x9950, 0x99B8),
    ("old persistent-backed OEM unlock reader", 0xA0F70, 0xA1060),
    ("old wrapper and OEM/FRP policy", 0xA1220, 0xA1440),
    ("old lock/unlock UI branch", 0xABD80, 0xABE90),
]


NEEDLES = [
    b"SAMANDR-BOOT!",
    b"[OEM]Oem unlock value is %d",
    b"[FRP][OEM] init succeed!",
    b"[OEM]PLC:%x",
    b"[OEM]LOCK:%d",
    b"androidboot.other.locked=1",
    b"Device is unlocked, Skipping boot verification",
    b"For device lock, Draw Lock Img",
    b"For device unlock, Draw UnLock Img",
    b"BL_EM_CMD_GET_MODES_BIT",
]


def write_disassembly_report(path: Path, regions, destination: Path, title: str) -> None:
    lines = [title, "", *pe_metadata(path), "", *string_hits(path, NEEDLES)]
    for label, start, end in regions:
        lines.extend(
            [
                "",
                f"REGION {label}",
                f"RANGE actual=0x{start:x}..0x{end:x} r2=0x{start + R2_BIAS:x}..0x{end + R2_BIAS:x}",
                *disasm(path, start, end),
            ]
        )
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def r2_cfg() -> dict:
    env = os.environ.copy()
    bundled_lib = ROOT / "tools" / "root" / "usr" / "lib64"
    if bundled_lib.exists():
        env["LD_LIBRARY_PATH"] = str(bundled_lib)
    result = subprocess.run(
        [
            str(R2),
            "-2",
            "-q",
            "-e",
            "log.level=0",
            "-c",
            "aaa;agfj @ 0x190ec;q",
            str(CURRENT),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return json.loads(result.stdout)[0]


def graph_evidence() -> str:
    fcn = r2_cfg()
    blocks = {block["offset"]: block for block in fcn["blocks"]}

    def successors(address: int) -> list[int]:
        block = blocks[address]
        return [
            block[key]
            for key in ("jump", "fail")
            if key in block and block[key] in blocks
        ]

    def containing(instruction: int) -> int:
        return next(
            block["offset"]
            for block in fcn["blocks"]
            if block["offset"] <= instruction < block["offset"] + block["size"]
        )

    entry = fcn["offset"]
    avb_call = 0x196F8       # r2 VA; actual RVA 0x96f8
    em_call = 0x1998C        # r2 VA; actual RVA 0x998c
    recursive_call = 0x19860 # r2 VA; actual RVA 0x9860
    avb_block = containing(avb_call)
    em_block = containing(em_call)

    def path(source: int, destination: int, forbidden: int | None = None):
        queue = collections.deque([source])
        previous = {source: None}
        while queue:
            current = queue.popleft()
            if current == destination:
                break
            for nxt in successors(current):
                if nxt == forbidden or nxt in previous:
                    continue
                previous[nxt] = current
                queue.append(nxt)
        if destination not in previous:
            return None
        answer = []
        cursor = destination
        while cursor is not None:
            answer.append(cursor)
            cursor = previous[cursor]
        return list(reversed(answer))

    reachable = set()
    pending = [entry]
    while pending:
        address = pending.pop()
        if address in reachable:
            continue
        reachable.add(address)
        pending.extend(successors(address))

    dominators = {address: set(reachable) for address in reachable}
    dominators[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for address in reachable - {entry}:
            predecessors = [
                candidate
                for candidate in reachable
                if address in successors(candidate)
            ]
            common = (
                set.intersection(*(dominators[p] for p in predecessors))
                if predecessors
                else set()
            )
            new = {address} | common
            if new != dominators[address]:
                dominators[address] = new
                changed = True

    def render_path(value):
        if value is None:
            return "NO PATH"
        return " -> ".join(f"0x{x:x}" for x in value)

    entry_to_avb_without_em = path(entry, avb_block, em_block)
    entry_to_em_without_avb = path(entry, em_block, avb_block)
    em_to_avb = path(em_block, avb_block)
    avb_to_em = path(avb_block, em_block)
    lines = [
        "ABL CURRENT MAIN-FUNCTION CONTROL-FLOW AUDIT",
        f"SOURCE {CURRENT.relative_to(ROOT)} SHA256 {sha256(CURRENT)}",
        "ADDRESS_NOTATION this section uses radare2 VAs; subtract 0x10000 for actual PE RVA/file offset",
        f"FUNCTION entry=0x{entry:x} blocks={len(blocks)} reachable_blocks={len(reachable)}",
        f"AVB_CALL instruction=0x{avb_call:x} actual=0x{avb_call-R2_BIAS:x} block=0x{avb_block:x}",
        f"EM_SYNC instruction=0x{em_call:x} actual=0x{em_call-R2_BIAS:x} block=0x{em_block:x}",
        f"RECURSIVE_CALL instruction=0x{recursive_call:x} actual=0x{recursive_call-R2_BIAS:x} calls function entry again",
        "",
        f"ENTRY_TO_AVB_AVOIDING_EM_SYNC: {render_path(entry_to_avb_without_em)}",
        f"ENTRY_TO_EM_SYNC_AVOIDING_AVB: {render_path(entry_to_em_without_avb)}",
        f"EM_SYNC_TO_AVB: {render_path(em_to_avb)}",
        f"AVB_TO_EM_SYNC: {render_path(avb_to_em)}",
        "",
        f"EM_SYNC_DOMINATES_AVB_BLOCK: {em_block in dominators[avb_block]}",
        f"AVB_BLOCK_DOMINATES_EM_SYNC: {avb_block in dominators[em_block]}",
        "CONCLUSION The EM synchronization block does not statically dominate the AVB call in this function. "
        "There is an entry-to-AVB CFG path that avoids it. A recursive self-call exists, so this intra-procedural "
        "result alone does not establish every possible cross-invocation temporal ordering.",
    ]
    return "\n".join(lines) + "\n"


def write_devinfo_evidence() -> None:
    data = DEVINFO.read_bytes()
    lines = [
        "CURRENT DEVINFO BYTES",
        f"SOURCE {DEVINFO.relative_to(ROOT)} SIZE {len(data)} SHA256 {sha256(DEVINFO)}",
        f"+0x000[13] {data[:13]!r}",
        f"+0x00d u8 {data[0x0d]}",
        f"+0x00e u8 {data[0x0e]}",
        f"+0x00f u8 {data[0x0f]}",
        f"+0x090 u8 {data[0x90]}",
        f"+0xc88 u32le {int.from_bytes(data[0xc88:0xc8c], 'little')}",
        "Interpretation is established by ABL callsites in abl-oneui8-evidence.txt, not by these bytes alone.",
    ]
    (OUT / "devinfo-layout-evidence.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    write_disassembly_report(
        CURRENT, CURRENT_REGIONS, OUT / "abl-oneui8-evidence.txt", "ONE UI 8.5 CURRENT ABL EVIDENCE"
    )
    write_disassembly_report(
        OLD, OLD_REGIONS, OUT / "abl-oneui7-comparison.txt", "ONE UI 7 OFFICIAL ABL COMPARISON"
    )
    (OUT / "abl-cfg-ordering.txt").write_text(graph_evidence(), encoding="utf-8")
    write_devinfo_evidence()
    for name in (
        "abl-oneui8-evidence.txt",
        "abl-oneui7-comparison.txt",
        "abl-cfg-ordering.txt",
        "devinfo-layout-evidence.txt",
    ):
        path = OUT / name
        print(f"{sha256(path)}  {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
