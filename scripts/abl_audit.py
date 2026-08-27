#!/usr/bin/env python3
"""Produce reproducible, read-only ABL disassembly and CFG evidence."""

from __future__ import annotations

import collections
import hashlib
import json
import os
import subprocess
import uuid
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

    # radare2 merges the Odin launcher at 0x190ec with LinuxLoader because the
    # dead-loop call after its return is not treated as noreturn. 0x19240 has a
    # fresh prologue and is the target used by the application entry wrapper.
    entry = 0x19240
    avb_call = 0x196F8       # r2 VA; actual RVA 0x96f8
    em_call = 0x1998C        # r2 VA; actual RVA 0x998c
    odin_call = 0x19860       # r2 VA; actual RVA 0x9860
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

    def render_blocks(label, value):
        lines = ["", f"{label}_BLOCKS"]
        if value is None:
            return [*lines, "  NO PATH"]
        for address in value:
            block = blocks[address]
            edges = " ".join(
                f"{key}=0x{block[key]:x}/actual=0x{block[key] - R2_BIAS:x}"
                for key in ("jump", "fail")
                if key in block
            ) or "terminal"
            lines.append(
                f"BLOCK r2=0x{address:x} actual=0x{address - R2_BIAS:x} "
                f"size=0x{block['size']:x} {edges}"
            )
            calls = []
            for op in block.get("ops", []):
                opcode = op.get("opcode", op.get("disasm", "?"))
                lines.append(
                    f"  r2 0x{op['offset']:x} actual 0x{op['offset'] - R2_BIAS:x} {opcode}"
                )
                if opcode.split(maxsplit=1)[0] in ("bl", "blr"):
                    calls.append(f"0x{op['offset']:x}: {opcode}")
            lines.append(f"  CALLS {', '.join(calls) if calls else 'none'}")
        return lines

    entry_to_avb_without_em = path(entry, avb_block, em_block)
    entry_to_em_without_avb = path(entry, em_block, avb_block)
    em_to_avb = path(em_block, avb_block)
    avb_to_em = path(avb_block, em_block)
    entry_to_avb_via_em = (
        [*entry_to_em_without_avb, *em_to_avb[1:]]
        if entry_to_em_without_avb and em_to_avb
        else None
    )
    lines = [
        "ABL CURRENT MAIN-FUNCTION CONTROL-FLOW AUDIT",
        f"SOURCE {CURRENT.relative_to(ROOT)} SHA256 {sha256(CURRENT)}",
        "ADDRESS_NOTATION this section uses radare2 VAs; subtract 0x10000 for actual PE RVA/file offset",
        f"RADARE_FUNCTION_MERGE reported_entry=0x{fcn['offset']:x} blocks={len(blocks)}",
        f"LOGICAL_MAIN entry=0x{entry:x} reachable_blocks={len(reachable)}",
        f"AVB_CALL instruction=0x{avb_call:x} actual=0x{avb_call-R2_BIAS:x} block=0x{avb_block:x}",
        f"EM_SYNC instruction=0x{em_call:x} actual=0x{em_call-R2_BIAS:x} block=0x{em_block:x}",
        f"ODIN_HELPER_CALL instruction=0x{odin_call:x} actual=0x{odin_call-R2_BIAS:x} target=0x190ec actual_target=0x90ec",
        "BOUNDARY helper 0x190ec has its own prologue and ret at 0x19238; LinuxLoader has a fresh prologue at 0x19240",
        "BOUNDARY caller 0x11374 branches to 0x19240; no caller branches to 0x190ec as LinuxLoader entry",
        "",
        f"ENTRY_TO_AVB_AVOIDING_EM_SYNC: {render_path(entry_to_avb_without_em)}",
        f"ENTRY_TO_EM_SYNC_AVOIDING_AVB: {render_path(entry_to_em_without_avb)}",
        f"EM_SYNC_TO_AVB: {render_path(em_to_avb)}",
        f"ENTRY_TO_AVB_VIA_EM_SYNC: {render_path(entry_to_avb_via_em)}",
        f"AVB_TO_EM_SYNC: {render_path(avb_to_em)}",
        "",
        f"EM_SYNC_DOMINATES_AVB_BLOCK: {em_block in dominators[avb_block]}",
        f"AVB_BLOCK_DOMINATES_EM_SYNC: {avb_block in dominators[em_block]}",
        "CONCLUSION The EM synchronization block does not statically dominate the AVB call in this function. "
        "There is a logical-main-to-AVB CFG path that avoids it. The call at 0x19860 is an external call to the "
        "preceding Odin-launch helper, not recursion.",
        *render_blocks("ENTRY_TO_AVB_AVOIDING_EM_SYNC", entry_to_avb_without_em),
        *render_blocks("ENTRY_TO_AVB_VIA_EM_SYNC", entry_to_avb_via_em),
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


def bypass_analysis_evidence() -> str:
    data = CURRENT.read_bytes()
    devinfo = DEVINFO.read_bytes()
    memcard_guid_bytes = data[0xE2E40:0xE2E50]
    memcard_guid = uuid.UUID(bytes_le=memcard_guid_bytes)
    initial_live = data[0x170E20:0x170E40]

    ufs_evidence = []
    for relative in ("device/properties-all.txt", "device/proc-bootconfig.txt"):
        path = ROOT / relative
        for line in path.read_text(encoding="utf-8").splitlines():
            if "ufshc" in line:
                ufs_evidence.append(f"  {relative}: {line}")

    regions = [
        ("application wrapper branches to the real LinuxLoader entry", 0x1348, 0x137C),
        ("Odin launcher prologue and GuidedFv lookup", 0x90EC, 0x9180),
        ("Odin launcher return followed by the LinuxLoader prologue", 0x921C, 0x9280),
        ("precondition and LocateProtocol backward slice", 0x933C, 0x943C),
        ("no-EM common path through the AVB call", 0x9608, 0x9700),
        ("normal UI path reaches its lazy service initializer", 0x66E60, 0x66F64),
        ("route after lazy initialization returns one", 0x6706C, 0x67148),
        ("service getter calls the lazy initializer", 0xA7920, 0xA79A0),
        ("lazy initializer guard", 0x989F0, 0x98A48),
        ("lazy initializer calls DeviceInfoInit", 0x98F70, 0x99018),
        ("DeviceInfo load and invalid-data defaults", 0x425EC, 0x42710),
        ("Engineering Mode synchronization", 0x9968, 0x99AC),
        ("IsUnlocked live-field reader", 0x41ED0, 0x41F24),
        ("SetUnlocked live-field writer", 0x424CC, 0x42530),
        ("libavb read_is_device_unlocked callback", 0x51048, 0x51074),
        ("call to the separate Odin launcher", 0x9838, 0x9890),
    ]

    lines = [
        "ABL DEVINFO CONDITIONAL STATE-PRESERVATION ANALYSIS",
        f"SOURCE {CURRENT.relative_to(ROOT)} SHA256 {sha256(CURRENT)}",
        f"DEVINFO {DEVINFO.relative_to(ROOT)} SHA256 {sha256(DEVINFO)}",
        "ADDRESS_NOTATION this section uses actual PE RVA/file offset; radare2 VA is actual+0x10000",
        "",
        "FINAL_CONCLUSION LIKELY NO",
        "PATH_CLASSIFICATION ERROR_ONLY",
        "",
        "BACKWARD_SLICE",
        "  actual 0x93f0 / r2 0x193f0: tbnz x0, #63, actual 0x9420 / r2 0x19420",
        "  containing block r2 0x193b4: jump=0x19420, fail/fallthrough=0x193f4",
        "  jump target: no direct DeviceInfo init and no Engineering Mode sync",
        "  fail/fallthrough: DeviceInfoInit at actual 0x425ec, then Engineering Mode sync at actual 0x998c",
        "  x0 is the EFI_STATUS returned by the indirect call at actual 0x93e4 / r2 0x193e4",
        "  x8 comes from *gBS at actual 0x15add0 / r2 0x16add0, then [x8 + 0x140]",
        "  EFI_BOOT_SERVICES +0x140 is LocateProtocol on AArch64 UEFI",
        "  LocateProtocol arguments are x0=&GUID, x1=NULL, x2=sp+0x10",
        f"  GUID bytes {memcard_guid_bytes.hex()} decode as {memcard_guid}",
        "  that GUID is gEfiMemCardInfoProtocolGuid, the Qualcomm SDCC/UFS unified card-info protocol",
        "  EFI_ERROR(Status) tests the high bit, exactly what tbnz x0,#63 does",
        "  therefore the no-EM edge is selected only when LocateProtocol returns an EFI error",
        "  actual 0x9348 is only a predecessor check: the call at actual 0x9344 / r2 target 0x69e08 must return zero",
        "  that earlier return does not feed 0x93f0 because LocateProtocol overwrites x0",
        "  no boot-mode value, UEFI variable, persistent byte, or function argument reaches the deciding test",
        "",
        "SEMANTIC_REACHABILITY",
        "  classification: ERROR_ONLY",
        "  this is not selected by recovery, download, charging, or another special boot mode",
        "  the target device is UFS-backed:",
        *ufs_evidence,
        "  a public Qualcomm ABL definition maps the GUID to a protocol whose card_type is UFS or MMC",
        "  missing that protocol on this retail UFS target is an initialization failure, not a normal retail state",
        "  the binary still handles the error and has a syntactic route to AVB, so it is not statically unsatisfiable",
        "  ABL alone cannot prove that the external UEFI driver publishes the protocol on every failed boot",
        "",
        "EXPLOITABILITY",
        "  this is conditional state preservation, not an unlock primitive",
        "  it requires LocateProtocol(MemCardInfo) to fail while DeviceInfo persistence remains readable",
        "  it also requires a valid persisted IsUnlocked=1 before the boot starts",
        "  no independent path that creates that persisted 1 was demonstrated",
        "  without such a writer, the last prerequisite is circular for the original unlock problem",
        "",
        "PUBLIC_REFERENCE",
        "  https://gitlab.com/Codeaurora/abl_tianocore_edk2/-/blob/uefi.lnx.6.4.9.r1-rel/QcomModulePkg/QcomModulePkg.dec",
        "  gEfiMemCardInfoProtocolGuid = 85c1f7d2-bce6-4f31-8f4d-d37e03d05eaa",
        "  https://gitlab.com/Codeaurora/abl_tianocore_edk2/-/blob/uefi.lnx.6.4.9.r1-rel/QcomModulePkg/Include/Protocol/EFICardInfo.h",
        "  the protocol header describes unified SDCC/UFS card information and card_type UFS or MMC",
        "",
        "NO_EM_TEMPORAL_ORDER",
        "  1. actual 0x93f0 takes the EFI-error edge and skips direct DeviceInfoInit",
        "  2. the live globals start zero in the PE: FirstReadDevInfo actual 0x170e20, DevInfo actual 0x170e28",
        f"     PE bytes actual 0x170e20..0x170e3f: {initial_live.hex()}",
        "  3. the actual 0x66e60 route that returns 1 at 0x67140 calls the lazy chain before AVB:",
        "     r2 0x196a0 -> 0x76e60 -> 0x76f58 -> 0xb7920 -> 0xb7938 -> 0xa89f0",
        "     -> 0xa8a14 -> 0xa8f70 -> 0xa8fbc -> 0x525ec DeviceInfoInit",
        "  4. on first use, DeviceInfoInit reads 0xcd0 bytes from persistence into live DevInfo at r2 0x180e28",
        "  5. valid persisted +0x0d=1 is therefore loaded after the divergence; invalid data takes defaults and writes zero",
        "  6. no resolved call between that lazy load and AVB reaches SetUnlocked or another live-field writer",
        "  7. actual 0x96f8 enters AVB; callback actual 0x51048 calls IsUnlocked and reads the live byte",
        "  if no earlier initializer ran and this lazy initializer is skipped or fails, the live byte stays at its PE-initialized zero",
        "  the static counterfactual works only when the card-info protocol lookup fails but DeviceInfo persistence still reads successfully",
        "",
        "NORMAL_TEMPORAL_ORDER",
        "  1. LocateProtocol succeeds and actual 0x93f4 calls DeviceInfoInit before normal boot setup",
        "  2. actual 0x998c BLInitToken, 0x9994 GetEMBit(3), and 0x99a4 dispatcher reach SetUnlocked",
        "  3. cset at actual 0x99a0 passes 1 for a nonzero mode bit and 0 for a clear bit",
        "  4. SetUnlocked writes live +0x0d and persists the complete structure",
        "  5. the later lazy DeviceInfoInit sees FirstReadDevInfo=1 and does not reload the old persisted byte",
        "  6. AVB reads the EM-synchronized live value; bit 3 clear means a prior 1 was cleared",
        "",
        "RECURSION_AUDIT",
        "  alleged recursive call: actual 0x9860 / r2 0x19860 calls actual 0x90ec / r2 0x190ec",
        "  actual 0x90ec has its own stack-frame prologue and returns at actual 0x9238",
        "  actual 0x9240 has a second, fresh prologue and is the real LinuxLoader entry",
        "  the application wrapper branches to r2 0x19240 at r2 0x11374",
        "  strings used by the 0x90ec helper identify GuidedFv lookup and Odin launch",
        "  actual 0x9858 only controls whether the optional 0xab960 preparation call runs; both edges join at 0x9860",
        "  no x0-x7 arguments are prepared at that join; the helper consumes globals and returns EFI_STATUS",
        "  radare2 merged the functions across a dead-loop/stack-check tail at r2 0x1923c",
        "  classification: function-boundary analysis artifact, not recursion",
        "  there is no earlier or nested LinuxLoader invocation that could run EM sync first",
        "",
        *string_hits(
            CURRENT,
            [
                b"Launching odin %d",
                b"LaunchAppFromGuidedFv odin, (%r)",
                b"GuidedFvProtocol is null, (%r)",
                b"GuidedFvProtocol->LaunchAppFromGuidedFv is null, (%r)",
                b"Failed to Launch Odin App: %d",
            ],
        ),
        "",
        "DEVINFO_FIELD_ACCESS_AUDIT",
        "  live structure: actual 0x170e28 / r2 0x180e28, size 0xcd0",
        "  IsUnlocked: live +0x0d, actual 0x170e35 / r2 0x180e35",
        "  direct reads: actual 0x41ef4 (debug value) and 0x41f14 (return value), both inside IsUnlocked",
        "  IsUnlocked callsites: actual 0x144e0, 0x14954, 0x42f30, 0x51060, 0x581dc, 0x98d54, 0xa7e78, 0xacc70",
        "  direct writes: actual 0x42524 SetUnlocked, actual 0x426fc invalid-data default",
        "  SetUnlocked dispatcher calls: actual 0x42150 and 0x42188; dispatcher callers are EM sync 0x99a4 and UI 0xacd2c",
        "  whole-live-structure reads that can overwrite +0x0d: actual 0x42468 and 0x4261c",
        "  no other effective-address xref to live +0x0d or live base produces another direct field writer",
        "  routines based at actual 0x4275c..0x42d6c touch bounded key/record ranges starting at +0x8a0 or later",
        "  callback actual 0x51048 calls IsUnlocked at 0x51060; there is no cached unlock copy in AvbOps",
        "",
        "READ_WRITE_DEVICEINFO_CALLS actual | r2 | mode | buffer | +0x0d effect",
        "  0x095d4 | 0x195d4 | read  | scratch actual 0x15af10 | copies persistent byte to scratch",
        "  0x09914 | 0x19914 | write | same scratch              | writes preserved scratch byte",
        "  0x423e0 | 0x523e0 | write | live DevInfo              | persists current byte",
        "  0x42468 | 0x52468 | read  | live DevInfo              | overwrites byte from persistence",
        "  0x42528 | 0x52528 | write | live after SetUnlocked    | persists explicit new byte",
        "  0x425a4 | 0x525a4 | write | live after +0x0e update   | persists unchanged +0x0d",
        "  0x4261c | 0x5261c | read  | live DevInfo              | first-load overwrite from persistence",
        "  0x42708 | 0x52708 | write | live defaults             | persists explicit zero",
        "  0x428b0 | 0x528b0 | write | live key-record update    | persists unchanged +0x0d",
        "  0x42dc8 | 0x52dc8 | write | live tail-field update    | persists unchanged +0x0d",
        "  0x42f10 | 0x52f10 | write | live key-record helper    | persists unchanged +0x0d",
        "  0x58df4 | 0x68df4 | read  | allocated scratch         | copies persistent byte to scratch",
        "  0x58f54 | 0x68f54 | write | same scratch              | writes preserved scratch byte",
        "",
        "DEVINFO_SNAPSHOT read-only observation; the counterfactual above assumes a valid persisted 1",
        f"  +0x0d u8 {devinfo[0x0d]}",
        f"  +0x0e u8 {devinfo[0x0e]}",
        f"  +0x90 u8 {devinfo[0x90]}",
        f"  +0xc88 u32le {int.from_bytes(devinfo[0xc88:0xc8c], 'little')}",
        "",
        "PATH_COMPARISON",
        "  branch condition | origin | path | EM sync | IsUnlocked before AVB | AVB source | confidence",
        "  EFI error | LocateProtocol(MemCardInfo) | 0x9420 -> 0x96a0 -> lazy DeviceInfoInit -> 0x96f8 | no | valid persisted byte loaded late; 1 survives, otherwise zero | live DevInfo+0x0d | high static state-flow, low retail reachability",
        "  EFI success | same LocateProtocol | 0x93f4 -> direct DeviceInfoInit -> 0x998c EM -> 0x96f8 | yes | equals GetEMBit(3); clear bit overwrites prior 1 with 0 | live DevInfo+0x0d | high",
        "",
        "WHY_LIKELY_NO",
        "  the state-preservation path is structurally valid after an EFI error: lazy DeviceInfoInit can load a persisted 1 and no EM writer follows",
        "  the deciding error is failure to locate the UFS/MMC card-info protocol on a confirmed UFS retail device",
        "  there is no normal retail or special-mode predicate that selects it",
        "  this makes a real S24 retail boot using the route unlikely, not confirmed impossible",
        "  CONFIRMED NO would require proving the external UEFI protocol is always installed on every boot that can still read devinfo",
        "  no state-changing device operation was used for this analysis",
    ]

    for label, start, end in regions:
        lines.extend(
            [
                "",
                f"REGION {label}",
                f"RANGE actual=0x{start:x}..0x{end:x} r2=0x{start + R2_BIAS:x}..0x{end + R2_BIAS:x}",
                *(line.rstrip() for line in disasm(CURRENT, start, end)),
            ]
        )
    return "\n".join(lines) + "\n"


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
    (OUT / "abl-devinfo-bypass-analysis.txt").write_text(bypass_analysis_evidence(), encoding="utf-8")
    for name in (
        "abl-oneui8-evidence.txt",
        "abl-oneui7-comparison.txt",
        "abl-cfg-ordering.txt",
        "devinfo-layout-evidence.txt",
        "abl-devinfo-bypass-analysis.txt",
    ):
        path = OUT / name
        print(f"{sha256(path)}  {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
