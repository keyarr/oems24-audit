#!/usr/bin/env python3
"""Reproducible DEX evidence extraction for the Engineering Mode audit."""

from __future__ import annotations

import hashlib
import io
import sys
import zipfile
from collections import deque
from pathlib import Path

from loguru import logger

logger.remove()

from androguard.core.dex import DEX, HiddenApiClassDataItem  # noqa: E402


# Android 16 contains hidden-api flag values newer than Androguard 4.1.4.
HiddenApiClassDataItem.DomapiApiFlag._missing_ = classmethod(
    lambda cls, value: cls.NONE
)

ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK = ROOT / "audit" / "framework"
OUT = ROOT / "audit" / "decompiled"
OUT.mkdir(parents=True, exist_ok=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iter_dex(archive: Path):
    with zipfile.ZipFile(archive) as zf:
        names = sorted(
            (name for name in zf.namelist() if name.startswith("classes") and name.endswith(".dex")),
            key=lambda name: (len(name), name),
        )
        for name in names:
            data = zf.read(name)
            yield name, data, DEX(data)


def field_value(field):
    value = field.get_init_value()
    if value is None:
        return "<not encoded>"
    result = value.get_value()
    if isinstance(result, bytes):
        return result.hex()
    return repr(result)


def method_lines(method):
    lines = [
        f"METHOD {method.get_class_name()}->{method.get_name()}{method.get_descriptor()}"
    ]
    code = method.get_code()
    if code is None:
        lines.append("  <native/abstract: no DEX code>")
        return lines
    offset = 0
    for instruction in code.get_bc().get_instructions():
        lines.append(
            f"  {offset:04x}: {instruction.get_name():24} {instruction.get_output()}"
        )
        offset += instruction.get_length()
    return lines


def write_framework_api():
    jar = FRAMEWORK / "framework.jar"
    chosen = None
    dex_meta = []
    for name, data, dex in iter_dex(jar):
        dex_meta.append(f"{name}\t{len(data)}\t{sha256(data)}")
        for cls in dex.get_classes():
            if cls.get_name() == "Lcom/samsung/android/service/EngineeringMode/EngineeringModeManager;":
                chosen = (name, dex, cls)
    if chosen is None:
        raise RuntimeError("EngineeringModeManager not found")

    name, _, cls = chosen
    lines = [
        "SOURCE audit/framework/framework.jar",
        f"DEX {name}",
        f"JAR_SHA256 {sha256(jar.read_bytes())}",
        "DEX_ENTRIES",
        *dex_meta,
        "",
        f"CLASS {cls.get_name()}",
        "STATIC_FIELDS",
    ]
    selected_prefixes = (
        "MODE_",
        "ERROR_",
        "NATIVE_",
    )
    for field in cls.get_fields():
        if field.get_name().startswith(selected_prefixes):
            lines.append(
                f"  {field.get_name()} {field.get_descriptor()} = {field_value(field)}"
            )

    wanted = {
        "<init>",
        "getStatus",
        "getModes",
        "getNumOfModes",
        "makeTokenReq",
        "makeTokenReqForESS",
        "installToken",
        "removeToken",
        "essCommand",
    }
    lines.append("")
    lines.append("METHODS")
    for method in cls.get_methods():
        if method.get_name() in wanted:
            lines.extend(method_lines(method))
            lines.append("")
    (OUT / "framework-engineeringmode-api.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def write_satsservice():
    jar = FRAMEWORK / "framework.jar"
    targets = {
        "Lcom/android/server/SatsService;": {"<clinit>", "<init>", "commandForESS"},
        "Lcom/android/server/SatsService$AtCmdHandler;": {
            "<init>",
            "doWork",
            "executeEmAtCommand",
            "isValidCommand",
            "run",
            "selectTarget",
        },
        "Lcom/android/server/SatsService$EngModesCmdHelper;": None,
        "Lcom/android/server/AuthUnlockATCmd;": {
            "<clinit>",
            "<init>",
            "getCmd",
            "processCmd",
            "nativeSessionAccept",
            "nativeSessionComplete",
            "nativeWipe",
        },
    }
    lines = [
        "SOURCE audit/framework/framework.jar",
        f"JAR_SHA256 {sha256(jar.read_bytes())}",
    ]
    for dex_name, data, dex in iter_dex(jar):
        for cls in dex.get_classes():
            class_name = cls.get_name()
            if class_name not in targets:
                continue
            wanted = targets[class_name]
            lines.extend(["", f"DEX {dex_name} SHA256 {sha256(data)}", f"CLASS {class_name}", "FIELDS"])
            for field in cls.get_fields():
                lines.append(
                    f"  {field.get_name()} {field.get_descriptor()} = {field_value(field)}"
                )
            lines.append("METHODS")
            for method in cls.get_methods():
                if wanted is None or method.get_name() in wanted:
                    lines.extend(method_lines(method))
                    lines.append("")
    (OUT / "framework-satsservice.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def scan_archive_callsites(archive: Path):
    lines = [
        f"SOURCE {archive.relative_to(ROOT)}",
        f"ARCHIVE_SHA256 {sha256(archive.read_bytes())}",
        "Only actual DEX instructions are reported; constant-pool strings alone are excluded.",
    ]
    count = 0
    reflection_count = 0
    for dex_name, data, dex in iter_dex(archive):
        lines.append(f"\nDEX {dex_name} SIZE {len(data)} SHA256 {sha256(data)}")
        for cls in dex.get_classes():
            class_name = cls.get_name()
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                instructions = []
                offset = 0
                for instruction in code.get_bc().get_instructions():
                    instructions.append(
                        (offset, instruction.get_name(), instruction.get_output())
                    )
                    offset += instruction.get_length()
                for index, (off, opcode, output) in enumerate(instructions):
                    direct = (
                        "Lcom/samsung/android/service/EngineeringMode/EngineeringModeManager;->"
                        in output
                    )
                    reflection = (
                        opcode.startswith("const-string")
                        and any(
                            marker in output
                            for marker in (
                                '"getStatus"',
                                '"makeTokenReq"',
                                '"installToken"',
                                '"MODE_CUST_KERNEL"',
                                '"com.samsung.android.service.EngineeringMode.EngineeringModeManager"',
                            )
                        )
                    )
                    if not direct and not reflection:
                        continue
                    if direct:
                        count += 1
                        kind = "DIRECT_CALLSITE"
                    else:
                        reflection_count += 1
                        kind = "REFLECTION_STRING_IN_CODE"
                    lines.append(
                        f"\n{kind} {class_name}->{method.get_name()}{method.get_descriptor()} at {off:04x}"
                    )
                    start = max(0, index - 14)
                    end = min(len(instructions), index + 18)
                    for n in range(start, end):
                        ioff, iop, iout = instructions[n]
                        marker = ">" if n == index else " "
                        lines.append(f" {marker} {ioff:04x}: {iop:24} {iout}")
    lines.extend(
        [
            "",
            f"DIRECT_CALLSITE_COUNT {count}",
            f"REFLECTION_STRING_IN_CODE_COUNT {reflection_count}",
        ]
    )
    return "\n".join(lines) + "\n"


def resolve_recent_constant(instructions, index, register):
    """Best-effort straight-line provenance for the argument register."""
    tracked = register
    for n in range(index - 1, max(-1, index - 80), -1):
        _, opcode, output = instructions[n]
        parts = [part.strip() for part in output.split(",")]
        if not parts or parts[0] != tracked:
            continue
        if opcode.startswith("const") and not opcode.startswith("const-string"):
            if len(parts) >= 2:
                return parts[1], n
            return "<malformed const>", n
        if opcode.startswith("move") and len(parts) >= 2:
            tracked = parts[1]
            continue
        # An intervening definition whose value is not a simple constant.
        if opcode not in {"if-eq", "if-ne"}:
            return "<dynamic>", n
    return "<dynamic/parameter>", None


def write_getstatus_summary():
    targets = [FRAMEWORK / "framework.jar"] + sorted(FRAMEWORK.glob("*.apk"))
    lines = [
        "Static straight-line audit of actual EngineeringModeManager.getStatus(int) invocations.",
        "The literal column is conservative: unresolved control/data flow is labelled dynamic.",
    ]
    literal_counts = {}
    for archive in targets:
        lines.extend(["", f"SOURCE {archive.relative_to(ROOT)} SHA256 {sha256(archive.read_bytes())}"])
        for dex_name, data, dex in iter_dex(archive):
            for cls in dex.get_classes():
                class_name = cls.get_name()
                if class_name.startswith(
                    "Lcom/samsung/android/service/EngineeringMode/EngineeringModeManager"
                ):
                    continue
                for method in cls.get_methods():
                    code = method.get_code()
                    if code is None:
                        continue
                    instructions = []
                    offset = 0
                    for instruction in code.get_bc().get_instructions():
                        instructions.append(
                            (offset, instruction.get_name(), instruction.get_output())
                        )
                        offset += instruction.get_length()
                    for index, (off, opcode, output) in enumerate(instructions):
                        if (
                            "Lcom/samsung/android/service/EngineeringMode/EngineeringModeManager;->getStatus(I)I"
                            not in output
                        ):
                            continue
                        prefix = output.split(", Lcom/samsung", 1)[0]
                        registers = [part.strip(" {}") for part in prefix.split(",")]
                        arg_register = registers[-1] if len(registers) >= 2 else "<?>"
                        literal, definition_index = resolve_recent_constant(
                            instructions, index, arg_register
                        )
                        literal_counts[literal] = literal_counts.get(literal, 0) + 1
                        lines.append(
                            f"{dex_name}\t{class_name}->{method.get_name()}{method.get_descriptor()}"
                            f"\toffset=0x{off:x}\targ={arg_register}\tliteral={literal}"
                        )
                        if definition_index is not None:
                            doff, dop, dout = instructions[definition_index]
                            lines.append(f"  def 0x{doff:x}: {dop} {dout}")
                        lines.append(f"  call 0x{off:x}: {opcode} {output}")
    lines.extend(["", "LITERAL_COUNTS"])
    for literal, count in sorted(literal_counts.items()):
        lines.append(f"  {literal}\t{count}")
    (OUT / "dex-getstatus-fixed-summary.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def write_callsites():
    targets = [FRAMEWORK / "framework.jar"] + sorted(FRAMEWORK.glob("*.apk"))
    for target in targets:
        output_name = f"dex-callsites-{target.stem}.txt"
        (OUT / output_name).write_text(
            scan_archive_callsites(target), encoding="utf-8"
        )
    write_getstatus_summary()


def main():
    write_framework_api()
    write_satsservice()
    write_callsites()
    for path in sorted(OUT.glob("*.txt")):
        if path.name.startswith(("framework-", "dex-callsites-", "dex-getstatus-")):
            print(f"{path.relative_to(ROOT)}\t{path.stat().st_size}\t{sha256(path.read_bytes())}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise
