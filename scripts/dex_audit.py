#!/usr/bin/env python3
"""Reproducible DEX evidence extraction for the Engineering Mode audit."""

from __future__ import annotations

import hashlib
import io
import sys
import zipfile
import zlib
from collections import deque
from pathlib import Path

from loguru import logger

logger.remove()

from androguard.core.apk import APK  # noqa: E402
from androguard.core.dex import DEX, HiddenApiClassDataItem  # noqa: E402


# Android 16 contains hidden-api flag values newer than Androguard 4.1.4.
HiddenApiClassDataItem.DomapiApiFlag._missing_ = classmethod(
    lambda cls, value: cls.NONE
)

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK = ROOT / "framework"
OUT = ROOT / "decompiled"
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
            parsed = bytearray(data)
            if int.from_bytes(parsed[0x24:0x28], "little") == 0x78:
                # Androguard does not accept the DEX 041 container header yet.
                parsed[0x24:0x28] = (0x70).to_bytes(4, "little")
                parsed[12:32] = hashlib.sha1(parsed[32:]).digest()
                parsed[8:12] = zlib.adler32(parsed[12:]).to_bytes(4, "little")
            try:
                dex = DEX(bytes(parsed))
            except ValueError as error:
                if "Wrong Adler32 checksum" not in str(error):
                    raise
                parsed[12:32] = hashlib.sha1(parsed[32:]).digest()
                parsed[8:12] = zlib.adler32(parsed[12:]).to_bytes(4, "little")
                dex = DEX(bytes(parsed))
            yield name, data, dex


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
        "SOURCE framework/framework.jar",
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
        "SOURCE framework/framework.jar",
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



HLOS_POLICY_TERMS = {
    "CHANGE_OEM_UNLOCK_ALLOWED": ("change_oem_unlock_allowed",),
    "isOemUnlockAllowedByCarrier": ("isoemunlockallowedbycarrier",),
    "OemUnlockPreferenceController": ("oemunlockpreferencecontroller",),
    "OemLockService": ("oemlockservice",),
    "OemLockManager": ("oemlockmanager",),
    "PersistentDataBlockManager": ("persistentdatablockmanager",),
    "VaultKeeper": ("vaultkeeper",),
    "TrustChain": ("trustchain",),
    "KMX": ("kmxservice", "samsung.android.kmx"),
    "ro.oem_unlock_supported": ("ro.oem_unlock_supported",),
    "sys.oem_unlock_allowed": ("sys.oem_unlock_allowed",),
    "carrier rejection": ("carrier does not allow oem unlock",),
    "OEM-lock HAL": ("android.hardware.oemlock", "ioemlock"),
    "OMC/CSC": ("/omc/", "omc_path", "cscfeature"),
}

EXPECTED_HLOS_PACKAGES = (
    "com.android.settings",
    "com.samsung.android.kmxservice",
)


def matching_policy_terms(value: str) -> list[str]:
    lowered = value.lower()
    return [
        label
        for label, needles in HLOS_POLICY_TERMS.items()
        if any(needle in lowered for needle in needles)
    ]


def apk_package(archive: Path) -> str:
    if archive.suffix.lower() != ".apk":
        return ""
    try:
        return APK(str(archive), testzip=False).get_package() or ""
    except Exception:
        return ""


def write_hlos_oem_policy():
    archives = sorted(
        (
            path
            for path in FRAMEWORK.iterdir()
            if path.is_file() and path.suffix.lower() in {".apk", ".jar"}
        ),
        key=lambda path: path.name,
    )
    lines = [
        "HLOS OEM POLICY DEX EVIDENCE",
        "",
        "Coverage states:",
        "  MATCH: decoded DEX in a covered artifact contains a reportable reference.",
        "  NO_MATCH_IN_COVERED_ARTIFACTS: no decoded DEX match in the listed artifacts.",
        "  NOT_COLLECTED: the package required to answer the package-specific question is absent.",
        "",
        "Classification:",
        "  EXECUTABLE_REFERENCE: a matching class/method/field appears in a non-literal instruction.",
        "  CODE_STRING: a matching string is loaded by a const-string instruction.",
        "  UNREFERENCED_LITERAL: a matching DEX string has no observed const-string load.",
        "",
        "COVERED_ARTIFACTS",
    ]
    packages = set()
    findings = set()

    for archive in archives:
        package = apk_package(archive)
        if package:
            packages.add(package)
        package_text = package or "<manifest package unavailable>"
        lines.append(
            f"  {archive.relative_to(ROOT)} SHA256 {sha256(archive.read_bytes())} PACKAGE {package_text}"
        )
        for dex_name, data, dex in iter_dex(archive):
            loaded_literals = set()
            matching_literals = {
                value
                for value in dex.get_strings()
                if matching_policy_terms(value)
            }
            for cls in dex.get_classes():
                class_name = cls.get_name()
                for method in cls.get_methods():
                    code = method.get_code()
                    if code is None:
                        continue
                    method_id = f"{class_name}->{method.get_name()}{method.get_descriptor()}"
                    offset = 0
                    for instruction in code.get_bc().get_instructions():
                        opcode = instruction.get_name()
                        output = instruction.get_output()
                        labels = matching_policy_terms(output)
                        if labels:
                            classification = (
                                "CODE_STRING"
                                if opcode.startswith("const-string")
                                else "EXECUTABLE_REFERENCE"
                            )
                            for label in labels:
                                findings.add(
                                    (
                                        label,
                                        classification,
                                        str(archive.relative_to(ROOT)),
                                        dex_name,
                                        method_id,
                                        offset,
                                        opcode,
                                        output,
                                    )
                                )
                        if opcode.startswith("const-string"):
                            loaded_literals.update(
                                value for value in matching_literals if value in output
                            )
                        offset += instruction.get_length()
            for value in matching_literals - loaded_literals:
                for label in matching_policy_terms(value):
                    findings.add(
                        (
                            label,
                            "UNREFERENCED_LITERAL",
                            str(archive.relative_to(ROOT)),
                            dex_name,
                            "<none>",
                            -1,
                            "string-pool",
                            repr(value),
                        )
                    )
            lines.append(
                f"    DEX {dex_name} SIZE {len(data)} SHA256 {sha256(data)}"
            )

    lines.extend(["", "RESULTS"])
    if findings:
        lines.append("STATUS MATCH")
        for label, kind, archive, dex_name, method, offset, opcode, output in sorted(findings):
            location = "string-pool" if offset < 0 else f"offset 0x{offset:x}"
            lines.extend(
                [
                    f"  TERM {label}",
                    f"  CLASSIFICATION {kind}",
                    f"  LOCATION {archive}!{dex_name} {method} {location}",
                    f"  INSTRUCTION {opcode} {output}",
                    "",
                ]
            )
    else:
        lines.append("STATUS NO_MATCH_IN_COVERED_ARTIFACTS")

    lines.extend(["", "PACKAGE_COVERAGE"])
    findings_by_archive = {finding[2] for finding in findings}
    for package in EXPECTED_HLOS_PACKAGES:
        package_archives = {
            str(archive.relative_to(ROOT))
            for archive in archives
            if apk_package(archive) == package
        }
        if not package_archives:
            state = "NOT_COLLECTED"
        elif package_archives & findings_by_archive:
            state = "MATCH"
        else:
            state = "NO_MATCH_IN_COVERED_ARTIFACTS"
        lines.append(f"  {package} {state}")
    lines.extend(
        [
            "",
            "MISSING_COVERAGE",
            "  Package identity is read from each collected APK manifest.",
            "  Runtime package references in dumps or framework code do not mean that package's APK was collected.",
        ]
    )
    missing = [package for package in EXPECTED_HLOS_PACKAGES if package not in packages]
    if missing:
        lines.extend(f"  {package}" for package in missing)
    else:
        lines.append("  none")

    (OUT / "dex-hlos-oem-policy-evidence.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def main():
    write_framework_api()
    write_satsservice()
    write_callsites()
    write_hlos_oem_policy()
    for path in sorted(OUT.glob("*.txt")):
        if path.name.startswith(
            ("framework-", "dex-callsites-", "dex-getstatus-", "dex-hlos-")
        ):
            print(f"{path.relative_to(ROOT)}\t{path.stat().st_size}\t{sha256(path.read_bytes())}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise
