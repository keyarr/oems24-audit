#!/usr/bin/env python3
"""Hash scripts and derived audit evidence into a deterministic TSV manifest."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT
DESTINATION = AUDIT / "manifests" / "derived-evidence.tsv"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def producer(path: Path) -> str:
    name = path.name
    if name == "abl-czd1-vs-dzdp-evidence.txt":
        return "python3 scripts/abl_audit_czd1.py"
    if name in (
        "abl-uefi-var-consumer-map.txt",
        "ta-preauth-handler-triage.txt",
        "xbl-odin-surface-map.txt",
    ):
        return "manual static triage (capstone/objdump/strings), see file header"
    if name.startswith("abl-") or name.startswith("devinfo-layout"):
        return "python3 scripts/abl_audit.py"
    if name.startswith("ta-"):
        return "python3 scripts/ta_audit.py"
    if name.startswith("native-") or name.startswith("aidl-transaction"):
        return "python3 scripts/native_audit.py"
    if name.startswith("dex-") or name.startswith("framework-"):
        return "python3 scripts/dex_audit.py"
    if name.startswith("services-"):
        return "scripts/services_dex_audit.sh"
    if path.parent.name == "scripts":
        return "source procedure"
    if name == "historical-daseul-ess.md":
        return "manual synthesis of cited historical public evidence"
    if name == "oem-lock-service-evidence.txt":
        return "manual reconstruction of services.jar/HAL chain"
    if path == AUDIT / "notes" / "findings.md":
        return "manual synthesis of cited primary/derived evidence"
    if path == AUDIT / "README.md":
        return "audit documentation"
    return "see report/provenance manifests"


def main() -> None:
    paths = set(AUDIT.glob("scripts/*"))
    paths.update(AUDIT.glob("decompiled/*.txt"))
    paths.update(AUDIT.glob("decompiled/*.json"))
    paths.update(AUDIT.glob("notes/*"))
    paths.add(AUDIT / "README.md")
    paths = {path for path in paths if path.is_file() and "__pycache__" not in path.parts}
    lines = ["sha256\tsize\tpath\tproducer"]
    for path in sorted(paths, key=lambda p: p.relative_to(ROOT).as_posix()):
        lines.append(
            "\t".join(
                [
                    sha256(path),
                    str(path.stat().st_size),
                    path.relative_to(ROOT).as_posix(),
                    producer(path),
                ]
            )
        )
    DESTINATION.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {DESTINATION.relative_to(ROOT)} with {len(lines) - 1} entries")


if __name__ == "__main__":
    main()
