#!/usr/bin/env python3
"""Extract the stable-AIDL surface of a Samsung NDK shim (fkeymaster / vaultkeeper).

Replicates the logic of native_audit.py:aidl_report() but for the
vendor.samsung.hardware.security.fkeymaster / .vaultkeeper interfaces.  It
locates each Bp<Ifc>::<method> symbol, disassembles it, and recovers the
transaction code (the `mov w1, #<txn>` immediately before the transact call).
No device access; read-only on the supplied binary.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SO = ROOT / "binaries_extra" / "vendor.samsung.hardware.security.fkeymaster-V1-ndk.so"
OUT = ROOT / "decompiled"
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True


def resolve() -> tuple[Path, str, Path]:
    import argparse
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--so", type=Path, default=DEFAULT_SO)
    p.add_argument("--iface", type=str, default="fkeymaster")
    p.add_argument("--out", type=Path, default=OUT)
    args, _ = p.parse_known_args()
    return args.so.resolve(), args.iface, args.out


@__import__("functools").lru_cache(maxsize=None)
def demangle(name: str) -> str:
    return subprocess.run(["c++filt", name], check=True, text=True,
                          capture_output=True).stdout.strip()


def sha256(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NativeSo:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        elf = ELFFile(path.open("rb"))
        self.header = dict(elf.header)
        self.symbols = []
        for sec in (elf.get_section_by_name(".dynsym"), elf.get_section_by_name(".symtab")):
            if not sec:
                continue
            for s in sec.iter_symbols():
                if s.name:
                    self.symbols.append({"name": s.name, "value": s["st_value"],
                                         "size": s["st_size"], "info": s["st_info"],
                                         "shndx": s["st_shndx"]})
        # build a VA->file map
        self.loads = [(int(s["p_vaddr"]), int(s["p_offset"]), int(s["p_filesz"]))
                      for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]

    def va_to_file(self, va: int) -> int:
        for v, off, sz in self.loads:
            if v <= va < v + sz:
                return off + va - v
        raise ValueError(f"VA 0x{va:x} not file-backed")

    def disasm(self, start: int, end: int) -> list:
        raw = self.data[self.va_to_file(start): self.va_to_file(start) + (end - start)]
        return list(MD.disasm(raw, start))

    def metadata(self) -> list[str]:
        h = self.header
        return [
            f"INPUT {self.path.relative_to(ROOT)}",
            f"SIZE {self.path.stat().st_size}",
            f"SHA256 {sha256(self.path)}",
            f"CLASS {h['e_ident']['EI_CLASS']} MACHINE {h['e_machine']} TYPE {h['e_type']}",
        ]


def bp_methods(so: NativeSo, iface: str) -> list[tuple[str, int, int, int]]:
    """Return (method, txn, value, size) for each Bp<Ifc>::method."""
    marker = f"BpSeh{iface}::"
    special = {"getInterfaceHash", "getInterfaceVersion", f"BpSeh{iface}"}
    out = []
    for sym in so.symbols:
        d = demangle(sym["name"])
        pos = d.find(marker)
        if pos < 0 or "(" not in d:
            continue
        method = d[pos + len(marker):].split("(")[0]
        if not method or method[0] in "~" or method in special:
            continue
        value, size = sym["value"], sym["size"]
        if not value:
            continue
        insns = so.disasm(value, value + (size or 0x200))
        txn = None
        for i, insn in enumerate(insns):
            if insn.mnemonic == "mov" and insn.op_str.startswith("w1, #"):
                imm = int(insn.op_str.split("#", 1)[1], 0)
                if 1 <= imm <= 0x7FFF:
                    # require a following bl (the transact call) within 8 insns
                    tail = insns[i + 1: i + 9]
                    if any(j.mnemonic == "bl" for j in tail):
                        txn = imm
                        break
        out.append((method, txn if txn is not None else -1, value, size))
    # sort by txn
    return sorted(out, key=lambda r: (r[1] if r[1] >= 0 else 0x10000, r[0]))


def imports_report(so: NativeSo, iface: str, methods) -> str:
    lines = [
        f"STABLE-AIDL NDK SHIM EVIDENCE: {iface}",
        "",
        *so.metadata(),
        "",
        "Bp METHODS AND TRANSACTION CODES (recovered from the `mov w1,#txn` before transact)",
        f"  method_count={len(methods)}",
    ]
    for method, txn, value, size in methods:
        lines.append(f"  txn={txn if txn>=0 else '??':<4} VA=0x{value:06x} sz={size:<5} {method}")
    # disasm evidence of the transaction-code block for each Bp method
    lines += ["", "METHOD TXN-SETTING DISASM (mov w1,#txn immediately before transact bl)"]
    for method, txn, value, size in methods:
        lines.append(f"  --- {method} (txn={txn}) VA=0x{value:06x} ---")
        try:
            insns = so.disasm(value, value + 0x40)
        except ValueError as e:
            lines.append(f"    (skip {e})")
            continue
        for i in insns:
            mark = " <== txn" if (i.mnemonic == "mov" and i.op_str.startswith("w1, #")
                                   and int(i.op_str.split("#")[1], 0) == txn) else ""
            lines.append(f"    VA 0x{i.address:06x}  {i.mnemonic:<8} {i.op_str}{mark}")
    # dynamic imports (undefined symbols)
    undef = sorted({demangle(s["name"]) for s in so.symbols
                    if str(s["shndx"]).startswith("SHN_UNDEF")})
    lines += ["", "DYNAMIC_IMPORTS (undefined symbols, demangled)"]
    for u in undef:
        lines.append(f"  {u}")
    # a few notable exported methods (Bn side / impl)
    bn = [demangle(s["name"]) for s in so.symbols if f"BnSeh{iface.capitalize()}::" in demangle(s["name"])]
    lines += [f"", f"Bn METHODS (server side impl names), count={len(bn)}"]
    for b in sorted(set(bn)):
        lines.append(f"  {b}")
    return "\n".join(lines) + "\n"


def main() -> None:
    so, iface, out = resolve()
    elf = NativeSo(so)
    out.mkdir(parents=True, exist_ok=True)
    methods = bp_methods(elf, iface)
    content = imports_report(elf, iface, methods)
    dest = out / f"{iface}-V1-ndk-imports.txt"
    dest.write_text(content, encoding="utf-8")
    print(f"wrote {dest.relative_to(ROOT)} ({len(content.encode('utf-8'))} bytes)")
    print(f"  recovered {len(methods)} Bp methods; methods with unknown txn: "
          f"{sum(1 for m in methods if m[1] < 0)}")
    for m in methods:
        print(f"    txn={m[1] if m[1]>=0 else '??':<4} {m[0]}")


if __name__ == "__main__":
    main()
