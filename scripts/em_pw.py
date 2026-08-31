#!/usr/bin/env python3
"""Read-only AArch64 analysis helpers for the ABL LinuxLoader EM/password audit.

Builds on abl_string_xref.sweep() (resumable, so constant pools do not truncate
the sweep) and adds:
  * a cached instruction index
  * call-graph / reverse call-graph construction
  * function boundary estimation from `bl` targets
  * pretty disassembly of an arbitrary RVA range

Nothing here writes to any device or modifies any artifact.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs  # noqa: E402

from abl_string_xref import executable_ranges, pe_layout, sweep  # noqa: E402

MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True

CACHE: dict[Path, dict] = {}


class Image:
    def __init__(self, path: str):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.layout = pe_layout(self.data)
        self.entry = self.layout["entry_rva"]
        self._insns: dict[int, object] | None = None
        self._order: list[int] | None = None
        self._calls: dict[int, int] | None = None
        self._funcs: list[int] | None = None

    # ---- sweep -----------------------------------------------------------
    @property
    def insns(self) -> dict[int, object]:
        if self._insns is None:
            self._insns = {}
            self._order = []
            for ins in sweep(self.data, self.layout):
                self._insns[ins.address] = ins
                self._order.append(ins.address)
        return self._insns

    @property
    def order(self) -> list[int]:
        self.insns  # force build
        return self._order

    def at(self, rva: int):
        return self.insns.get(rva)

    # ---- call graph ------------------------------------------------------
    @property
    def calls(self) -> dict[int, int]:
        """{call_site_rva: bl_target_rva}"""
        if self._calls is None:
            self._calls = {}
            for addr in self.order:
                ins = self.insns[addr]
                if ins.mnemonic == "bl" and ins.operands:
                    self._calls[addr] = ins.operands[0].imm
        return self._calls

    @property
    def func_starts(self) -> list[int]:
        if self._funcs is None:
            starts = {self.entry}
            for _site, target in self.calls.items():
                starts.add(target)
            self._funcs = sorted(starts)
        return self._funcs

    def func_of(self, rva: int) -> int:
        """Largest known function start <= rva."""
        best = None
        for start in self.func_starts:
            if start <= rva:
                best = start
            else:
                break
        return best if best is not None else rva

    def func_end(self, start: int) -> int:
        idx = None
        for i, s in enumerate(self.func_starts):
            if s == start:
                idx = i
                break
        if idx is None:
            return start
        if idx + 1 < len(self.func_starts):
            return self.func_starts[idx + 1]
        return max(self.insns) + 4

    def body(self, start: int):
        end = self.func_end(start)
        return [self.insns[a] for a in self.order if start <= a < end]

    def callers(self, target: int) -> list[int]:
        return sorted(site for site, tgt in self.calls.items() if tgt == target)

    def callees(self, start: int) -> list[tuple[int, int]]:
        """[(call_site, target)] in address order for the function at `start`."""
        end = self.func_end(start)
        return [(s, t) for s, t in sorted(self.calls.items()) if start <= s < end]

    # ---- printing --------------------------------------------------------
    def dis(self, lo: int, hi: int, show_bytes: bool = False) -> str:
        out = []
        for a in self.order:
            if lo <= a < hi:
                ins = self.insns[a]
                raw = ""
                if show_bytes:
                    raw = ins.bytes.hex() + "  "
                target = ""
                if ins.mnemonic in ("bl", "b") and ins.operands:
                    t = ins.operands[0].imm
                    target = f"  ; -> 0x{t:06x}{'  [X]' if t < 0x1000 or t > 0x190000 else ''}"
                out.append(f"{a:06x}: {raw}{ins.mnemonic:8} {ins.op_str}{target}")
        return "\n".join(out)

    def printable(self, rva: int, length: int = 64) -> str:
        d = self.data[rva : rva + length]
        return "".join(chr(c) if 32 <= c < 127 else "." for c in d)

    def cstr(self, rva: int, limit: int = 256) -> str:
        d = self.data[rva : rva + limit]
        end = d.find(b"\x00")
        if end >= 0:
            d = d[:end]
        return d.decode("ascii", "replace")


def load(path: str) -> Image:
    p = Path(path)
    if p not in CACHE:
        CACHE[p] = Image(path)
    return CACHE[p]


def upward(img: Image, roots: list[int], entry: int | None = None, maxdepth: int = 40):
    """BFS up the reverse call graph from `roots` toward `entry`.

    Returns {func_rva: depth}. Prints the chain(s) it found.
    """
    if entry is None:
        entry = img.entry
    seen: dict[int, int] = {}
    frontier = [(r, 0) for r in roots]
    for r, _d in frontier:
        seen.setdefault(r, 0)
    chains: list[list[int]] = []
    while frontier:
        nxt = []
        for fn, depth in frontier:
            if depth >= maxdepth:
                continue
            for site in img.callers(fn):
                caller = img.func_of(site)
                if caller in seen:
                    continue
                seen[caller] = depth + 1
                nxt.append((caller, depth + 1))
        frontier = nxt
    return seen


def path_to(img: Image, target: int, entry: int | None = None) -> list[int]:
    """One shortest caller chain from entry down to `target`."""
    if entry is None:
        entry = img.entry
    # BFS on the forward graph from entry
    from collections import deque

    prev: dict[int, int] = {}
    seen = {entry}
    q = deque([entry])
    while q:
        cur = q.popleft()
        if cur == target:
            break
        for _site, tgt in img.callees(cur):
            if tgt not in seen and 0x1000 <= tgt <= max(img.insns):
                seen.add(tgt)
                prev[tgt] = cur
                q.append(tgt)
    if target not in seen and target != entry:
        return []
    chain = [target]
    while chain[-1] != entry:
        p = prev.get(chain[-1])
        if p is None:
            return list(reversed(chain))
        chain.append(p)
    return list(reversed(chain))


def path_up(img: Image, target: int, entry: int | None = None) -> list[int]:
    """One shortest caller chain from target up to entry (reverse BFS)."""
    if entry is None:
        entry = img.entry
    from collections import deque

    prev: dict[int, int] = {target: -1}
    q = deque([target])
    while q:
        cur = q.popleft()
        if cur == entry:
            break
        for site in img.callers(cur):
            caller = img.func_of(site)
            if caller in prev:
                continue
            prev[caller] = cur
            q.append(caller)
    if entry not in prev:
        return []
    chain = [entry]
    cur = entry
    while cur != target:
        nxt = prev.get(cur)
        if nxt is None:
            break
        chain.append(nxt)
        cur = nxt
    return chain
