#!/usr/bin/env python3
"""Offline Unicorn harness for the engmode TA BUG-1 question.

Emulates VA 0xa5cc (em_token_verify_token_signature path, file 0xb5cc)
with a controlled parsed struct and watches:
  - the w5 authenticated-length computation (VA 0xa674, file 0xb674),
  - out-of-bounds reads/writes (exact ctx/parsed/stack maps + guards),
  - whether flow aborts before doing anything with the digest,
  - the function return value (w0).

Read-only vs the repo: never touches the device, emulates em.img bytes.
Requires: pip install unicorn
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / "partitions" / "em.img"

FUNC_VA = 0xA5CC          # em_token_verify_token_signature
W5_SITE_FILE = 0xB674     # add w5, w9, #0x2a  (VA 0xa674)
FUNC_END_FILE = 0xB954

CTX_SIZE = 0x352E0
CTX_BASE = 0x40000000
PARSED_BASE = 0x50000000
# arg1 is a large per-request heap (key material lives at +0x4BBBC); size it generously
PARSED_SIZE = 0x80000
STACK_BASE = 0x60000000
STACK_SIZE = 0x200000
RET_MAGIC = 0xFFFFFFFFFFFFFF00

VENEER_NAMES = {
    0x20: "qsee_log", 0x30: "qsee_is_ns_range", 0x40: "qsee_malloc",
    0x50: "qsee_free", 0x60: "qsee_get_random_bytes", 0x70: "qsee_kdf",
    0x80: "qsee_stor_write_sectors", 0x90: "qsee_stor_read_sectors",
    0xA0: "qsee_get_secure_state", 0xB0: "qsee_stor_device_init",
    0xC0: "qsee_stor_open_partition", 0xD0: "qsee_stor_device_get_info",
    0xE0: "qsee_stor_add_partition", 0xF0: "qsee_err_fatal",
    0x100: "__funcs_on_exit", 0x110: "cmnlib_init", 0x120: "GPAppLib_init",
    0x130: "GPAppLib_appInit", 0x140: "GPAppLib_appShutdown",
    0x150: "cmnlib_release", 0x160: "GPAppLib_handleRequest",
    0x170: "CApp_openSession", 0x180: "qsee_prng_getdata",
    0x190: "qsee_printf",
}
VENEER_END = 0x1A0

MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


class Result:
    def __init__(self):
        self.w5_at_sites: list[tuple[int, int]] = []
        self.bl_calls: list[tuple[int, int]] = []
        self.oob: list[tuple[int, int, int, bool]] = []
        self.veneers: list[tuple[int, str]] = []
        self.pac_skips = 0
        self.w0 = None
        self.stopped = ""


def build_machine(count: int, res: Result, zero_fill_oob: bool):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED
    from unicorn import UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED
    from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
        UC_ARM64_REG_LR, UC_ARM64_REG_SP, UC_ARM64_REG_PC,
        UC_ARM64_REG_W0, UC_ARM64_REG_W5,
    )

    data = IMAGE.read_bytes()

    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    # text PT_LOAD: file 0x1000 -> VA 0, RWX for simplicity (harness only)
    text = data[0x1000:0x1000 + 0x123174]
    mu.mem_map(0, 0x124000)
    mu.mem_write(0, text)
    # data PT_LOADs at their VAs
    mu.mem_map(0x124000, 0x1000)
    mu.mem_write(0x124000, data[0x125000:0x125000 + 0xD3])
    mu.mem_map(0x125000, 0xF000)
    mu.mem_write(0x125000, data[0x126000:0x126000 + 0xE2F8])
    mu.mem_map(0x134000, 0x4000)
    mu.mem_write(0x134000, data[0x135000:0x135000 + 0x36D0])
    mu.mem_map(0x138000, 0x20000)
    mu.mem_write(0x138000, data[0x139000:0x139000 + 0x176B5])
    # exact ctx heap + guards (neighbors left unmapped)
    mu.mem_map(CTX_BASE, 0x36000)  # one page past the exact 0x352e0 object
    mu.mem_write(CTX_BASE, b"\x00" * CTX_SIZE)
    # parsed struct, exact + guards
    mu.mem_map(PARSED_BASE, 0x80000)
    parsed = bytearray(PARSED_SIZE)
    struct.pack_into("<H", parsed, 0x1C, count)  # +0x1c mode count
    mu.mem_write(PARSED_BASE, bytes(parsed))
    # stack
    mu.mem_map(STACK_BASE, STACK_SIZE)
    sp = STACK_BASE + STACK_SIZE - 0x100
    mu.reg_write(UC_ARM64_REG_SP, sp)
    mu.reg_write(UC_ARM64_REG_X0, CTX_BASE)
    mu.reg_write(UC_ARM64_REG_X1, PARSED_BASE)
    mu.reg_write(UC_ARM64_REG_X2, CTX_BASE + 0x342E8)  # as the gate sets it
    mu.reg_write(UC_ARM64_REG_LR, RET_MAGIC)

    malloc_next = [CTX_BASE + CTX_SIZE + 0x100000]

    def hook_code(uc, address, size, _user):
        if address == RET_MAGIC & ((1 << 64) - 1):
            res.w0 = uc.reg_read(UC_ARM64_REG_W0)
            res.stopped = f"returned w0={res.w0:#x}"
            uc.emu_stop()
            return
        if 0x20 <= address < VENEER_END and address % 0x10 == 0:
            name = VENEER_NAMES.get(address, f"veneer+{address:#x}")
            res.veneers.append((address, name))
            lr = uc.reg_read(UC_ARM64_REG_LR)
            if address == 0x40:  # qsee_malloc(w0=size)
                size = uc.reg_read(UC_ARM64_REG_X0)
                ptr = malloc_next[0]
                malloc_next[0] += (size + 0xFFF) & ~0xFFF
                try:
                    uc.mem_map(ptr, (size + 0xFFF) & ~0xFFF)
                except Exception:
                    pass
                uc.reg_write(UC_ARM64_REG_X0, ptr)
            elif address == 0x60:  # random: pattern fill
                uc.mem_write(uc.reg_read(UC_ARM64_REG_X0),
                             b"\xA5" * uc.reg_read(UC_ARM64_REG_X1))
                uc.reg_write(UC_ARM64_REG_X0, 0)
            else:
                uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, lr)
            return
        if address == W5_SITE_FILE - 0x1000:  # next exec check below instead
            pass
        # PAC/BTI tolerance
        try:
            raw = uc.mem_read(address, 4)
        except Exception:
            return
        ins = next(MD.disasm(raw, address), None)
        if ins is not None and (
            ins.mnemonic in ("pacibsp", "autibsp") or ins.mnemonic.startswith("bti")
            or ins.mnemonic in ("pacib", "autib", "paciza", "hint")
        ):
            res.pac_skips += 1
            uc.reg_write(UC_ARM64_REG_PC, address + 4)
            return
        if ins is not None and ins.mnemonic == "bl":
            try:
                tgt = int(ins.op_str.strip().lstrip("#"), 16)
                res.bl_calls.append((address - 0x1000 + 0x1000, tgt))
            except ValueError:
                pass
        # w5 sample right after the authenticated-length add (file 0xb674)
        if address == (W5_SITE_FILE + 4 - 0x1000):
            res.w5_at_sites.append((address, uc.reg_read(UC_ARM64_REG_W5)))

    def hook_bad(uc, access, address, size, value, _user):
        from unicorn import UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED
        pc = uc.reg_read(UC_ARM64_REG_PC)
        is_write = access in (UC_MEM_WRITE_UNMAPPED,)
        res.oob.append((pc, address, size, is_write))
        if len(res.oob) > 200:
            uc.emu_stop()
            return False
        # demand-map a zero page and retry: models adjacent heap, lets the
        # flow run to its natural abort so we can observe it
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000)
        except Exception:
            uc.emu_stop()
            return False
        return True

    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                hook_bad)

    def hook_bounds(uc, access, address, size, value, _user):
        # maps are page-rounded; enforce exact object bounds here
        in_ctx = CTX_BASE <= address and address + size <= CTX_BASE + CTX_SIZE
        past_ctx = CTX_BASE <= address < CTX_BASE + 0x36000 and not in_ctx
        past_parsed = PARSED_BASE <= address < PARSED_BASE + 0x80000 and not (
            PARSED_BASE <= address and address + size <= PARSED_BASE + PARSED_SIZE)
        if past_ctx or past_parsed:
            pc = uc.reg_read(UC_ARM64_REG_PC)
            if len(res.oob) < 500:
                res.oob.append((pc, address, size, access))
            return True  # log and continue; unmapped tail handled by hook_bad
        return True

    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_bounds)
    return mu


def run(count: int, zero_fill_oob: bool = False, limit: int = 3_000_000) -> Result:
    res = Result()
    mu = build_machine(count, res, zero_fill_oob)
    from unicorn import UcError
    from unicorn.arm64_const import UC_ARM64_REG_W0, UC_ARM64_REG_PC
    try:
        mu.emu_start(FUNC_VA, RET_MAGIC, count=limit)
        if res.oob and mu.reg_read(UC_ARM64_REG_PC) != RET_MAGIC:
            pc = mu.reg_read(UC_ARM64_REG_PC)
            res.stopped = f"halted mid-function (pc={pc:#x})"
        else:
            res.w0 = mu.reg_read(UC_ARM64_REG_W0)
            res.stopped = f"returned w0={res.w0:#x}"
    except UcError as e:
        if res.w0 is None:
            res.stopped = f"UcError {e}"
    return res


def main() -> int:
    counts = [int(x, 0) for x in sys.argv[1:]] or [0x10, 0x1F4, 0x1F5, 0xFFFF]
    for count in counts:
        res = run(count)
        print(f"===== count={count:#x} =====")
        print(f"  stopped: {res.stopped}")
        for _pc, w5 in res.w5_at_sites:
            print(f"  w5(auth len)={w5:#x} ({w5} bytes)")
        print(f"  bl calls: {len(res.bl_calls)} pac_skips: {res.pac_skips}")
        for pc, addr, size, _acc in res.oob[:10]:
            print(f"  OOB pc={pc:#x} addr={addr:#x} size={size}")
        seen = sorted({n for _, n in res.veneers})
        if seen:
            print(f"  veneers hit: {', '.join(seen)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
