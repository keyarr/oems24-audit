#!/usr/bin/env python3
"""Offline Unicorn harness for H2: emGetTokenRequest VLA-before-check + fixed blobs + NEON.

Target: binaries/libengmode_server.so EngineeringModeWorld::emGetTokenRequest 0xf07c.
Read-only vs repo/device: emulates committed bytes, never touches device.
Requires: pip install unicorn (already used by scripts/ta_harness.py).

What it proves:
  - VLA size (count*2+15)&~0xF + memset happen BEFORE cmp w22,#0x40.
  - 15B/6B/8B blob copies read without lens (0xf3ec/0xf410/0xf438).
  - NEON ld2 conversion reads beyond wire len (0xf4a8/0xf504).
  - Exact-object OOB (within-page but past object end) vs unmapped OOB.
  - Wire len <0xC801 does NOT bound BE count contents.
"""
from __future__ import annotations
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "binaries" / "libengmode_server.so"

FUNC_VA = 0xF07C
RET_MAGIC = 0xFFFFFFFFFFFFFF00

# PLT stubs (from plt_map)
PLT_MEMSET = 0x164D0
PLT_MEMCPY = 0x16170
PLT_MEMCPY_CHK = 0x165F0
PLT_STRLEN = 0x16560
PLT_STRLEN_CHK = 0x15FC0
PLT_CALLOC = 0x16140
PLT_LOG = 0x15E70
PLT_PREPARE = 0x16890
PLT_READ_STEADY = 0x168A8
PLT_CLEAR = 0x168C0
PLT_EMPROCESS = 0x16800

# key sites
VLA_SIZE_PC = 0xF0EC  # and x9, #0x3fff0 (x9 = VLA bytes)
SP_MOV_PC = 0xF0FC    # mov sp, x24
MEMSET_PC = 0xF10C    # bl memset (x0=VLA buf, x2=count*2)
COUNT_CMP_PC = 0xF110  # cmp w22, #0x40
BLOB15_PC = 0xF3EC    # ldr x9,[x21] / ldur x10,[x21,#7]
BLOB6_PC = 0xF410     # ldr w9,[x28] / ldrh w10,[x28,#4]
BLOB8_PC = 0xF438     # ldr x9,[x9] where x9=*x4
NEON_PC = 0xF4A8      # ld2 32B fast loop
NEON_TAIL_PC = 0xF504  # ld2 8B tail
STORE_COUNT_PC = 0xF54C  # strh w22,[req+#0x2aa]
REQ_COPY_PC = 0xF558   # bl memcpy(req+0x2ac, VLA buf, count*2)
EMPROCESS_PC = 0xF570  # bl emProcess


class Result:
    def __init__(self):
        self.vla_bytes = None
        self.sp_before = None
        self.sp_after = None
        self.memset_n = None
        self.count = None
        self.count_pass = None
        self.obj_oob = []  # (pc, addr, size, objname, is_write)
        self.unmapped = []  # (pc, addr, size, is_write)
        self.bl = []
        self.veneers = []
        self.w0 = None
        self.stopped = ""
        self.sink_reached = False


def build(scenario: dict):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED
    from unicorn import UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED
    from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                     UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                     UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                                     UC_ARM64_REG_X6, UC_ARM64_REG_X7,
                                     UC_ARM64_REG_X8, UC_ARM64_REG_SP,
                                     UC_ARM64_REG_PC, UC_ARM64_REG_LR,
                                     UC_ARM64_REG_W0)
    data = LIB.read_bytes()
    # Parse PT_LOAD via elftools
    sys.path.insert(0, str(ROOT / "scripts"))
    from elftools_helpers import Bin
    b = Bin(str(LIB))
    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    for vaddr, off, fsz, msz, fl in b.segs:
        if fsz == 0:
            continue
        size = (fsz + 0xFFF) & ~0xFFF
        mu.mem_map(vaddr, size)
        mu.mem_write(vaddr, data[off:off + fsz])
    res = Result()

    # ---- exact objects with guards ----
    # We map each test object in its own 0x1000 page; next page left unmapped.
    # Exact bounds tracked separately so intra-page over-read is still flagged.
    objs = {}  # name -> (base, exact_size)
    next_base = [0x40000000]

    def alloc_obj(name: str, content: bytes):
        base = next_base[0]
        need = (len(content) + 0xFFF) & ~0xFFF
        # object pages + one guard page unmapped
        mu.mem_map(base, need)
        mu.mem_write(base, content)
        next_base[0] += need + 0x1000
        objs[name] = (base, len(content))
        return base

    # World struct 0x200
    world = alloc_obj("world", b"\x00" * 0x200)
    # req/rsp/steady/token (sized as live)
    req = alloc_obj("req_big", b"\x00" * 0x22000)
    # trim exact: req object is big on purpose (backend buffer), exact = full page span?
    # For OOB purposes req/rsp are large allocations: exact = mapped size bucket
    objs["req_big"] = (req, 0x21C7D)
    rsp = alloc_obj("rsp_big", b"\x00" * 0x21000)
    objs["rsp_big"] = (rsp, 0x20936)
    steady = alloc_obj("steady", b"\x00" * 0x2C00)
    token = alloc_obj("token", b"\x00" * 0x11000)
    # wire World pointers
    mu.mem_write(world + 0x10, struct.pack("<Q", steady))
    mu.mem_write(world + 0x18, struct.pack("<Q", token))
    mu.mem_write(world + 0x70, struct.pack("<Q", req))
    mu.mem_write(world + 0x78, struct.pack("<Q", rsp))
    # this+0xc flag for preparePayload path (nonzero to skip 0x16860)
    mu.mem_write(world + 0x0C, struct.pack("<I", 1))

    # str1 (x1): scenario len
    s1 = scenario["str1"]
    s1_base = alloc_obj("str1", s1 + b"\x00")
    # x2 blob p2 for 15B copy
    p2 = scenario["p2"]
    p2_base = alloc_obj("p2", p2)  # exact len as given (may be <15)
    # x3 blob p3 for 6B copy
    p3 = scenario["p3"]
    p3_base = alloc_obj("p3", p3)
    # x4 -> objA -> objB (8B copy via double deref)
    p4data = scenario["p4data"]
    objB = alloc_obj("p4data", p4data)
    objA = alloc_obj("p4ptr", struct.pack("<Q", objB))
    # modes vec x5: BE count + payload
    modes = scenario["modes"]
    modes_base = alloc_obj("modes", modes)
    # str2 (x6)
    s2 = scenario["str2"]
    s2_base = alloc_obj("str2", s2 + b"\x00")
    # out buf + outLen
    out = alloc_obj("out", b"\x00" * 0x11000)
    objs["out"] = (out, 0x11000)
    outlen = alloc_obj("outlen", struct.pack("<I", 0))
    # pre-seed rsp so sink is reachable if emProcess stub returns 0
    # rsp+0 !=0, rsp+4 ==1, rsp+0x516 bit0, rsp+0x14132 len, rsp+0x14136 data
    mu.mem_write(rsp + 0x00, struct.pack("<I", 0))
    mu.mem_write(rsp + 0x04, b"\x01")
    mu.mem_write(rsp + 0x516, b"\x01")
    mu.mem_write(rsp + 0x14132, struct.pack("<I", 0x20))
    mu.mem_write(rsp + 0x14136, b"A" * 0x20)

    # stack with outLen pointer as 9th arg at [sp,#0x60] per 0xf228? Actually
    # World is called directly here (not via onTransact), so 9th arg (outLen ptr
    # is x8?) — AArch64: x0..x7 regs, 9th on stack. Signature has 9 args
    # (this + 8). x7=out, stack[0]=outLen ptr. Set both x8 (caller in some
    # builds passes outLen in x8?) and stack.
    STACK_BASE = 0x60000000
    STACK_SIZE = 0x400000
    mu.mem_map(STACK_BASE, STACK_SIZE)
    sp0 = STACK_BASE + STACK_SIZE - 0x200
    # 9th arg (outLen ptr) is read by World at [x29,#0x60] where x29=sp-0x50
    # after entry prologue, i.e. [sp0+0x10]. Write it at both [sp0] and [sp0+0x10].
    mu.mem_write(sp0, struct.pack("<Q", outlen))
    mu.mem_write(sp0 + 0x10, struct.pack("<Q", outlen))
    mu.reg_write(UC_ARM64_REG_SP, sp0)
    res.sp_before = sp0

    mu.reg_write(UC_ARM64_REG_X0, world)
    mu.reg_write(UC_ARM64_REG_X1, s1_base)
    mu.reg_write(UC_ARM64_REG_X2, p2_base)
    mu.reg_write(UC_ARM64_REG_X3, p3_base)
    mu.reg_write(UC_ARM64_REG_X4, objA)
    mu.reg_write(UC_ARM64_REG_X5, modes_base)
    mu.reg_write(UC_ARM64_REG_X6, s2_base)
    mu.reg_write(UC_ARM64_REG_X7, out)
    mu.reg_write(UC_ARM64_REG_X8, outlen)
    mu.reg_write(UC_ARM64_REG_LR, RET_MAGIC)

    malloc_next = [0x50000000]
    try:
        mu.mem_map(malloc_next[0], 0x100000)
    except Exception:
        pass

    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def in_exact(addr: int, size: int):
        for name, (base, esz) in objs.items():
            if base <= addr and addr + size <= base + esz:
                return name
        return None

    def containing(addr: int):
        for name, (base, esz) in objs.items():
            # mapped page is 0x1000; object may be smaller
            if base <= addr < base + 0x1000:
                return name, base, esz
        return None, None, None

    def hook_code(uc, address, size, _u):
        if address == (RET_MAGIC & ((1 << 64) - 1)):
            res.w0 = uc.reg_read(UC_ARM64_REG_W0)
            res.stopped = f"returned w0={res.w0:#x}"
            uc.emu_stop()
            return
        # PLT stubs
        if address == PLT_MEMSET:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            w1 = uc.reg_read(UC_ARM64_REG_X1) & 0xFF
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            if res.memset_n is None and address == 0:
                pass
            # log memset at World VLA site
            pc = uc.reg_read(UC_ARM64_REG_PC)
            try:
                uc.mem_write(x0, bytes([w1 & 0xFF]) * min(x2, 0x40000))
            except Exception:
                pass
            uc.reg_write(UC_ARM64_REG_X0, x0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address in (PLT_MEMCPY, PLT_MEMCPY_CHK):
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            x1 = uc.reg_read(UC_ARM64_REG_X1)
            x2 = uc.reg_read(UC_ARM64_REG_X2)
            try:
                uc.mem_write(x0, bytes(uc.mem_read(x1, min(x2, 0x40000))))
            except Exception:
                pass
            uc.reg_write(UC_ARM64_REG_X0, x0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == PLT_STRLEN:
            x0 = uc.reg_read(UC_ARM64_REG_X0)
            n = 0
            try:
                while n < 0x2000:
                    if uc.mem_read(x0 + n, 1) == b"\x00":
                        break
                    n += 1
            except Exception:
                pass
            uc.reg_write(UC_ARM64_REG_X0, n)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address in (PLT_CALLOC,):
            import struct as st
            # calloc(nmemb=x0, size=x1)? Actually call sites: mov w0,#1; mov w1,#size; bl calloc
            nm = uc.reg_read(UC_ARM64_REG_X0)
            sz = uc.reg_read(UC_ARM64_REG_X1)
            total = nm * sz
            ptr = malloc_next[0]
            malloc_next[0] += (total + 0xFFF) & ~0xFFF
            try:
                uc.mem_write(ptr, b"\x00" * min(total, 0x20000))
            except Exception:
                pass
            uc.reg_write(UC_ARM64_REG_X0, ptr)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address in (PLT_LOG, PLT_STRLEN_CHK, PLT_PREPARE, PLT_READ_STEADY, PLT_CLEAR):
            # preparePayload/steady -> return 0 (success) to reach deep flow
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == PLT_EMPROCESS:
            res.bl.append((address, address))
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if address == 0x16800:  # real emProcess function entry (not PLT)
            res.bl.append((address, address))
            uc.reg_write(UC_ARM64_REG_X0, 0)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        # site sampling
        if address == VLA_SIZE_PC:
            try:
                raw = uc.mem_read(address, 4)
                ins = next(md.disasm(raw, address), None)
            except Exception:
                pass
        if address == COUNT_CMP_PC:
            res.count = uc.reg_read(UC_ARM64_REG_X0 + 22 - 0) if False else None
        # PAC/BTI tolerance
        try:
            raw = uc.mem_read(address, 4)
        except Exception:
            return
        ins = next(md.disasm(raw, address), None)
        if ins is not None and (ins.mnemonic.startswith("bti") or ins.mnemonic in ("paciasp", "autiasp")):
            uc.reg_write(UC_ARM64_REG_PC, address + 4)
            return
        if ins is not None and ins.mnemonic == "bl":
            try:
                tgt = int(ins.op_str.strip().lstrip("#"), 16)
                res.bl.append((address, tgt))
            except ValueError:
                pass
        if address == EMPROCESS_PC:
            pass
        if address in (BLOB15_PC, BLOB6_PC, BLOB8_PC, NEON_PC, NEON_TAIL_PC, STORE_COUNT_PC, REQ_COPY_PC):
            pass

    def hook_bad(uc, access, address, size, value, _u):
        from unicorn import UC_MEM_WRITE_UNMAPPED
        pc = uc.reg_read(UC_ARM64_REG_PC)
        is_w = (access == UC_MEM_WRITE_UNMAPPED)
        res.unmapped.append((pc, address, size, is_w))
        if len(res.unmapped) > 300:
            uc.emu_stop()
            return False
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000)
        except Exception:
            uc.emu_stop()
            return False
        return True

    def hook_rw(uc, access, address, size, value, _u):
        # exact-object check
        name = in_exact(address, size)
        if name is None:
            c = containing(address)
            if c[0] is not None:
                pc = uc.reg_read(UC_ARM64_REG_PC)
                from unicorn import UC_MEM_WRITE
                is_w = (access == UC_MEM_WRITE)
                if len(res.obj_oob) < 500:
                    res.obj_oob.append((pc, address, size, c[0], is_w))
        else:
            # sample VLA/SP/count at key PCs
            pass
        # sample sites on read/write at specific PCs
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if pc == VLA_SIZE_PC + 4:
            pass
        return True

    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_bad)
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_rw)

    # sample VLA/count via direct reads after mapping: we read them in hook_code
    # by instrumenting registers at specific PCs. Simpler: add second code hook.
    from unicorn import UC_HOOK_CODE as CH
    from unicorn.arm64_const import UC_ARM64_REG_X9, UC_ARM64_REG_X2, UC_ARM64_REG_X0
    state = {}

    def hook_sites(uc, address, size, _u):
        from unicorn.arm64_const import UC_ARM64_REG_X9, UC_ARM64_REG_X2, UC_ARM64_REG_SP, UC_ARM64_REG_W0
        if address == 0xF0EC:
            pass
        if address == 0xF0FC + 4:  # after mov sp
            res.sp_after = uc.reg_read(UC_ARM64_REG_SP)
            # x9 holds VLA bytes at 0xF0EC and x24 at 0xF0F8; read x9
            try:
                res.vla_bytes = uc.reg_read(UC_ARM64_REG_X9)
            except Exception:
                pass
        if address == 0xF10C + 4:  # after memset bl? actually at bl; sample x2 before
            pass
        if address == 0xF110:
            # w22 count: x22? w22 is low 32 of x22
            try:
                from unicorn.arm64_const import UC_ARM64_REG_X22
                res.count = uc.reg_read(UC_ARM64_REG_X22) & 0xFFFFFFFF
            except Exception:
                pass
        if address == 0xF114 + 4:
            # b.lo taken? if PC==0xF148 pass else fail
            pass
        if address == 0xF148:
            res.count_pass = True
        if address == 0xF118:
            res.count_pass = False
        if address in (0xF618, 0x11DB0):
            res.sink_reached = True

    mu.hook_add(CH, hook_sites)
    return mu, res, objs


def run_scenario(name: str, scenario: dict) -> Result:
    mu, res, objs = build(scenario)
    from unicorn import UcError
    from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_W0
    try:
        mu.emu_start(FUNC_VA, RET_MAGIC, count=800000)
        try:
            res.w0 = mu.reg_read(UC_ARM64_REG_W0)
            if not res.stopped:
                res.stopped = f"returned w0={res.w0:#x}"
        except Exception:
            pass
    except UcError as e:
        if not res.stopped:
            res.stopped = f"UcError {e}"
    print(f"===== {name} =====")
    print(f"  stopped: {res.stopped}")
    print(f"  VLA bytes={(hex(res.vla_bytes) if res.vla_bytes is not None else '?')} sp_delta={(res.sp_before - res.sp_after) if (res.sp_before and res.sp_after) else '?'} count={(hex(res.count) if res.count is not None else '?')} pass={res.count_pass}")
    print(f"  sink_reached={res.sink_reached} w0={(hex(res.w0) if res.w0 is not None else '?')}")
    print(f"  obj-OOB: {len(res.obj_oob)} unmapped: {len(res.unmapped)}")
    for pc, addr, size, obj, is_w in res.obj_oob[:16]:
        print(f"    {'W' if is_w else 'R'} pc={pc:#x} addr={addr:#x} size={size} obj={obj}")
    for pc, addr, size, is_w in res.unmapped[:8]:
        print(f"    UNMAPPED {'W' if is_w else 'R'} pc={pc:#x} addr={addr:#x} size={size}")
    return res


def main() -> int:
    # Control: correctly sized
    ctrl_modes = struct.pack(">H", 1) + b"\x00\x03"
    run_scenario("control count=1 wire=4 all-sized", {
        "str1": b"A" * 10, "p2": b"B" * 15, "p3": b"C" * 6,
        "p4data": b"D" * 8, "modes": ctrl_modes, "str2": b"E" * 8,
    })
    # H2-B: short blobs + count=63 wire=4 (passes <0x40, zero-padded modes)
    run_scenario("H2-B short-blobs count=63 wire=4", {
        "str1": b"A" * 10, "p2": b"B" * 4, "p3": b"C" * 2,
        "p4data": b"D" * 2, "modes": struct.pack(">H", 63) + b"\x00\x03",
        "str2": b"E" * 8,
    })
    # H2-C: count=0x40 (just over limit) wire=4 -> VLA before fail
    run_scenario("H2-C count=0x40 wire=4 VLA-before-fail", {
        "str1": b"A" * 10, "p2": b"B" * 15, "p3": b"C" * 6,
        "p4data": b"D" * 8, "modes": struct.pack(">H", 0x40) + b"\x00\x03",
        "str2": b"E" * 8,
    })
    # H2-D: count=0xFFFF wire=4 -> max VLA waste then fail
    run_scenario("H2-D count=0xFFFF wire=4 max-VLA", {
        "str1": b"A" * 10, "p2": b"B" * 15, "p3": b"C" * 6,
        "p4data": b"D" * 8, "modes": struct.pack(">H", 0xFFFF) + b"\x00\x03",
        "str2": b"E" * 8,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
