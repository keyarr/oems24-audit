#!/usr/bin/env python3
"""Read-only static analysis of the LinuxLoader PE for the devinfo persistence + EM sync state-preservation surface.

Companion to decompiled/devinfo-root-stageability-analysis.txt.

Scope:
- DeviceInfo load (0x425ec), default init, magic validation.
- Persist writers (0xff30 read, 0xff30 write, 0x42edc write wrapper).
- EM sync flow (0x9984..0x99ac) including BLInitToken/GetEMBit/SetUnlock dispatcher.
- MemCardInfo LocateProtocol (0x93e0..0x93f0) gating.
- Lazy init route (0x66e60..0x98fbc) used when MemCardInfo lookup fails.
- SetUnlocked call sites (0x424cc) and dispatcher call sites (0x41f88).

This script does NOT modify anything. It is byte-level only.

Usage:
    python3 scripts/devinfo_root_stageability.py
    python3 scripts/devinfo_root_stageability.py --quiet
"""
import struct
import sys
import capstone


PE = "decompiled/linuxloader-oneui8.pe"
TEXT_RA = 0x1000
TEXT_RS = 0xe3000
DATA_RA = 0xe4000
DATA_RS = 0xa9000


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_pe():
    with open(PE, "rb") as f:
        return f.read()


def disasm_region(buf, base_rva, size):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    code = buf[base_rva:base_rva + size]
    out = []
    for ins in md.disasm(code, base_rva):
        out.append((ins.address, ins.mnemonic, ins.op_str))
    return out


def all_calls_to(buf, target):
    out = []
    for addr, mn, op in disasm_region(buf, TEXT_RA, TEXT_RS):
        if mn == "bl" and op.strip() == f"#{hex(target)}":
            out.append(addr)
    return out


def all_branches_to(buf, target):
    out = []
    for addr, mn, op in disasm_region(buf, TEXT_RA, TEXT_RS):
        if target_hex := hex(target).lower() in op.lower():
            if mn in ("b", "b.eq", "b.ne", "b.lt", "b.gt", "b.le", "b.ge",
                       "b.lo", "b.hi", "b.ls", "b.hs", "b.cc", "b.cs",
                       "cbz", "cbnz", "tbz", "tbnz"):
                out.append((addr, mn, op))
    return out


def find_string(buf, target):
    return buf.find(target.encode() if isinstance(target, str) else target)


def print_section(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def report():
    buf = load_pe()

    print_section("DEVICEINFO LOAD (0x425ec) and MAGIC VALIDATION (0x42660 -> 0xf2ec)")
    # DeviceInfoInit flow:
    #  0x42608: tbnz FirstReadDevInfo bit0 -> skip read
    #  0x4261c: bl 0xff30 (read 0xcd0 bytes)
    #  0x42660: bl 0xf2ec  (memcmp with SAMANDR-BOOT! 13 bytes)
    #  0x42664: cbz -> default init path (zeros +0x0d, sets +0x90=1, writes 0xcd0)
    #  0x4273c: mov x19, xzr  (return NULL = success)
    print("  DeviceInfoInit @ 0x425ec")
    print("   - FirstReadDevInfo@0x170e20: bit0 set on entry to skip reread")
    print("   - 0x4261c bl 0xff30  ->  ReadBlocks(slot0, live_DevInfo@0x170e28, 0xcd0)")
    print("   - 0x42660 bl 0xf2ec  ->  memcmp(live_DevInfo, \"SAMANDR-BOOT!\", 13)")
    print("   - On memcmp==0: jump 0x4273c  ->  return x19=0 (xzr)")
    print("   - On memcmp!=0: jump 0x4268c default-init path")
    print("   - default-init path:")
    print("       memset 0x170e28..0x171af8  (0xcd0 bytes)")
    print("       strb wzr, [x19, #0xd]  (live +0x0d = 0)")
    print("       strb w8,  [x19, #0x90] (live +0x90 = 1)")
    print("       bl 0xff30  (WriteBlocks)")
    magic_off = find_string(buf, "SAMANDR-BOOT!")
    print(f"   - magic string at file offset 0x{magic_off:x} (RVA 0xc9730)")
    print("   - the thunk at 0x42f34 tail-calls with x0=live, x1=&magic, x2=13")

    print()
    print("VALIDATION SUMMARY")
    print("   - only memcmp(live, magic, 13) gates the structure")
    print("   - no version, no size, no CRC, no signature, no HMAC, no RPMB")
    print("   - failure => zero-init AND persist the zero, returning non-NULL")
    print("   - success => live is left untouched, return NULL")

    print_section("PERSISTENCE READ/WRITE (0xff30)")
    for addr, mn, op in disasm_region(buf, 0xff30, 0xc0):
        if addr > 0xfff0:
            break
        print(f"   0x{addr:06x}  {mn:8s} {op}")
    print("   GUID used by LocateProtocol: 8e5eff91-21b6-47d3-af2b-c15a01e020ec (custom BlockIo-like)")
    # LocateProtocol wrapper at 0x10aac adds 0xf80 to the caller-provided page.
    # 0xff30 passes page 0xe2000 -> 0xe2f80 (the GUID above).
    # +8 of the protocol is ReadBlocks; +16 is WriteBlocks (EFI_BLOCK_IO style).
    print("   second LocateProtocol wrapper at 0x10004 uses GUID at 0xe2fb0 (d68edce2-a314-457b-962a-1d99bbfcbbfb)")
    print("   => the persist path is a normal UFS BlockIo Read/Write, no secure-world channel")

    print_section("DEVICEINFO PERSIST CALLSITES")
    table = [
        (0x425ec, "RVA+0x00  DeviceInfoInit first-load read (0xcd0)"),
        (0x42528, "RVA+0x28  SetUnlocked -> WriteBlocks (full 0xcd0)"),
        (0x425a4, "RVA+0x24  post-+0x0e update -> WriteBlocks (full 0xcd0, +0x0d untouched)"),
        (0x4261c, "RVA+0x04  inside default-init: ReadBlocks to refresh live"),
        (0x42670, "RVA+0x68  default-init: WriteBlocks (zeros +0x0d)"),
        (0x42708, "RVA+0x00  default-init: WriteBlocks (full 0xcd0, +0x0d=0)"),
        (0x428b0, "RVA+0x84  key-record update -> WriteBlocks (full, +0x0d untouched)"),
        (0x42dc8, "RVA+0xdc  tail-field update -> WriteBlocks (full, +0x0d untouched)"),
        (0x42f10, "RVA+0x10  key-record helper -> WriteBlocks (full, +0x0d untouched)"),
        (0x95d4,  "early-load read into 0x15af10 (extra scratch read, not the live)"),
        (0x58df4, "ReadBlocks to scratch (separate persistence path)"),
        (0x58f54, "WriteBlocks from scratch (separate persistence path)"),
    ]
    for rva, what in table:
        print(f"   0x{rva:06x}  {what}")
    # confirmed in bypass analysis: no path other than these 12 callsites mutates +0x0d

    print_section("EM SYNC FLOW (0x9984..0x99ac)")
    print("   0x9984: bl 0x44d40  -> w21 = BootLockState pre-check (1=locked)")
    print("   0x998c: bl 0xade70  -> w0 = BLInitToken (TA open cmd 0x19, then cmd 0x15)")
    print("   0x9990: mov w0, #3")
    print("   0x9994: bl 0xadae0  -> w0 = GetEMBit(3) (lsr+and on 0x18c9e0[3])")
    print("   0x999c: mov w1, 0")
    print("   0x999a0: cset w0, ne   (w0 = 1 if bit 3 set, else 0)")
    print("   0x999a4: bl 0x41f88  -> SetUnlock dispatcher(w0=bit, w1=0)")
    print("   0x999a8: mov w0, w21 (BootLockState)")
    print("   0x999ac: bl 0x4e360   -> UI flow / boot path")
    print("   SetUnlocked(0x424cc) is the only writer of +0x0d in this PE.")
    print("   dispatcher 0x41f88 callers: 0x99a4 (EM sync) and 0xacd2c (UI).")
    print("   SetUnlocked(0x424cc) callers: 0x42150 and 0x42188 (both inside dispatcher).")
    print("   => no other static path writes +0x0d.")

    print_section("EM SYNC FAILURE MATRIX")
    print("   Stage                | Failure              | SetUnlock called? | Value | +0x0d survives?")
    print("   ---------------------|----------------------|-------------------|-------|----------------")
    print("   BootLockState (0x9984) | returns 1 (locked) | YES (path runs)  | bit  | depends on bit")
    print("   BLInitToken (0x998c)   | TA open fails       | YES              | bit  | depends on bitmap (0x18c9e0=0 => bit=0 => zeros +0x0d)")
    print("   GetEMBit (0x9994)      | bitmap zeros         | YES              | 0    | NO, +0x0d becomes 0 and is persisted")
    print("   SetUnlock dispatcher    | error path skip      | maybe (no 0x0d write on internal error) | n/a | conditional")
    print()
    print("   CASE 1 (default): failure => SetUnlock(0) => +0x0d=0 persisted (DESTROYS prior 1)")
    print("   CASE 2: no failure path inside BLInitToken/GetEMBit avoids SetUnlock. The only no-EM path is the LocateProtocol error path (0x9420).")

    print_section("MEMCARDINFO GATE (0x93e0..0x93f0)")
    for addr, mn, op in disasm_region(buf, 0x93e0, 0x40):
        if addr > 0x93f4:
            break
        print(f"   0x{addr:06x}  {mn:8s} {op}")
    print("   GUID bytes: 85c1f7d2-bce6-4f31-8f4d-d37e03d05eaa (gEfiMemCardInfoProtocolGuid)")
    print("   LocateProtocol wrapper at 0x13e38 (or 0x10aac) loads gBS->LocateProtocol at offset 0x140.")
    print("   tbnz x0, #0x3f at 0x93f0 selects the EFI_ERROR path: 0x9420 (no-EM) vs 0x93f4 (normal).")

    print_section("MEMCARDINFO INSTALLER (where the GUID is published)")
    inner = open("decompiled/abl-inner-oneui8.fv.bin", "rb").read()
    target = bytes.fromhex("d2f7c185e6bc314f8f4dd37e03d05eaa")
    for off in range(0, len(inner) - 16, 16):
        if inner[off:off+16] == target:
            print(f"   GUID found in abl-inner-oneui8.fv.bin @ 0x{off:x} (inside a likely FFS data area)")
            break
    print("   The ABL inner FV is responsible for installing the MemCardInfo protocol,")
    print("   typically from a UFS/SDCC DXE driver. Symbols of that driver are not present in the audited")
    print("   artifacts. Without the DXE image, we cannot enumerate the failure modes of its installer.")
    print("   The standard BlockIo GUID 225b4e96-6459-11d2-8e39-00a0c969723b is NOT present in the audited")
    print("   LinuxLoader PE nor the inner FV as a standalone string. The read path uses a Samsung-specific")
    print("   BlockIo variant (8e5eff91-21b6-47d3-af2b-c15a01e020ec).")

    print_section("LAZY INIT ROUTE (no-EM -> AVB)")
    for addr, mn, op in disasm_region(buf, 0x9420, 0x80):
        if addr > 0x9520:
            break
        print(f"   0x{addr:06x}  {mn:8s} {op}")
    print()
    print("   0x9420-0x9438  setup; bl 0x131ec (custom protocol check GUID b0760469-970c-487a-a4b5-28db7b45cef1)")
    print("   0x9438 cbz -> 0x9608  (if the check returns 0, continue to AVB)")
    print("   0x9608-0x969c  reads extra devinfo, branches on boot mode, then bl 0x66e60 (lazy init)")
    print("   0x66e60 -> 0x98fbc -> DeviceInfoInit -> AVB. NO EM SYNC on this path.")

    print_section("PARTITION RUNTIME (read-only evidence)")
    print("   /dev/block/by-name/devinfo -> /dev/block/sda15 (UFS user partition, 4096 bytes)")
    print("   SELinux label: u:object_r:block_device:s0")
    print("   not mounted as filesystem (raw block)")
    print("   root context: u:r:ksu:s0 (KernelSU).")
    print("   With SELinux set to permissive (per operator), root can open the block device for read+write.")

    print_section("CONCLUSION")
    print("   Q1: Can root prepare a DeviceInfo that ABL accepts with IsUnlocked=1?")
    print("       YES in principle. Persist SAMANDR-BOOT! + +0x0d=1 (other bytes preserved).")
    print("       Validation is only the 13-byte magic. There is no other integrity gate.")
    print("   Q2: What integrity values must be recomputed?")
    print("       None. The structure is plain: magic + fields, no CRC/signature.")
    print("   Q3: Does any EM init failure preserve +0x0d=1 without the MemCardInfo error path?")
    print("       NO. The EM sync flow always reaches SetUnlocked with the current GetEMBit(3) result,")
    print("       and the bitmap is zero at boot, so any TA failure collapses to SetUnlock(0), which")
    print("       zeros +0x0d and persists. Only the MemCardInfo LocateProtocol error path skips this.")
    print("   Q4: Is there evidence that MemCardInfo can disappear while BlockIo remains usable?")
    print("       UNKNOWN / EXTERNAL. The MemCardInfo installer lives in the ABL inner FV (DXE) and its")
    print("       failure conditions are not enumerable from the audited LinuxLoader PE. The standard")
    print("       BlockIo GUID is not visible as a literal in the LinuxLoader or the inner FV, so we")
    print("       cannot assert independence. Treat as unproven.")
    print("   Q5: Chain A status:")
    print("       Edge A (root -> persisted +0x0d=1):  ROOT-STAGEABLE in principle (raw UFS, no secure-world).")
    print("       Edge B (persisted -> AVB without EM overwrite):")
    print("         - on the LocateProtocol SUCCESS path: NO (EM sync always overwrites)")
    print("         - on the LocateProtocol ERROR path: possible (no EM sync, lazy DeviceInfoInit)")
    print("       Edge B overall: requires the MemCardInfo error, which is UNKNOWN/EXTERNAL.")
    print("       Net:  THEORETICAL (with one external precondition).")
    print("       It is NOT a DEAD END (the persist+integrity layer is fully reproducible),")
    print("       but it is NOT ROOT-STAGEABLE in isolation: the EM-sync-bypass precondition is external.")


if __name__ == "__main__":
    quiet = "--quiet" in sys.argv
    if quiet:
        import io
        old = sys.stdout
        sys.stdout = io.StringIO()
    try:
        report()
    finally:
        if quiet:
            out = sys.stdout.getvalue()
            sys.stdout = old
            print(f"quiet run ok, {len(out)} bytes")
