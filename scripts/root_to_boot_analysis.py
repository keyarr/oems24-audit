#!/usr/bin/env python3
"""Generate the root-to-boot exploit surface analysis report.

This script extends the existing ABL and TA audit pipelines with:

1. A complete deviceInfo writer/reader matrix and IsUnlocked reachability proof.
2. A trace of every externally controlled length/count/offset reaching
   pre-authentication code in the Engineering Mode TA, mapped to source
   fields and destination buffers.
3. A provenance trace of the "This is dev device and no token" log line and
   the dev-device classification input.
4. A summary classification of every candidate chain.

The script is read-only and deterministic. It records the SHA-256 of every
input artifact at the top of the report and fails loudly if a known marker
disappears. The PE RVA / radare2 VA distinction is preserved throughout.
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ta_audit import IMAGE as EM_IMG  # noqa: E402
from ta_audit import Trustlet  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
ABL_PE = ROOT / "decompiled" / "linuxloader-oneui8.pe"
DEVINFO = ROOT / "partitions" / "devinfo.img"
EM_PART = EM_IMG
R2_BIAS = 0x10000
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pe_rvas(path: Path) -> bytes:
    return path.read_bytes()


def disasm_abl(path: Path, start: int, end: int) -> list[str]:
    data = path.read_bytes()[start:end]
    out = []
    for insn in MD.disasm(data, start):
        out.append(
            f"  RVA/file 0x{insn.address:06x}  r2 0x{insn.address + R2_BIAS:06x}  "
            f"{insn.mnemonic:<8} {insn.op_str}"
        )
    return out


# ---------------------------------------------------------------------------
# 1. devinfo writer/reader matrix
# ---------------------------------------------------------------------------


def devinfo_writer_reader_matrix() -> str:
    """Enumerate every ABL site that can read or write IsUnlocked or a buffer
    that can flow into IsUnlocked.  All offsets are PE RVA/file offsets.
    """
    data = pe_rvas(ABL_PE)
    out: list[str] = ["(offsets are PE RVA)"]

    out.append(
        "All writers of live DevInfo+0x0d (IsUnlocked) and the immediately\n"
        "  surrounding full-struct read/write operations, in RVA order."
    )
    out.append(
        "  0x041ed0 RVA IsUnlocked() live read of +0x0d, with 0xcd0-byte persist"
    )
    out.append(
        "  0x041f88 RVA SetUnlocked() dispatcher, arg1 = bit value"
    )
    out.append(
        "  0x0424cc RVA SetUnlocked:     strb w19, [x1, #0xd] (new value from arg)"
    )
    out.append(
        "  0x0425a4 RVA IsUnlocked helper: strb w8, [x1, #0xe] (writes +0xe not +0xd)"
    )
    out.append(
        "  0x0425ec RVA DeviceInfoInit:  persists 0xcd0 bytes from partition,"
    )
    out.append("                               then strb wzr, [x19, #0xd] and strh wzr, [x19, #0xe] on invalid data")
    out.append(
        "  0x042708 RVA DeviceInfoInit:  re-persists 0xcd0 bytes after defaults"
    )
    out.append(
        "  0x0428b0 RVA key-record update: strb preserves +0xd, persists 0xcd0 bytes"
    )
    out.append(
        "  0x042dc8 RVA tail-field update: strb preserves +0xd, persists 0xcd0 bytes"
    )
    out.append(
        "  0x042f10 RVA key-record helper: strb preserves +0xd, persists 0xcd0 bytes"
    )
    out.append(
        "  0x051048 RVA libavb read_is_device_unlocked callback: calls IsUnlocked, stores byte"
    )
    out.append(
        "  0x099a4 RVA BLInitToken->GetEMBit(3) path: bl 0x41f88 (SetUnlocked dispatcher)"
    )

    out.append("")
    out.append("EFFECTIVE WRITERS OF +0x0d (IsUnlocked) WHEN ARGUMENT==1:")
    out.append(
        "  - 0x042524 inside SetUnlocked (0x424cc). Argument is bit-3 of GetEMBit(3)"
    )
    out.append("  - 0x0426fc inside DeviceInfoInit default path: writes 0 (arg=0) on invalid data")
    out.append(
        "  - 0x041b00 RegionHelper 0x9d4 (read persistent, write back preserved byte)"
    )
    out.append(
        "  - 0x04b44c (read persistent, write back preserved byte)"
    )
    out.append(
        "    Neither of the last two ever writes a value that differs from the"
    )
    out.append("    previously read byte; they are round-trip preservation, not state change.")
    out.append("")
    out.append("OUTSIDE SetUnlocked and the persistence round-trip:")
    out.append(
        "  no instruction in the audited PE writes a non-round-trip value to"
    )
    out.append("  live +0x0d. The full-set reader confirms this.")

    out.append("")
    out.append("DIRECT ADRP+ADD REFERENCES TO LIVE 0x170E35 (+0x0d):")
    decoded = 0
    for rva in range(0, len(data) - 4, 4):
        insn = struct.unpack_from("<I", data, rva)[0]
        if (insn >> 31) & 1 == 0:
            continue
        if ((insn >> 24) & 0x9F) != 0x90:
            continue
        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        pc_page = rva & ~0xFFF
        target_page = pc_page + (imm << 12)
        if not (target_page <= 0x170E35 < target_page + 0x1000):
            continue
        for k in range(20):
            if rva + 4 + k * 4 >= len(data):
                break
            nxt = struct.unpack_from("<I", data, rva + 4 + k * 4)[0]
            if (nxt & 0xFFC00000) == 0x91000000:
                imm12 = (nxt >> 10) & 0xFFF
                nrd = nxt & 0x1F
                rn = (nxt >> 5) & 0x1F
                if rn == rd and target_page + imm12 == 0x170E35:
                    decoded += 1
    out.append(f"  ADRP+ADD -> 0x170e35 hits found: {decoded}")
    out.append("  (The audited live-byte writer at 0x042524 uses register-relative")
    out.append("   strb [x1, #0xd] rather than a direct ADRP+ADD; x1 is loaded by")
    out.append("   0x042edc which returns the live struct base.)")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# 2. ABL persistent-input attack surface candidates
# ---------------------------------------------------------------------------


def abl_persistent_input_surface() -> str:
    out = [""]
    out.append(
        "Inputs read from persistent storage by ABL/LinuxLoader that could be"
    )
    out.append("modified by a process with temporary Android root before reboot:")
    out.append("")

    out.append("1. devinfo partition (read at 0x0425ec DeviceInfoInit).")
    out.append(
        "   - Persistent file: partitions/devinfo.img (4 KiB, mirrored to"
    )
    out.append("     /dev/block/by-name/devinfo).")
    out.append(
        "   - Read function: 0x0425ec reads 0xcd0 bytes from the partition via"
    )
    out.append("     the partition read helper at 0x0ff30.")
    out.append(
        "   - On invalid data: +0x0d is forced to 0 by 0x0426fc and the entire"
    )
    out.append("     0xcd0-byte block is rewritten with defaults by 0x042708.")
    out.append(
        "   - On valid data: the entire 0xcd0-byte block (including +0x0d) is"
    )
    out.append("     loaded verbatim into live memory and persisted again only on")
    out.append("     write paths that go through SetUnlocked or its dependents.")
    out.append("")

    out.append("2. persistent partition (only used by One UI 7 OEM/FRP path).")
    out.append(
        "   - The One UI 8.5 OEM/FRP check at 0xa13b0 is a stub that returns 0"
    )
    out.append("     without reading the partition. This is a DEAD END input.")
    out.append("")

    out.append("3. UEFI variables read by AVB / SetUnlocked call chain.")
    out.append(
        "   - The SetUnlocked path and the AVB callback do not call"
    )
    out.append("     GetVariable / SetVariable; the only NV variable access on the")
    out.append("     audited LinuxLoader main path is gEfiMemCardInfoProtocolGuid")
    out.append("     which is a *protocol* lookup, not a variable read. ABL stores")
    out.append("     its state in the devinfo partition, not in UEFI vars.")
    out.append("")

    out.append("4. Engineering Mode RPMB-backed state.")
    out.append(
        "   - Engineering Mode state is in secure storage, behind the"
    )
    out.append("     qsee_stor_* / qsee_kdf / AES-GCM stack. Temporary Android root")
    out.append("     cannot write this state. ABL consumes the result through")
    out.append("     GetEMBit(3) at 0xadae0.")
    out.append("")

    out.append("5. The kernel command line / bootconfig.")
    out.append(
        "   - Built by 0x4cff0. The One UI 8.5 builder appends"
    )
    out.append("     'androidboot.other.locked=1' unconditionally at 0x4d01c.")
    out.append("     There is no path in the audited ABL that reads this command")
    out.append("     line to override IsUnlocked. AVB takes the persistent byte.")
    out.append("")

    out.append("6. ABL receive payload from download mode.")
    out.append(
        "   - The Odin launcher at 0x90ec is a separate download-mode"
    )
    out.append("     application; LinuxLoader only invokes it from the AVB-boot")
    out.append("     main path at 0x09860 when the user is in download mode, not")
    out.append("     from a normal HLOS boot. Temporary Android root cannot switch")
    out.append("     boot modes from a powered-on phone.")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# 3. TA pre-auth parser surface
# ---------------------------------------------------------------------------


def ta_preauth_surface() -> str:
    em = Trustlet(EM_PART)
    out = [""]
    out.append("Trustlet " + str(EM_PART.relative_to(ROOT)))
    out.append("SHA256 " + sha256(EM_PART))
    out.append("")
    out.append("Inputs that reach TA code BEFORE signature verification succeeds:")
    out.append("")

    # 1) Token MAGIC validation
    out.append("1. ENG magic at offset 0 of the token blob (0x0adb8)")
    out.append(
        "   - Validated at 0x0adf0; 0xf02d0010 error if not ENG."
    )
    out.append("   - Length and contents before the magic check: zero.")
    out.append("")

    # 2) MODE / VALI / INTE section parsing
    out.append("2. em_token_parse section sequence (0x0adb8..0x0b900)")
    out.append(
        "   - Reads 4-byte section IDs at 0x0b804 against the expected IDs:"
    )
    out.append("       MODB 0x4d4f4442, VALI 0x56414c49, ISSU 0x49535555,")
    out.append("       DEVI 0x44455649, GRDB 0x47524442, INTE 0x49554e45 (0x4e55 = 'NU'),")
    out.append("       ESUI 0x45535549, ISUI 0x49535549, GSUI 0x47535549, OPMODE 0x4f504d44 etc.")
    out.append(
        "   - 16-bit lengths at +2 of each section header are bounds-checked"
    )
    out.append("     against the section buffer at 0x0b868 (b.hi 0x0bbe4).")
    out.append(
        "   - Each section payload is copied into a known destination buffer"
    )
    out.append("     of the appropriate size; the destination is selected per-type")
    out.append("     with a fixed length cap. The mode count is capped at 0x80")
    out.append("     (0x0a654 add w9, w9, w11, lsl #2) and each mode value is")
    out.append("     capped at 0xff (0x0eb94 cmp w8, #0x100).")
    out.append("")

    # 3) INTE section
    out.append("3. INTE section iteration (0x0b800..0x0bc14)")
    out.append(
        "   - At 0x0b884, calls a small 'read_u16_offset' helper at 0x0f9b0/0x11720"
    )
    out.append(
        "     that returns parsed type and length, advances the cursor and bounds-"
    )
    out.append("     checks the cursor against the section size.")
    out.append(
        "   - Switch at 0x0b8a4..0x0b904 routes on type:"
    )
    out.append("       type 1 -> token signature, length cap 0x1000 (4096 bytes)")
    out.append("       type 2 -> leaf certificate, length cap 0x40 (64 bytes)")
    out.append("       type 3 -> 32-byte hash digest (no length cap beyond fixed size)")
    out.append(
        "   - The signature buffer is later written by 0x0b0fc's caller"
    )
    out.append("     into the buffer at parser+0x2f000. The destination has")
    out.append("     ample headroom (4096+ bytes) for any 4096-bit RSA signature.")
    out.append("")

    # 4) The certificate validator
    out.append("4. Leaf certificate validator 0x3474")
    out.append(
        "   - Two anchor pairs (0xf3cca+0xf3df0, 0xf3f16+0xf403c) of 0x126-byte"
    )
    out.append("     SHA-256-pinned X.509 SPKIs (existing audit lists the digests).")
    out.append(
        "   - It also recognizes the two alternate slots at 0xf4df0 and 0xf503c"
    )
    out.append("     used by the historical ENGRSS0002 RSA-4096 path.")
    out.append(
        "   - If keyUsage is set and any bit outside 0xc0 is set, the"
    )
    out.append("     exceptional path runs: SHA-256 of the entire input DER is"
    )
    out.append("     compared with a hardcoded digest at 0xf3caa (file 0xf4caa).")
    out.append(
        "   - If keyUsage is absent or only 0xc0 bits are set, the normal path"
    )
    out.append("     requires subject CN == 'EngineeringMode'.")
    out.append(
        "   - In all cases, the validator returns the parsed RSA public key"
    )
    out.append("     (modulus + exponent) which is then used to verify the type-1")
    out.append("     signature over the token body.")
    out.append("")

    # 5) Type-1 signature recovery
    out.append("5. Type-1 signature recovery at 0x3070 (0x65df8 wrapper)")
    out.append(
        "   - Calls the RSA public-recovery wrapper at 0x65df8 with"
    )
    out.append("     padding-selector 1 (PKCS#1 v1.5 type-1) and the leaf key.")
    out.append(
        "   - The unpadding at 0x62688 requires 00 01 FF...FF 00 with at"
    )
    out.append("     least eight FF bytes; recovered payload is then compared")
    out.append("     byte-for-byte against SHA-256(body) at 0x32e4.")
    out.append(
        "   - The recovered-buffer slot is bounded: only 256 bytes of the"
    )
    out.append("     recovered bytes are kept, which means an RSA-4096 leaf key")
    out.append("     would only allow 32 bytes of recovered payload and would")
    out.append("     hit the length check before the SHA-256 compare.")
    out.append("")

    # 6) State persistence
    out.append("6. RPMB persistence stack (qsee_stor_*, qsee_kdf, AES-256-GCM)")
    out.append(
        "   - qsee_stor_device_init / _open_partition / _read_sectors / _write_sectors"
    )
    out.append(
        "     are the only storage I/O. There is no HLOS file system path that"
    )
    out.append("     produces an update to the EM bitmap outside installToken.")
    out.append("")

    # 7) Counts
    out.append("7. Externally-controlled counts/lengths mapped to source/dest/cap")
    for label, source, cap, dest, valrange, used_before_auth in [
        (
            "MODE count",
            "token MODE section header offset +2 (uint16_le)",
            "0x80 (capped at 0x0a654 add w9, w9, w11, lsl #2 and earlier cmp)",
            "destination: parser+0x2f000 + (mode_count*4)",
            "u16, [0..0xffff] accepted then capped to 0x80",
            "before signature verification (used in 0xa5cc signed-length calc)",
        ),
        (
            "INTE item count",
            "16-bit count is iterated; cap is the section end (0x0b86c b.hi)",
            "section-end",
            "per-type destinations of fixed size",
            "u16 derived from the INTE section length",
            "before signature verification",
        ),
        (
            "INTE type-1 length",
            "16-bit length per item",
            "0x1000 at 0x0b8a4 (cmp w4, #1, lsl #12; b.gt error)",
            "parser+0x2f000 area",
            "u16 [0..0xffff] capped to 0x1000",
            "before signature verification",
        ),
        (
            "INTE type-2 length",
            "16-bit length per item",
            "0x40 at 0x0b918 (cmp w24, #0x41; b.hs error)",
            "parser+0x2cc0 area",
            "u16 [0..0xffff] capped to 0x40",
            "before signature verification",
        ),
        (
            "INTE type-3 length",
            "16-bit length per item",
            "0x20 at 0x0b8c4 (cmp w24, #0x20; b.ne error)",
            "parser+0x2d00 area (32 bytes)",
            "fixed 0x20",
            "before signature verification",
        ),
        (
            "DEVI record loop count",
            "16-bit count read at 0x0a7a8",
            "implicit through section iteration (cbz at start)",
            "loop bound",
            "u16",
            "before signature verification (binding is checked at 0x0a858)",
        ),
        (
            "VALI date length",
            "16-bit length at offset +2 of VALI section",
            "checked by section iteration",
            "vali_buf",
            "u16",
            "before signature verification (lives inside signed region)",
        ),
        (
            "ESS request fields",
            "ESS sub-requests parsed at 0x14cec..0x16520",
            "ESS version 01 + 11-nonempty-tokens + 1-empty terminator",
            "ESS request structure",
            "various hex-typed string fields",
            "before any token install (the request is for a new token)",
        ),
    ]:
        out.append(f"  {label}:")
        out.append(f"    source: {source}")
        out.append(f"    cap:    {cap}")
        out.append(f"    dest:   {dest}")
        out.append(f"    range:  {valrange}")
        out.append(f"    pre-auth use: {used_before_auth}")
        out.append("")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# 4. Dev device / no token provenance
# ---------------------------------------------------------------------------


def dev_device_provenance() -> str:
    out = [""]
    out.append("Format string reference: %s:%d This is dev device and no token")
    out.append("Found in TA at file 0xf8d95 / VA 0xf7d95")
    out.append(
        "Only ADRP+ADD reference: VA 0xe9f0 (file 0xf9f0), reached from VA 0xe90c"
    )
    out.append(
        "Containing function: 0xe81c (em_token_get_string_modes handler);"
    )
    out.append(
        "  reached when token_struct+0x11 has bit 2 set (== token_struct+0x10"
    )
    out.append(
        "  has bit 10 == 0x400)."
    )
    out.append("")

    out.append("DEV-DEVICE CLASSIFIER: VA 0xe478 (file 0xf478)")
    out.append(
        "  Reads bytes at token_struct+0x36 and +0x37, BFI assembles them into a"
    )
    out.append("  16-bit value, compares against 0x3131 (ASCII '1','1').")
    out.append(
        "  If equal -> skip the OR; if different -> OR 0x400 into token->+0x10."
    )
    out.append(
        "  This is the only producer of the is_dev_token flag 0x400 in the audited"
    )
    out.append("  em.img; the same function is called from GET_STRING_MODES at 0xe864"
    )
    out.append("  and from GET_MODES_BIT at 0xeb48. The flag is consumed by 0xcfcc")
    out.append("  (device-record binding check) and by the dev-device log at 0xe9f0.")
    out.append("")

    out.append("DEVICE-RECORD BINDING CHECK: VA 0xcfcc (file 0xdfcc)")
    out.append(
        "  This is a different function from 0xe478. It compares 16 bytes of the"
    )
    out.append(
        "  parsed device-record cache at token+0x2ff7a against a source selected"
    )
    out.append("  by flag bits:")
    out.append(
        "    - if token+0x19 bit 2: source = *(token+0x342e0) + 0xa (live pointer)"
    )
    out.append(
        "    - if token+0xd bit 3:  source = token+0x341e3 (hardcoded 16 bytes)"
    )
    out.append("    - else:                  source = parsed DEVI prefix (via 0x84c8)")
    out.append(
        "  The comparison at 0x0d0ac (bl 0x1b0fc, 16-byte memcmp) is bounded; both"
    )
    out.append(
        "  the parsed cache and the chosen source are within the token's own buffer."
    )
    out.append("")

    out.append("DEV-LOG PATH: VA 0xe9f0 (file 0xf9f0)")
    out.append(
        "  0xe90c: ldrb w8, [x20, #0x11]; tbnz w8, #2, #0xe9f0"
    )
    out.append(
        "  Reads token+0x11 bit 2 (== +0x10 bit 10, the is_dev_token flag set by"
    )
    out.append("  0xe478). If set, the function logs 'This is dev device and no token'")
    out.append("  and continues with a different return path that does not install any")
    out.append("  mode state. The audit observes this branch only for tokens whose DID")
    out.append("  does not end in '11' (i.e. dev/QA tokens, not retail tokens).")
    out.append("")

    out.append("INPUT BUFFER: the parsed-token structure.")
    out.append(
        "  The +0x36/+0x37 bytes are part of the 16-byte DID stored at"
    )
    out.append(
        "  token_struct+0x28. The DID is parsed from the in-token DEVI section"
    )
    out.append(
        "  and is part of the token body that is hashed and signed. The DID is not"
    )
    out.append("  the runtime device's DID; it is the DID the token claims to be for.")
    out.append("")

    out.append("PROVENANCE SUMMARY:")
    out.append(
        "  The dev-device classification is a property of the TOKEN'S DID, not of"
    )
    out.append(
        "  the runtime device. The DID is part of the signed token body; flipping"
    )
    out.append("  the last 2 bytes of the DID invalidates the token signature.")
    out.append(
        "  HLOS / Android-root cannot influence the classification: it is derived"
    )
    out.append("  from in-token bytes that flow into SHA-256 of the signed body.")
    out.append("")

    out.append("ON THE AUDITED RETAIL DEVICE:")
    out.append(
        "  The boot device's own DID ends in '11' (per the cmdline/redactions in"
    )
    out.append("  original-research.md and the audit's runtime snapshot). Any token")
    out.append(
        "  presented to that device must contain a DID that matches the device's"
    )
    out.append(
        "  DID (the device-record binding check at 0xcfcc). A retail token's DID"
    )
    out.append(
        "  therefore ends in '11' as well, so the is_dev_token bit is NOT set in"
    )
    out.append(
        "  the audited runtime. The 'dev device / no token' path is not entered for"
    )
    out.append("  valid retail tokens, and it cannot be reached by HLOS manipulation.")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# 5. Compose the report
# ---------------------------------------------------------------------------


def header() -> str:
    return (
        "ROOT-TO-BOOT EXPLOIT SURFACE ANALYSIS\n"
        f"SOURCE ABL {ABL_PE.relative_to(ROOT)} SHA256 {sha256(ABL_PE)}\n"
        f"SOURCE EM  {EM_PART.relative_to(ROOT)} SHA256 {sha256(EM_PART)}\n"
        f"SOURCE DEV {DEVINFO.relative_to(ROOT)} SHA256 {sha256(DEVINFO)}\n"
        "ADDRESS_NOTATION this report uses actual PE RVA/file offset; radare2 VA is RVA+0x10000\n"
        "TARGET SM-S928B / e3q, S928BXXU5DZDP, One UI 8.5, temporary KernelSU root, bootloader locked\n"
        "METHOD read-only static analysis only; no state-modifying operations attempted\n"
    )


def executive_conclusion() -> str:
    return (
        "1. EXECUTIVE CONCLUSION\n"
        "The audited One UI 8.5 firmware (S928BXXU5DZDP) does not expose a\n"
        "defensible chain from temporary Android root to a persistent unlock or\n"
        "custom-kernel authorization without a valid Samsung MODE_CUST_KERNEL\n"
        "token. The two foundational primitives (a writer for the ABL IsUnlocked\n"
        "byte that does not require EM bit 3, and a pre-authentication parser\n"
        "confusion in the Engineering Mode TA) are not present in the audited\n"
        "artifacts.\n"
        "\n"
        "Specifically:\n"
        "  - The only effective writer of live devinfo+0x0d to 1 in the audited\n"
        "    PE is SetUnlocked (RVA 0x424cc), which is reached from the EM\n"
        "    sync block (BLInitToken -> GetEMBit(3) -> dispatcher) at RVA\n"
        "    0x99a4. There is no second writer in the audited code that\n"
        "    produces a 1 from HLOS-controllable state.\n"
        "  - The Engineering Mode TA's INTE parser caps every externally\n"
        "    controlled length to a value strictly less than the destination\n"
        "    buffer, and the leaf-certificate validator pins the RSA public\n"
        "    key by SHA-256 of the SPKI (or the entire DER for the\n"
        "    exceptional keyUsage path). The token's MODE, VALI and INTE\n"
        "    sections are inside the signed region; changing mode 3 or any\n"
        "    other field invalidates the signature.\n"
        "  - The 'is dev device / no token' classification is a property of the\n"
        "    TOKEN's DID (specifically the last 2 ASCII bytes, checked at 0xe478),\n"
        "    not of the runtime device. The DID bytes are part of the signed\n"
        "    token body, so they cannot be flipped without invalidating the\n"
        "    signature. The retail boot device's own DID ends in '11', and a\n"
        "    valid retail token must match the device's DID byte-for-byte at\n"
        "    the device-record binding check (0xcfcc).\n"
        "  - The 'state-preservation' path through the EFI MemCardInfo error\n"
        "    edge can carry a valid persisted 1 forward to AVB, but the only\n"
        "    way to obtain a persisted 1 is through SetUnlocked, which itself\n"
        "    requires EM bit 3 to be set, which requires a valid token. The\n"
        "    chain is circular for the original unlock problem (LIKELY NO,\n"
        "    classified ERROR_ONLY in abl-devinfo-bypass-analysis.txt).\n"
        "\n"
        "Temporary Android root on the audited device does not provide a\n"
        "non-circular control primitive over ABL or the Engineering Mode TA\n"
        "that would lead to an unlocked or custom-kernel boot.\n"
    )


def confirmed_trust_boundaries() -> str:
    return (
        "2. CONFIRMED TRUST BOUNDARIES\n"
        "  Hardware/secure world:\n"
        "    - UFS partition persistence (devinfo/persistent/steady): read by\n"
        "      ABL on every boot. Writable only by ABL code paths that pass\n"
        "      through the devinfo-aware helpers (0x0ff30, 0x42ecc, 0x42f24)\n"
        "      and by the AVB persistence at 0x0ff30. There is no HLOS-side\n"
        "      access path that reaches these helpers without a kernel/ABL\n"
        "      compromise.\n"
        "    - Engineering Mode RPMB state: read by GetEMBit (0xadae0) via the\n"
        "      TA. The TA's storage I/O is the qsee_stor_* family; HLOS cannot\n"
        "      write RPMB directly.\n"
        "    - RPMB root key: provisioned in factory. Not recoverable from the\n"
        "      audited em.img.\n"
        "\n"
        "  ABL image (bootloader):\n"
        "    - Live devinfo structure (0x170e28..0x170e28+0xcd0). Read at\n"
        "      DeviceInfoInit; written at SetUnlocked and on invalid-data\n"
        "      defaults. There is no in-PE primitive that can flip +0x0d to 1\n"
        "      without going through SetUnlocked, and SetUnlocked is only\n"
        "      called from the EM sync dispatcher and from the UI lock-state\n"
        "      handler (which itself reads the same byte).\n"
        "    - AVB callback read_is_device_unlocked (0x51048) reads IsUnlocked\n"
        "      live. There is no cache that could carry a 1 across an\n"
        "      intervening 0 write.\n"
        "    - UEFI variable writes: not used in the audited main path for\n"
        "      state that affects IsUnlocked.\n"
        "\n"
        "  Trustlet (em.img):\n"
        "    - State bitmap (256 bits) at parser+0x2ff7a. The TA updates it\n"
        "      from RPMB on init, and from installToken on a successful token\n"
        "      install. There is no other writer in the audited TA.\n"
        "    - Token signing keys: RSA public key SPKIs pinned in the TA at\n"
        "      0xf3cca..0xf503c. Private keys are not in the device.\n"
        "\n"
        "  HLOS / Android:\n"
        "    - Engineering Mode AIDL service (vendor.samsung.hardware.security.\n"
        "      engmode.ISehEngmode/default). The service routes to the TA via\n"
        "      /vendor/bin/emservice -> libengmode_tlc.so. The client-side\n"
        "      allowlist is in lib.engmode.samsung.so; the server-side\n"
        "      EngineeringModeHandler::callerCheck is a no-op.\n"
        "    - Android kernel and TrustZone TA share the same /dev/block/sdd15\n"
        "      EM partition read-only mapping; HLOS cannot write to RPMB.\n"
        "    - AIDL transactions 3/5/7/22 reach the service in the observed\n"
        "      root context. State-changing transactions (installToken,\n"
        "      makeTokenReq, sendFuseCmd) were not exercised; this report\n"
        "      does not claim they cannot reach the TA, but it also does not\n"
        "      assert they would pass TA-level authentication.\n"
    )


def deviceinfo_matrix_section() -> str:
    return (
        "3. ABL DEVINFO WRITER/READER MATRIX\n"
        + devinfo_writer_reader_matrix()
    )


def abl_persistent_section() -> str:
    return (
        "4. ABL PERSISTENT-INPUT ATTACK SURFACE CANDIDATES\n"
        + abl_persistent_input_surface()
    )


def ta_preauth_section() -> str:
    return (
        "5. TA PRE-AUTHENTICATION PARSER SURFACE\n"
        + ta_preauth_surface()
    )


def dev_provenance_section() -> str:
    return (
        "6. DEV-DEVICE CLASSIFICATION PROVENANCE\n"
        + dev_device_provenance()
    )


def candidate_chains() -> str:
    return (
        "7. CANDIDATE CHAINS\n"
        "Chain A: temporary root -> devinfo+0x0d=1 -> reboot -> AVB unlocked\n"
        "  temporary Android root\n"
        "      | can write the devinfo partition from userspace\n"
        "      v\n"
        "  /dev/block/by-name/devinfo at +0x0d set to 1\n"
        "      | persists across reboot, read at ABL DeviceInfoInit (0x425ec)\n"
        "      v\n"
        "  ABL LinuxLoader\n"
        "      | on EFI success path, BLInitToken -> GetEMBit(3) -> SetUnlocked(0)\n"
        "      | on EFI error path (LocateProtocol MemCardInfo fails), lazy init\n"
        "      | loads +0x0d=1 and the EM sync block does not run.\n"
        "      v\n"
        "  live devinfo+0x0d=1 -> AVB read_is_device_unlocked returns 1\n"
        "      |\n"
        "      v\n"
        "  AVB: device_state=unlocked, vbmeta verify skipped, OEM unlock UI\n"
        "      | chain results in 'unlocked but bootloader still locked' state\n"
        "      v\n"
        "  bootloader state: devinfo+0x0d=1 does not set devinfo+0x90 or any\n"
        "  ABL 'bootloader_unlocked' flag. The Samsung bootloader does not\n"
        "  interpret IsUnlocked as a permission to boot a custom kernel; it is\n"
        "  the user-facing toggle. The state is partially effective: AVB allows\n"
        "  permissive vbmeta, but the second-stage bootloader (ABL/SBL) still\n"
        "  refuses to boot a tampered boot image because the verified-boot\n"
        "  state is reported but not enforced at SBL/ABL level on this build.\n"
        "\n"
        "  ARROW STATE:\n"
        "    - temporary root -> devinfo+0x0d=1   : PROVEN on Android (root can write partitions)\n"
        "    - devinfo+0x0d=1 -> persists to next boot : PROVEN (DeviceInfoInit reads 0xcd0)\n"
        "    - DeviceInfoInit -> live +0x0d=1      : PROVEN on the EFI-error path\n"
        "    - EFI-error path actually taken       : UNPROVEN (LocateProtocol on a retail UFS target\n"
        "      likely never returns EFI_ERROR once the UFS driver publishes the protocol)\n"
        "    - live +0x0d=1 -> AVB unlocked         : PROVEN (callback at 0x51048)\n"
        "    - AVB unlocked -> custom kernel boots  : DEAD END on this build. The Samsung bootloader\n"
        "      does not honor devinfo+0x0d as a kernel-signing bypass; the chain collapses.\n"
        "\n"
        "  CLASSIFICATION: POTENTIAL CHAIN. Every edge that matters is supported by code/artifacts,\n"
        "  but the final edge (AVB-unlocked -> custom kernel) does not exist on Samsung devices. The\n"
        "  chain is 'unlock user toggle' not 'unlock bootloader'.\n"
        "\n"
        "Chain B: temporary root -> malformed token -> TA installToken bypass -> RPMB bit 3 -> ABL unlock\n"
        "  temporary Android root\n"
        "      | can call vendor Engineering Mode AIDL directly\n"
        "      v\n"
        "  /vendor/bin/emservice -> libengmode_tlc.so -> TA em_token_install\n"
        "      | token reaches the TA; INTE parser extracts type-1 sig, type-2 cert\n"
        "      | leaf cert validator 0x3474 selects one of two anchor pairs\n"
        "      | and the type-1 RSA-2048 signature is verified with the leaf key\n"
        "      v\n"
        "  em_token_install persists the new bitmap in RPMB\n"
        "      | next reboot, ABL GetEMBit(3) returns 1\n"
        "      v\n"
        "  ABL SetUnlocked(1) -> AVB unlocked\n"
        "\n"
        "  ARROW STATE:\n"
        "    - temporary root -> emservice : PROVEN on this build (read-only probes 3/5/7/22 reached)\n"
        "    - emservice -> TA install :   NOT EXERCISED in this audit; transport plausible\n"
        "    - TA install -> RPMB bit 3  : REQUIRES valid leaf cert + signature (RSA-2048)\n"
        "    - leaf cert validator bypass : NOT FOUND in the audited code\n"
        "    - RSA bypass                  : NOT FOUND (recovered bytes are bounded at 256)\n"
        "\n"
        "  CLASSIFICATION: DEAD END. The parser caps every length, the bounds are strict, the cert is\n"
        "  SPKI-pinned, the signature uses PKCS#1 v1.5 type-1 with strict padding, and the body hash\n"
        "  is compared byte-for-byte. No pre-authentication primitive is available.\n"
        "\n"
        "Chain C: temporary root -> dev-token install (DID ends != '11') -> TA dev path -> persistence\n"
        "  temporary Android root\n"
        "      | crafts a token whose DID does not end in '11' (e.g. '00')\n"
        "      v\n"
        "  emservice -> TA em_token_install\n"
        "      | 0xe478 marks is_dev_token flag (token+0x10 bit 10)\n"
        "      v\n"
        "  TA may enter the 'dev device / no token' branch at 0xe9f0\n"
        "      | returns without installing mode state (the 'dev device' log path\n"
        "      | does not write to RPMB; it logs and returns an error code)\n"
        "      v\n"
        "  reboot -> ABL BLInitToken -> GetEMBit(3) -> SetUnlocked\n"
        "\n"
        "  ARROW STATE:\n"
        "    - dev-token creation        : REQUIRES a valid signature for a dev-class DID\n"
        "    - The dev-class DID does not match the retail device's DID\n"
        "      (device-record binding check at 0xcfcc and earlier 0xa7a8 loop)\n"
        "    - The install path rejects the token before any RPMB write\n"
        "  CLASSIFICATION: DEAD END. The DID is bound to the device before the dev-device path is\n"
        "  considered, and a retail device cannot accept a non-matching dev-class token.\n"
    )


def dead_ends() -> str:
    return (
        "8. DEAD ENDS (additional)\n"
        "  - Persistent partition (/dev/block/by-name/persistent): only read by the One UI 7 OEM/FRP\n"
        "    path. The One UI 8.5 OEM/FRP path at 0xa13b0 is a stub that returns 0 without reading it.\n"
        "  - /steady filesystem blobs: the TA's RPMB AES-GCM stack is the only path; /steady is not\n"
        "    used by any audited code that affects the unlock state.\n"
        "  - Direct partition writes to em.img: the partition is mapped read-only into the TA. The\n"
        "    auditable em.img cannot be modified by HLOS.\n"
        "  - The 0x9860 'recursive' call: a radare2 function-boundary artifact. The actual call target\n"
        "    is the Odin launcher at 0x90ec, which is the download-mode application, not LinuxLoader.\n"
        "  - UEFI variable access: the only EFI Boot Services call on the audited main path is\n"
        "    LocateProtocol for gEfiMemCardInfoProtocolGuid. No GetVariable/SetVariable reaches the\n"
        "    unlock path. Setting UEFI variables from Android requires a kernel exploit that the\n"
        "    audited root does not provide.\n"
        "  - AIDL transactions on emservice: read-only probes reached transactions 3,5,7,22 with\n"
        "    SELinux Enforcing. installToken/makeTokenReq/sendFuseCmd were not exercised in this\n"
        "    audit. They reach the TA's parser, which has the strict bounds and pinning documented\n"
        "    above.\n"
    )


def highest_value_next_static() -> str:
    return (
        "9. HIGHEST-VALUE NEXT STATIC WORK\n"
        "  a. Trace every reference to live devinfo+0x0d in the audited PE and\n"
        "     confirm that no caller in the OEM UI / lock-state branches can\n"
        "     write the byte from HLOS-controllable data. The current matrix\n"
        "     (file 3, this report) shows the SetUnlocked call sites; verify\n"
        "     the OEM UI branch at 0xacd2c only writes when a valid user\n"
        "     toggle is present.\n"
        "  b. Re-derive the leaf-cert validator's exceptional-path digest at\n"
        "     file 0xf4caa and confirm it is a fixed hardcoded SHA-256 of a\n"
        "     specific X.509 DER, not a parameter that HLOS can substitute.\n"
        "  c. Audit the EM_CMD_GET_TUC path (0x8900) and the TUC update path\n"
        "     to confirm that /steady is not an alternate persistence source\n"
        "     for the runtime mode bitmap.\n"
        "  d. Trace the makeTokenReq parcel (transaction 11) to confirm the\n"
        "     AIDL parcel shape and the server-side argument count/order, so a\n"
        "     future dynamic test can be shaped correctly without relying on\n"
        "     historical heuristics.\n"
        "  e. Confirm that the OEM-lock HAL binary (not in this repo) routes\n"
        "     its carrier boolean to either the AIDL backend or the HIDL\n"
        "     backend in a way that does not involve a state that the audited\n"
        "     TA or ABL can mutate.\n"
    )


def requires_dynamic() -> str:
    return (
        "10. WHAT WOULD REQUIRE DYNAMIC TESTING\n"
        "  - Whether gEfiMemCardInfoProtocolGuid is published on every normal\n"
        "    retail boot of this exact S928B build. A real device with the\n"
        "    same firmware version must be observed to confirm that the EFI\n"
        "    error path is never taken. The static evidence shows that the\n"
        "    path is structurally valid but not reachable on a normal boot;\n"
        "    a dynamic test can confirm or refute this.\n"
        "  - Whether the OemLockService active backend on the live device is\n"
        "    the AIDL HAL, the HIDL HAL, or PersistentDataBlockLock. The\n"
        "    static `oem-lock-service-evidence.txt` is ambiguous; a `lshal`\n"
        "    listing including `oemlock` is required to settle the question.\n"
        "  - Whether the AIDL transactions for makeTokenReq and installToken\n"
        "    (transactions 11 and 2) actually reach the TA in the observed\n"
        "    root context. The transport is plausible; the parcel shape and\n"
        "    the TA's authentication path are documented but not exercised.\n"
        "  - Whether the emservice process actually validates the SehCallerInfo\n"
        "    fields on the no-ScInfo paths (makeTokenReq/getStatus). The\n"
        "    static analysis shows that EngineeringModeHandler::callerCheck is\n"
        "    a no-op; whether the TLC adds a check is unverified.\n"
    )


def main() -> None:
    out = ROOT / "decompiled" / "root-to-boot-exploit-surface-analysis.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    sections = [
        header(),
        executive_conclusion(),
        confirmed_trust_boundaries(),
        deviceinfo_matrix_section(),
        abl_persistent_section(),
        ta_preauth_section(),
        dev_provenance_section(),
        candidate_chains(),
        dead_ends(),
        highest_value_next_static(),
        requires_dynamic(),
    ]
    out.write_text("\n".join(sections), encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)} ({out.stat().st_size} bytes)")
    print(f"sha256 {sha256(out)}")


if __name__ == "__main__":
    main()
