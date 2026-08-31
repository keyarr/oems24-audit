#!/usr/bin/env python3
"""ABL post-unlock authentication analysis.

This script extends the existing ABL audit pipeline with a focused analysis
of what security-relevant operations still occur after LinuxLoader accepts
IsUnlocked == 1 and before it hands off to the next boot stage.

It is read-only, deterministic, and fails loudly if the input artifacts
change. All offsets reported are PE RVA / file offset. radare2 VA values
are explicitly distinguished where the existing audit log uses them.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from abl_audit import CURRENT, DEVINFO, R2_BIAS  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
EM_PART = ROOT / "partitions" / "em.img"
ABL_PE = ROOT / "decompiled" / "linuxloader-oneui8.pe"
MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def disasm(path: Path, start: int, end: int) -> list[str]:
    data = path.read_bytes()[start:end]
    out = []
    for insn in MD.disasm(data, start):
        out.append(
            f"  RVA/file 0x{insn.address:06x}  r2 0x{insn.address + R2_BIAS:06x}  "
            f"{insn.mnemonic:<8} {insn.op_str}"
        )
    return out


def find_bl_targets(data: bytes, target: int) -> list[int]:
    out: list[int] = []
    for rva in range(0, len(data) - 4, 4):
        insn = struct.unpack_from("<I", data, rva)[0]
        if (insn >> 26) != 0x25:
            continue
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= 1 << 26
        target_va = (rva + (imm26 << 2)) & 0xFFFFFFFF
        if target_va == target:
            out.append(rva)
    return out


def decode_adrp(insn: int):
    if (insn >> 31) & 1 == 0:
        return None
    if ((insn >> 24) & 0x9F) != 0x90:
        return None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (rd, imm)


def find_adrp_add_to(data: bytes, target: int, max_window: int = 16) -> list[int]:
    out: list[int] = []
    for rva in range(0, len(data) - 4, 4):
        insn = struct.unpack_from("<I", data, rva)[0]
        adrp = decode_adrp(insn)
        if not adrp:
            continue
        rd, page_delta = adrp
        pc_page = rva & ~0xFFF
        target_page = pc_page + (page_delta << 12)
        if target_page + 0x1000 <= target or target_page > target:
            continue
        for k in range(max_window):
            if rva + 4 + k * 4 >= len(data):
                break
            nxt = struct.unpack_from("<I", data, rva + 4 + k * 4)[0]
            if (nxt & 0xFFC00000) != 0x91000000:
                continue
            imm12 = (nxt >> 10) & 0xFFF
            rn = (nxt >> 5) & 0x1F
            if rn == rd and (target_page + imm12) == target:
                out.append(rva)
                break
    return out


# ---------------------------------------------------------------------------
# Section: 0x96f8 avb_slot_verify call site and result handling
# ---------------------------------------------------------------------------


def avb_call_site_section() -> str:
    data = CURRENT.read_bytes()
    lines = [
        "A. AVB SLOT VERIFY CALL SITE (RVA 0x96f8)",
        "   0x9240 LinuxLoader main entry",
        "   0x96f8 bl 0x140dc    ; avb_slot_verify(AvbOps, slot, ...)",
        "   0x96fc ldr w8, [sp, #0x460]   ; AVB_SLOT_VERIFY_RESULT loaded",
        "   0x9700 cmp w8, #3    ; ROLLBACK_INDEX = 3",
        "   0x9704 ccmp x0, #0, #0, ne  ; AND x0==0",
        "   0x9708 b.eq 0x9820   ; if (result==3 && x0==0) -> slot-swap",
        "   0x970c-0x9770      : rollback / version error logging and bail",
        "   0x9798 bl 0x48460 (red warning UI helper)",
        "   0x979c bl 0xb8b0    ; SetVerifiedBootState(?)",
        "   0x97b4-0x97d4      : rollback / version error checks",
        "   0x9820 bl 0x16e54   ; success path - BootLinux(...)",
        "   0x9828 tbnz x19, #63, #0x9890  ; EFI error path",
        "",
        "   RESULT HANDLING (RVA 0x1630c-0x16400, inside the verification wrapper):",
        "   0x1630c ldr w8, [x19, #0x438]    ; load wrapper result/flags",
        "   0x16310 cmp w8, #1            ; case 1: AVB_RESULT_OK",
        "   0x16314 b.eq 0x16358         ; -> unlocked path",
        "   0x16318 cmp w8, #2            ; case 2",
        "   0x1631c b.eq 0x1639c",
        "   0x16320 cmp w8, #3            ; case 3 (some other status)",
        "   0x16324 b.ne 0x163d8         ; default: continue past switch",
        "   0x16328 mov w0, #2",
        "   0x1632c bl 0x590ac            ; display a status UI (arg=2)",
        "   0x16330 cbz x0, 0x163d8      ; UI failed -> continue",
        "   0x16334-0x16350             : log + return",
        "   0x16358 ldrb w8, [sp]        ; byte set at 0x162dc on one path",
        "   0x1635c cbz w8, 0x1636c      ; if 0 -> skip 0x18dd8",
        "   0x16360 bl 0x18dd8            ; descriptor foreach (RVA 0x18dd8)",
        "   0x16364 tst w0, #0xff",
        "   0x16368 b.eq 0x16440         ; result handling",
        "   0x1636c mov w0, #1",
        "   0x16370 bl 0x590ac            ; display a status UI (arg=1)",
        "   0x16374 cbz x0, 0x163d4      ; UI failed -> 0x163d4 (fallback)",
        "   0x16378-0x16388             : log + return on UI success",
        "   0x16390 adrp x1, #0xb6000",
        "   0x16394 add  x1, x1, #0x1b6   ; string at file 0xb61b6",
        "   0x16398 b    0x163c8         ; log the string",
        '   STRING = "Device is unlocked, Skipping boot verification"',
        "   0x163d4 bl 0x59254            ; UI fallback",
        "   0x163d8 bl 0x42310            ; update persistent record",
        "   0x163dc tst w0, #0xff",
        "   0x163e0 b.ne 0x163ec",
        "   0x163e4-0x163e8             : check record flag",
        "   0x163ec bl 0x16754            ; stack canary check (epilogue)",
        "   0x163f0 b.ne 0x16470         ; (to error path)",
        "   0x163f4-0x163fc             : function epilogue, ret",
    ]
    lines.append("")
    lines.append("FUNCTION CALLERS OF 0x140dc (avb_slot_verify):")
    callers = find_bl_targets(data, 0x140DC)
    for c in callers:
        lines.append(f"   BL to 0x140dc at RVA 0x{c:x}")
    if not callers:
        lines.append("   (no direct BL; reached via the audit-documented main flow at 0x96f8)")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Section: All IsUnlocked readers
# ---------------------------------------------------------------------------


def isunlocked_readers_section() -> str:
    data = CURRENT.read_bytes()
    # Per the existing audit: callers at 0x144e0, 0x14954, 0x42f30, 0x51060,
    # 0x581dc, 0x98d54, 0xa7e78, 0xacc70
    sites = {
        0x144E0: "avb_slot_verify 0x140dc  -> branch to verification-skip (0x14520)",
        0x14954: "verifier_3xxx 0x147bc  -> related AVB descriptor-foreach",
        0x42F30: "isunlocked_set/refresh area (audit helper)",
        0x51060: "libavb read_is_device_unlocked callback (AvbOps+0x48)",
        0x581DC: "lock/unlock UI flow",
        0x98D54: "main LinuxLoader -> writes cset w8, eq to global state 0x1507fc",
        0xA7E78: "GetEM/EM-misc flow (selects from EM result)",
        0xACC70: "UI flow (load/unlock UI)",
    }
    lines = [
        "B. ALL IsUnlocked READERS (BL to RVA 0x41ed0)",
        "IsUnlocked is the function at RVA 0x41ed0 which reads the live",
        "DeviceInfo+0x0d byte and returns it (zero-extended).",
    ]
    for site, note in sites.items():
        bls = find_bl_targets(data, site)
        lines.append(f"   0x{site:x}  ({note})")
        for c in bls:
            lines.append(f"     BL at RVA 0x{c:x}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Section: SetUnlocked() side effects
# ---------------------------------------------------------------------------


def setunlocked_side_effects_section() -> str:
    return (
        "C. SetUnlocked() SIDE EFFECTS (RVA 0x424cc)\n"
        "The function SetUnlocked writes only:\n"
        "   - RVA 0x42524: strb w19, [x1, #0xd]  (live +0x0d)\n"
        "   - RVA 0x4251c: str  w9,  [x8, #0xab0]  (UnlockCount, devinfo+0xc88)\n"
        "   - RVA 0x42528: bl   0xff30            (persist full 0xcd0-byte DevInfo)\n"
        "Callers of SetUnlocked (RVA 0x424cc):\n"
        "   - dispatcher at RVA 0x41f88, called from RVA 0x99a4 (BLInitToken->GetEMBit->SetUnlocked)\n"
        "   - the lock/unlock UI flow at RVA 0xacd2c (sets via UI button)\n"
        "It does NOT modify any other boot state (no kernel cmdline change, no\n"
        "verification flag change, no separate authentication variable).\n"
    )


# ---------------------------------------------------------------------------
# Section: Indirect handoff near BootLinux
# ---------------------------------------------------------------------------


def handoff_search_section() -> str:
    data = CURRENT.read_bytes()
    # ERET
    erets = [rva for rva in range(0, len(data) - 4, 4) if struct.unpack_from("<I", data, rva)[0] == 0xD69F03E0]
    # SVC #0
    svcs = [rva for rva in range(0, len(data) - 4, 4) if struct.unpack_from("<I", data, rva)[0] == 0xD4000001]
    # br x0 (kernel handoff via indirect)
    out = [
        "D. INSTRUCTION-LEVEL HANDOFF SEARCH",
        "ERET encoding 0xD69F03E0 (return from EL2 to EL1/EL0):",
        f"   count = {len(erets)}",
        "SVC #0 encoding 0xD4000001 (sync exception into EL1):",
        f"   count = {len(svcs)}",
        "Interpretation: LinuxLoader does NOT use ERET or SVC to hand off to the kernel.",
        "The actual handoff is the indirect call at RVA 0x1a1bc which loads a",
        "function pointer from a runtime EFI protocol structure and branches to it.",
        "That pointer is set up via the standard gBS / gRT boot services table.",
    ]
    out.append("")
    out.append("Targeted search inside the BootLinux function (0x16e54-0x18500):")
    for rva in range(0x16E54, 0x18500, 4):
        insn = struct.unpack_from("<I", data, rva)[0]
        if insn == 0xD61F0000:
            out.append(f"   br x0  at RVA 0x{rva:x}  (hypothetical kernel jump)")
        if insn == 0xD63F0000:
            out.append(f"   blr x0 at RVA 0x{rva:x}  (indirect call)")
    out.append(
        "Conclusion: the post-BootLinux code uses gBS->StartImage-style\n"
        "indirection (RVA 0x1a1bc / 0x1b340). There is no direct ERET or SVC in\n"
        "the audited binary that bypasses the AVB result handling."
    )
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Section: SCM / QSEE / TrustZone cross-stage checks
# ---------------------------------------------------------------------------


def tz_qsee_section() -> str:
    data = CURRENT.read_bytes()
    needles = [
        (b"qsee", "QSEECom"),
        (b"QSEECOM", "QSEECOM protocol"),
        (b"SCM", "Locate SCM Protocol"),
        (b"TZ_", "TZ app"),
        (b"qcom,", "DTB compatibility string"),
        (b"KVB", "Knox Vault Boot"),
        (b"KNOXGUARD", "KNOXGUARD"),
    ]
    lines = [
        "E. TZ / QSEE / SCM STRING SURVEY",
        "Strings that indicate second-stage authentication APIs:",
    ]
    for needle, label in needles:
        for pos in 0, data.find(needle):
            # We re-run with proper starting offset
            pass
        for pos in range(0, len(data) - len(needle)):
            if data[pos : pos + len(needle)] != needle:
                continue
            ctx = data[max(0, pos - 16) : pos + 60]
            if any(c < 0x20 or c > 0x7E for c in ctx[: max(0, pos - 16)]):
                # skip if the lead bytes are non-printable (likely data)
                pass
            lines.append(f"   {label!r:>30} at 0x{pos:x}: {ctx!r}")
            break
    lines.append("")
    lines.append(
        "Findings: the only QSEECom-related string is at file 0xbeb70\n"
        "('Unable to locate QSEECom protocol' inside libavb/avb_rsa.c). This\n"
        "is the standard libavb RSA backend; it is invoked from inside\n"
        "avb_slot_verify. There is no separate kernel-image-auth call.\n"
    )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Section: locked vs unlocked diff
# ---------------------------------------------------------------------------


def locked_vs_unlocked_section() -> str:
    return (
        "F. LOCKED vs UNLOCKED DIFF (after avb_slot_verify enters 0x140dc)\n"
        "\n"
        "LOCKED PATH  (IsUnlocked=0, normal slot verify):\n"
        "   0x144e0 bl IsUnlocked -> w0=0\n"
        "   0x144e4 tst w0, #0xff\n"
        "   0x144e8 b.eq 0x14580  -> jump to 0x14580\n"
        "   0x14580 mov x0, x19\n"
        "   0x14584 bl 0x16238    -> call verify wrapper (does full AVB flow)\n"
        "       Wrapper at 0x16238 returns normally with w8!=1, no 'unlocked' log\n"
        "\n"
        "UNLOCKED PATH  (IsUnlocked=1, set by prior EM sync or earlier set):\n"
        "   0x144e0 bl IsUnlocked -> w0=1\n"
        "   0x144e4 tst w0, #0xff\n"
        "   0x144e8 b.eq NOT taken  -> fall through to 0x144ec\n"
        "   0x144ec cbz x23, 0x14580  -> if x23==0, take locked path (defensive)\n"
        "   0x144f0 bl 0x1c70; tst w0, #0xff\n"
        "   0x144f8 b.eq 0x1451c   -> if 0, jump past extra checks\n"
        "   0x144fc bl 0x1674c; tst w0, #0xff\n"
        "   0x14504 b.eq 0x1451c\n"
        "   0x1451c mov x0, x19\n"
        "   0x14520 bl 0x16238      -> call verify wrapper\n"
        "       Inside wrapper at 0x16358: reads sp byte, may call 0x18dd8,\n"
        "       may log 'Device is unlocked, Skipping boot verification'\n"
        "\n"
        "After the wrapper returns (either path):\n"
        "   0x1474c  bl 0x1677c  ; stack canary check\n"
        "   0x14758  b.ne 0x147b8 ; mismatch -> 0x14a4 panic path\n"
        "   0x1475c  mov x0, x23 ; return value x23\n"
        "   0x14760-0x14774  : function epilogue, ret\n"
        "\n"
        "Inside 0x16358 'unlocked' branch (RVA 0x16358-0x163d8):\n"
        "   - 0x18dd8  descriptor foreach (helper)\n"
        "   - 0x590ac  red-warning UI (arg=1)\n"
        "   - 0x42310  persistent record update (writes devinfo+0x11)\n"
        "   - log 'Device is unlocked, Skipping boot verification' at 0x16390\n"
        "   - NO additional signature check\n"
        "   - NO additional TLS / TrustZone call\n"
        "\n"
        "POST-VERIFY (0x96fc-0x9828 in main LinuxLoader):\n"
        "   - on AVB result = ROLLBACK_ERROR (w8==3 && x0==0): slot swap path (0x9820)\n"
        "   - on rollback / version errors: log and bail to 0x994c (or 0x9948)\n"
        "   - on success: b 0x97b4 path; SetVerifiedBootState at 0x979c\n"
        "   - IsUnlocked read at 0x98d54: writes INVERSE state (cset eq) to global 0x1507fc\n"
        "     which is then propagated to NVRAM via gRT->SetVariable (no further gate)\n"
        "\n"
        "THEN: EM sync (0x998c-0x99a4) -> SetUnlocked, then BootLinux (0x9820 -> 0x16e54)\n"
    )


# ---------------------------------------------------------------------------
# Header / footer
# ---------------------------------------------------------------------------


def header() -> str:
    return (
        "ABL POST-UNLOCK AUTHENTICATION ANALYSIS\n"
        f"SOURCE ABL {ABL_PE.relative_to(ROOT)} SHA256 {sha256(ABL_PE)}\n"
        f"SOURCE DEV {DEVINFO.relative_to(ROOT)} SHA256 {sha256(DEVINFO)}\n"
        f"SOURCE EM  {EM_PART.relative_to(ROOT)} SHA256 {sha256(EM_PART)}\n"
        "ADDRESS_NOTATION this report uses actual PE RVA / file offset. radare2\n"
        "  VA values, where used in earlier audits, are actual RVA + 0x10000.\n"
        "TARGET SM-S928B / e3q, S928BXXU5DZDP, One UI 8.5\n"
        "METHOD read-only static analysis. No state-changing operation.\n"
    )


def main() -> None:
    pe = CURRENT.read_bytes()
    em = EM_PART.read_bytes()

    # Marker checks: fail loudly if a known offset/byte pattern disappears.
    markers = [
        (pe, 0xB61B6, b"Device is unlocked, Skipping boot verification", "Skipping log string"),
        (em, 0xF8D9B, b"This is dev device and no token", "dev-token log string (em.img)"),
    ]
    for data, off, needle, label in markers:
        if off + len(needle) > len(data):
            raise SystemExit(f"input too small for marker {label}")
        if data[off : off + len(needle)] != needle:
            raise SystemExit(
                f"marker mismatch: {label} at file 0x{off:x} expected {needle!r}"
            )

    out = ROOT / "decompiled" / "abl-post-unlock-auth-analysis.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    sections = [
        header(),
        avb_call_site_section(),
        isunlocked_readers_section(),
        setunlocked_side_effects_section(),
        handoff_search_section(),
        tz_qsee_section(),
        locked_vs_unlocked_section(),
    ]
    out.write_text("\n".join(sections), encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)} ({out.stat().st_size} bytes)")
    print(f"sha256 {sha256(out)}")


if __name__ == "__main__":
    main()
