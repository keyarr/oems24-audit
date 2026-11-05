# SVE-2026-3546 triage for the SM-S928B research

Date: 2026-11-04

## Verdict

The SVE-2026-3546 PoC in `SVE-2026-3546/` is not directly portable to the
SM-S928B target. Reusing its USB/Odin transport is plausible because the
SM-S928B ABL has an Odin USB handler and the audited protocol includes command
`0x66`. Porting the exploit itself remains unproven: the repo PoC is an
S5E8825-specific LK exploit and payload, while
the audited device is the Snapdragon SM8650 `e3q`, whose boot chain and analyzed
unlock path are Qualcomm XBL plus Samsung ABL/LinuxLoader. The repo has no
SM8650 adaptation, compatible LK image, offsets, or payload profile.

The underlying SVE may still be relevant to an unpatched S24 firmware, but
public details do not identify the vulnerable bootloader component or affected
models. Samsung's November 2026 bulletin says Android 14–17 builds before
SMR Nov-2026 Release 1 are affected by an out-of-bounds write in the
bootloader, exploitable by a physical attacker, and says the patch adds input
validation. This is not enough to establish that the S24's ABL/Odin path
contains the flaw. The current firmware corpus ends at DZDP (April 2026) and
DZG1 (July 2026), both predating the stated fix; there is no post-fix S24 image
here to compare.

## Evidence from the PoC

- `README.md` explicitly limits support to platform `s5e8825` and describes
  fusing Secure Boot KEY2 and flashing re-signed bootloader files.
- `resolve.py` rejects any LK image without the literal `s5e8825` and derives
  addresses from that LK's memory map, Odin V3 buffers, compression path, and
  callback layout. Those addresses cannot be carried over to SM8650.
- `s5e8825.json`, the signing layout, and the build scripts are specific to
  that platform. The payload also invokes OTP SMC selectors to write/use KEY2
  and flashes bootloader partitions; this is a destructive end-to-end demo,
  not a harmless compatibility probe.
- `flash_and_fuse.py` triggers the issue through Samsung's USB Odin/Loke
  protocol. Similarity of protocol names does not prove the vulnerable parser
  or memory layout exists in the S24's boot chain.
- The S24 corpus already contains a reverse-engineered Odin USB handler in
  `audit/decompiled/odin-oneui8.pe`. Its manual audit maps command `0x66`,
  including the data receive path, and records a size cap plus a matching
  300 MiB allocation. It does not identify the PoC's compressed-download
  overflow in that handler. The exact parser and subcommand behavior still
  needs a direct crosswalk against the PoC; the existing Odin audit leaves
  per-command parse-before-verify work open.

## Relation to the unlock research

If an SM8650 implementation gave arbitrary code execution or an equivalent
pre-auth write in the bootloader before AVB, it could in principle change the
unlock-state analysis: the current research found `devinfo+0x0d` is consumed by
AVB, but its legitimate writer is `SetUnlocked`, fed by Engineering Mode bit
3. A bootloader compromise could potentially bypass that trust path. The
published advisory only guarantees an out-of-bounds write, however; it does
not establish controllable writes, code execution, persistence, execution
before AVB, or reachability to `devinfo`/the AVB decision. The current PoC's
KEY2 fuse and re-sign workflow must not be treated as proof of any of those
properties on S24.

## Assessment and next evidence

| Question | Assessment |
| --- | --- |
| Can the Odin transport be reused? | Plausibly, in part: the S24 has Odin USB and command `0x66`; matching the PoC's compressed subcommands and vulnerable operation is not yet established. |
| Can the checked-in exploit/payload be ported as-is? | No; it rejects non-S5E8825 LK and derives platform-specific memory, callback, and buffer addresses. |
| Could a ported exploit affect a pre-November S24 bootloader? | Possible only if the same bug exists in the S24 handler or an equivalent path; the advisory and current audit do not establish that. |
| Does the current evidence show an unlock primitive? | No. The advisory says OOB write only; exploitability and effect on the unlock/AVB path are unknown. |
| Is the S24 baseline potentially pre-fix? | Yes. DZDP and DZG1 predate SMR Nov-2026 Release 1, but actual applicability and device patch delivery must be checked against the model's firmware. |

To resolve portability, crosswalk each PoC Odin command and subcommand through
the S24 ABL dispatcher, then compare the receive/decompression path and the
specific out-of-bounds sink. The current S24 audit has already mapped much of
the USB handler, so this is a bounded follow-up rather than a ground-up port.
Then obtain the exact SM-S928B post-November bootloader package and its pre-fix
counterpart to identify the patched component and compare the handler. Do not
run the checked-in `flash_and_fuse.py` on the S24: its code path writes
bootloader images and fuses OTP state, and its platform assumptions are wrong
for this target.

## Sources

- Samsung Mobile Security, SMR Nov-2026, SVE-2026-3546 / CVE-2026-21155:
  https://security.samsungmobile.com/securityUpdate.smsb?month=10&year=2026
- Local PoC: `SVE-2026-3546/README.md`, `resolve.py`, `s5e8825.json`,
  `flash_and_fuse.py`, and `loader/payload.c`.
- Local target scope and unlock findings: `audit/README.md` and
  `audit/notes/findings.md`.
