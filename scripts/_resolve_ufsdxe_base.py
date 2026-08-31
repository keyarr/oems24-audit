import capstone
from capstone import CS_ARCH_ARM64, CS_MODE_ARM
import struct, sys

data = open('decompiled_extra/ufsdxe_efi_extracted.pe', 'rb').read()
md = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# We know strings live at file offset 0x1ba58 area. In a contiguous dump,
# code references them via adrp(imm) ; add(imm). adrp gives page of (addr),
# add gives page offset. The referenced absolute = base + string_rva.
# If the dump is contiguous with base B, then string absolute within dump = B + 0x1ba58.
# We try candidate bases B in a search: for each plausible B, decode whole blob,
# collect adrp/add pairs referencing addresses in [B+0x1b000, B+0x1d000], score.
# Simplest: assume B such that adrp target pages align. We scan each 4-byte for
# adrp (0x90000000 mask). Decode and gather referenced pages for add-combos.

def gather_refs(base):
    refs = []
    # decode in windows
    off = 0
    while off + 4 <= len(data):
        # capstone can disassemble the whole thing; but we want adrp+add chains
        for ins in md.disasm(data[off:off+0x2000], base + off):
            if ins.mnemonic == 'adrp':
                # operand like 'x0, #0x123000' -> absolute page
                try:
                    page = int(ins.op_str.split('#')[1].split()[0].rstrip(','), 16)
                except Exception:
                    continue
                # next instructions add? we just record candidate page; later if an 'add xN, xN, #imm' follows
                refs.append(page)
    return refs

# Instead of full decode (slow), take a targeted approach:
# collect every adrp page, see which page ranges are most common (likely .rodata/.text pages).
pages = {}
off = 0
for off in range(0, len(data)-4, 4):
    w = struct.unpack('<I', data[off:off+4])[0]
    if (w & 0x9F000000) == 0x90000000:
        # adrp: imm = immhi:immlo
        immhi = (w >> 5) & 0x7FFFF
        immlo = (w >> 29) & 0x3
        imm = (immhi << 2) | immlo
        imm = (imm << 12)
        if imm & (1 << 32-1):  # sign extend 33-bit? simpler ignore
            pass
        page = imm  # page value computed (low 12 bits zero)
        pages[page] = pages.get(page, 0) + 1

# most referenced pages
top = sorted(pages.items(), key=lambda kv: -kv[1])[:15]
print("top adrp pages:", [(hex(p), c) for p, c in top])
# If strings at 0x1ba58 -> absolute likely 0x1b000 page-ish.
# The dump may already be at file offsets == RVAs (base 0). Then adrp pages
# computed >= 0x1000. Check if any page in 0x1b000 range.
for p, c in top:
    if 0x1b000 <= p <= 0x1d000:
        print("HIT page near strings:", hex(p), "count", c)
