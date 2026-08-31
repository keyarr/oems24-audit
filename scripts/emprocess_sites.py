"""Locate every call site of emProcess / em_lite_entry / em_tlc_send in
libengmode_server.so and dump the argument setup immediately preceding it."""
import sys, re, struct
sys.path.insert(0, 'scripts')
from elftools_helpers import Bin
from pltmap import plt_map, func_bounds, enclosing
from server_analysis import annotate

B = Bin('binaries/libengmode_server.so')
PM = plt_map(B)
FNS = func_bounds(B)

TARGETS = {}
for va, nm in PM.items():
    if nm in ('emProcess', 'em_lite_entry', 'em_tlc_send') or 'emProcess' in nm:
        TARGETS[va] = nm
print('PLT stubs:', {hex(k): v for k, v in TARGETS.items()})

# invoke plt_map's own disasm loop; but plt_map only indexes .rela.plt names.
# emProcess is imported -> find its PLT stub by name lookup in rela.plt order
plt_sec = None
rela = None
for s in B.f.iter_sections():
    if s.name == '.plt':
        plt_sec = s.header
    if s.name == '.rela.plt':
        rela = s
stubs = {}
n = rela.header.sh_size // 24
symtab = B.f.get_section(rela.header.sh_link)
for i in range(n):
    o, info, add = struct.unpack_from('<QQq', B.data, rela.header.sh_offset + 24 * i)
    stubs[plt_sec.sh_addr + 0x18 + 8 + 0x18 * i] = symtab.get_symbol(info >> 32).name

WANT = {k: v for k, v in stubs.items() if 'emProcess' in v or 'em_lite_entry' in v or 'em_tlc_send' in v}
print('WANT stubs:', {hex(k): v for k, v in WANT.items()})

# scan .text for BL to those stubs
text = None
for s in B.f.iter_sections():
    if s.name == '.text':
        text = (s.header.sh_addr, s.header.sh_size)
o = B.v2o(text[0])
words = struct.unpack_from('<%dI' % (text[1] // 4), B.data, o)

sites = []
for i, w in enumerate(words):
    if (w >> 26) == 0b100101:  # BL
        imm = w & 0x3ffffff
        if imm & 0x2000000:
            imm -= 0x4000000
        tgt = text[0] + 4 * i + 4 * imm
        if tgt in WANT:
            sites.append((text[0] + 4 * i, tgt, WANT[tgt]))

print(f'\n=== {len(sites)} call sites ===')
for (at, tgt, nm) in sites:
    enc = enclosing(FNS, at)
    print(f'  {at:#08x}  bl {nm:<16}   inside {enc[2] if enc else "?"}')

print('\n\n### argument setup for each site (60 instructions before) ###')
seen = set()
for (at, tgt, nm) in sites:
    enc = enclosing(FNS, at)
    fn = enc[2] if enc else '?'
    key = (fn, at)
    if key in seen:
        continue
    seen.add(key)
    print()
    print('#' * 100)
    print(f'# CALL {nm} @ {at:#x}   in {fn}')
    print('#' * 100)
    start = max(enc[0] if enc else at - 0x100, at - 0xF0)
    annotate(B, start, at - start + 4, f'pre-call context for {nm} @ {at:#x} in {fn}')
