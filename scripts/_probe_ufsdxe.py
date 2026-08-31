import struct, re, sys

d = open('decompiled_extra/ufsdxe_efi_extracted.pe', 'rb').read()
print("size", len(d))
print("magic", d[:4].hex(), d[:4])
if d[:2] == b'VZ':
    (sig, mach, subsys, mmode, imgtype, nsects, shdr, tstamp, entry, base, imgbase, code_base, rsvd) = \
        struct.unpack('<HHHHHIHIIQQII', d[:36])
    print("TE: mach", hex(mach), "nsects", nsects, "entry", hex(entry), "imgbase", hex(imgbase))
elif d[:2] == b'MZ':
    e_lfanew = struct.unpack('<I', d[0x3c:0x40])[0]
    print("PE at", hex(e_lfanew), d[e_lfanew:e_lfanew+4])
    (magic,) = struct.unpack('<H', d[e_lfanew+24:e_lfanew+26])
    print("opt magic", hex(magic))
else:
    print("no MZ/TE magic; raw image. first bytes:", d[:16].hex())

seen = set()
for m in re.finditer(rb'[ -~]{5,}', d):
    s = m.group()
    low = s.lower()
    if any(k in low for k in (b'ufs', b'memcard', b'block', b'qcompkg', b'descriptor',
                              b'rpmb', b'query', b'geom', b'lun', b'unitdesc', b'scsi')):
        key = s[:40]
        if key in seen:
            continue
        seen.add(key)
        print(hex(m.start()), s[:60])
