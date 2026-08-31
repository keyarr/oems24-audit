#!/usr/bin/env python3
"""
Targeted analysis of GUID references in VerifiedBootDxe and UFSDxe.
"""

from pathlib import Path
import struct
import capstone

ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = ROOT / "decompiled" / "dxe_modules"

def find_exact_guid_xrefs(pe_path: Path, guids: dict[str, bytes]):
    data = pe_path.read_bytes()
    print(f"\n=======================================================")
    print(f"EXACT GUID XREFS FOR {pe_path.name}")
    print(f"=======================================================")

    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_hdr_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    sec_hdr_start = e_lfanew + 24 + opt_hdr_size

    sections = []
    for i in range(num_sections):
        s_name, s_vsize, s_vaddr, s_rawsize, s_rawoff, _, _, _, _, s_flags = struct.unpack_from('<8sIIIIIIHHI', data, sec_hdr_start + i * 40)
        s_name_str = s_name.decode('latin1').rstrip('\x00')
        sections.append({
            "name": s_name_str,
            "vaddr": s_vaddr,
            "vsize": s_vsize,
            "rawoff": s_rawoff,
            "rawsize": s_rawsize
        })

    text_sec = next(s for s in sections if ".text" in s["name"])
    text_data = data[text_sec["rawoff"] : text_sec["rawoff"] + text_sec["rawsize"]]

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    # Build instructions list
    insns = list(md.disasm(text_data, text_sec["vaddr"]))

    for gname, gbytes in guids.items():
        g_pos = data.find(gbytes)
        if g_pos == -1:
            continue
        g_rva = 0
        for s in sections:
            if s["rawoff"] <= g_pos < s["rawoff"] + s["rawsize"]:
                g_rva = s["vaddr"] + (g_pos - s["rawoff"])
                break

        print(f"\nTarget GUID {gname}: RVA = 0x{g_rva:x} (offset 0x{g_pos:x})")

        # Track ADRP + ADD / LDR pairs
        for i, insn in enumerate(insns):
            if insn.mnemonic == 'adrp':
                page_str = insn.op_str.split(',')[-1].strip().lstrip('#')
                page = int(page_str, 16)
                reg = insn.op_str.split(',')[0].strip()
                if page == (g_rva & ~0xfff):
                    # check next few instructions for reference to reg with low 12 bits of g_rva
                    low12 = g_rva & 0xfff
                    # check next 4 insns
                    for j in range(i+1, min(len(insns), i+6)):
                        next_insn = insns[j]
                        if reg in next_insn.op_str and hex(low12) in next_insn.op_str:
                            print(f"\n[HIT] Exact reference to {gname} at 0x{next_insn.address:x}:")
                            # print context around next_insn
                            start_k = max(0, i - 4)
                            end_k = min(len(insns), j + 12)
                            for k in range(start_k, end_k):
                                marker = "=>" if k in (i, j) else "  "
                                print(f"  {marker} 0x{insns[k].address:08x}: {insns[k].mnemonic:<10s} {insns[k].op_str}")
                            break

def main():
    guids = {
        "EFI_MEM_CARDINFO_PROTOCOL": bytes.fromhex("d2f7c185e6bc314f8f4dd37e03d05eaa"),
        "SAMSUNG_VB_PROTOCOL": bytes.fromhex("91ff5e8eb621d347af2bc15a01e020ec"),
        "EFI_BLOCK_IO_PROTOCOL": bytes.fromhex("215b4e965964d2118e3900a0c969723b"),
    }
    find_exact_guid_xrefs(MODULES_DIR / "DXE_FV_MAIN_fd975fb5-92c3-40b3-b05c-9c434326ab64.efi", guids)
    find_exact_guid_xrefs(MODULES_DIR / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi", guids)

if __name__ == "__main__":
    main()
