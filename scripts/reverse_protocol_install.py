#!/usr/bin/env python3
"""
Reverse engineer the protocol installation logic in UFSDxe, VerifiedBootDxe, and SdccDxe.
"""

from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = ROOT / "decompiled" / "dxe_modules"

def disassemble_around(data: bytes, file_offset: int, size: int = 128):
    # Using python-capstone or simple hexdump/analysis if available
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        chunk = data[file_offset : file_offset + size]
        for insn in md.disasm(chunk, file_offset):
            print(f"  0x{insn.address:08x}: {insn.mnemonic:<10s} {insn.op_str}")
    except ImportError:
        print(f"  Hexdump at 0x{file_offset:x}: {data[file_offset:file_offset+size].hex()}")

def analyze_install_protocol(pe_path: Path, name: str):
    print(f"\n=======================================================")
    print(f"Disassembling cross-references for {name}")
    print(f"=======================================================")
    data = pe_path.read_bytes()

    # Search for references to GUIDs
    GUIDS = {
        "EFI_MEM_CARDINFO_PROTOCOL": bytes.fromhex("d2f7c185e6bc314f8f4dd37e03d05eaa"),
        "SAMSUNG_VB_PROTOCOL": bytes.fromhex("91ff5e8eb621d347af2bc15a01e020ec"),
        "EFI_BLOCK_IO_PROTOCOL": bytes.fromhex("215b4e965964d2118e3900a0c969723b"),
    }

    # Find Section Headers in PE
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
        print(f"  Section {s_name_str:<8s}: vaddr=0x{s_vaddr:x}, vsize=0x{s_vsize:x}, rawoff=0x{s_rawoff:x}")

    for gname, gbytes in GUIDS.items():
        g_pos = data.find(gbytes)
        if g_pos != -1:
            g_rva = 0
            for s in sections:
                if s["rawoff"] <= g_pos < s["rawoff"] + s["rawsize"]:
                    g_rva = s["vaddr"] + (g_pos - s["rawoff"])
                    break
            print(f"\n{gname} found at file offset 0x{g_pos:x}, RVA=0x{g_rva:x}")

            # Search in text section for ADRP / LDR referencing this RVA
            # In AArch64 ADRP calculates page difference
            text_sec = next((s for s in sections if ".text" in s["name"]), sections[0])
            text_data = data[text_sec["rawoff"] : text_sec["rawoff"] + text_sec["rawsize"]]

            # disassemble entire text section with capstone and look for references
            try:
                import capstone
                md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                md.detail = True

                # Check instructions referencing g_rva page or g_rva
                print(f"Searching xrefs in {text_sec['name']} (0x{text_sec['vaddr']:x}..0x{text_sec['vaddr']+text_sec['vsize']:x})...")
                xref_count = 0
                for insn in md.disasm(text_data, text_sec["vaddr"]):
                    # If adrp
                    if insn.mnemonic == 'adrp':
                        page_str = insn.op_str.split(',')[-1].strip().lstrip('#')
                        page = int(page_str, 16)
                        if page == (g_rva & ~0xfff):
                            print(f"  XREF ADRP at 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                            # show next 15 instructions
                            disassemble_around(data, text_sec["rawoff"] + (insn.address - text_sec["vaddr"]), 64)
                            xref_count += 1
                if xref_count == 0:
                    print("  No direct ADRP xref found.")
            except ImportError:
                print("Capstone not available for detailed xref analysis.")

def main():
    analyze_install_protocol(MODULES_DIR / "DXE_FV_MAIN_0d35cd8e-97ea-4f9a-96af-0f0d89f76567.efi", "UFSDxe")
    analyze_install_protocol(MODULES_DIR / "DXE_FV_MAIN_fd975fb5-92c3-40b3-b05c-9c434326ab64.efi", "VerifiedBootDxe")

if __name__ == "__main__":
    main()
