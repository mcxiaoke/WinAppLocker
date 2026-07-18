#!/usr/bin/env python3
"""快速对比 PE 文件的关键特性：CFG / ASLR / TLS / 重定位类型分布"""
import sys
import struct
import os

def parse_pe(path):
    with open(path, 'rb') as f:
        data = f.read()
    dos = struct.unpack_from('<H', data, 0)[0]
    assert dos == 0x5A4D, f"not MZ: {path}"
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    sig = struct.unpack_from('<I', data, e_lfanew)[0]
    assert sig == 0x4550, f"not PE: {path}"
    machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
    n_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    # Optional header
    oh_off = e_lfanew + 24
    magic = struct.unpack_from('<H', data, oh_off)[0]
    assert magic == 0x20b, f"not PE32+: {path}"
    image_base = struct.unpack_from('<Q', data, oh_off + 24)[0]
    size_of_image = struct.unpack_from('<I', data, oh_off + 56)[0]
    ep_rva = struct.unpack_from('<I', data, oh_off + 16)[0]
    dll_char = struct.unpack_from('<H', data, oh_off + 70)[0]
    # DataDirectory starts at oh_off + 112 (PE32+)
    dd_off = oh_off + 112
    # DataDirectory[5] = BaseReloc
    reloc_rva, reloc_size = struct.unpack_from('<II', data, dd_off + 5*8)
    # DataDirectory[9] = TLS
    tls_rva, tls_size = struct.unpack_from('<II', data, dd_off + 9*8)
    # DataDirectory[10] = LoadConfig (for CFG)
    lc_rva, lc_size = struct.unpack_from('<II', data, dd_off + 10*8)

    # Section table
    sec_off = oh_off + struct.unpack_from('<H', data, e_lfanew + 20)[0]
    sections = []
    for i in range(n_sec):
        so = sec_off + i * 40
        name = data[so:so+8].rstrip(b'\x00').decode('latin1')
        vsize, vaddr, raw_size, raw_off = struct.unpack_from('<IIII', data, so + 8)
        char = struct.unpack_from('<I', data, so + 36)[0]
        sections.append((name, vaddr, vsize, raw_off, raw_size, char))

    def rva_to_raw(rva):
        for name, vaddr, vsize, raw_off, raw_size, _ in sections:
            if vaddr <= rva < vaddr + max(vsize, raw_size):
                return raw_off + (rva - vaddr)
        return None

    # CFG: read LoadConfig
    cfg_flags = None
    guard_cf_func_table_rva = None
    guard_cf_func_table_count = None
    if lc_rva and lc_size:
        lc_raw = rva_to_raw(lc_rva)
        if lc_raw is not None:
            guard_flags = struct.unpack_from('<I', data, lc_raw + 0x100)[0]  # offset 0x100 = GuardFlags
            cfg_flags = guard_flags
            # GuardCFFunctionTable (RVA) at offset 0x108, count at 0x110
            cf_table_rva, cf_table_count = struct.unpack_from('<II', data, lc_raw + 0x108)
            # cf_table_count is in bytes, count = bytes / 8 (each entry is RVA + 1 byte flags, padded to 8)
            guard_cf_func_table_rva = cf_table_rva
            guard_cf_func_table_count = cf_table_count

    # Parse reloc table to count type distribution
    reloc_counts = {0: 0, 1: 0, 2: 0, 3: 0, 10: 0, 'other': 0}
    reloc_text_count = 0  # 在 .text 范围内的 reloc 数
    text_range = None
    for name, vaddr, vsize, raw_off, raw_size, char in sections:
        if char & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            text_range = (vaddr, vaddr + vsize)
            break
    if not text_range:
        for name, vaddr, vsize, raw_off, raw_size, _ in sections:
            if name == '.text':
                text_range = (vaddr, vaddr + vsize)
                break

    if reloc_rva and reloc_size:
        r_raw = rva_to_raw(reloc_rva)
        if r_raw is not None:
            off = r_raw
            end = r_raw + reloc_size
            while off < end:
                block_rva, block_size = struct.unpack_from('<II', data, off)
                if block_size == 0 or block_size < 8:
                    break
                n_entries = (block_size - 8) // 2
                for i in range(n_entries):
                    e = struct.unpack_from('<H', data, off + 8 + i*2)[0]
                    t = e >> 12
                    if t in reloc_counts:
                        reloc_counts[t] += 1
                    else:
                        reloc_counts['other'] += 1
                    # 检查是否在 .text 范围
                    if text_range:
                        patch_rva = block_rva + (e & 0xFFF)
                        if text_range[0] <= patch_rva < text_range[1]:
                            reloc_text_count += 1
                off += block_size

    print(f"=== {os.path.basename(path)} ===")
    print(f"  Machine=0x{machine:04X}, Sections={n_sec}, ImageBase=0x{image_base:X}, SizeOfImage=0x{size_of_image:X}")
    print(f"  EP RVA=0x{ep_rva:X}, DllCharacteristics=0x{dll_char:04X}")
    print(f"  ASLR={'YES' if dll_char & 0x40 else 'no'}, HIGH_ENTROPY={'YES' if dll_char & 0x20 else 'no'}")
    print(f"  NO_SEH={'YES' if dll_char & 0x4000 else 'no'}, NX={'YES' if dll_char & 0x100 else 'no'}")
    if text_range:
        print(f"  .text range: RVA [0x{text_range[0]:X}, 0x{text_range[1]:X})")
    print(f"  TLS: RVA=0x{tls_rva:X} Size=0x{tls_size:X}")
    print(f"  LoadConfig: RVA=0x{lc_rva:X} Size=0x{lc_size:X}")
    if cfg_flags is not None:
        # GuardFlags: bit 0 = CF_FUNCTION_TABLE_PRESENT
        print(f"  CFG GuardFlags=0x{cfg_flags:08X} (CF_INSTRUMENTED={'Y' if cfg_flags & 1 else 'N'}, "
              f"TABLE_PRESENT={'Y' if cfg_flags & 0x1000 else 'N'})")
        if guard_cf_func_table_rva:
            print(f"  CFG FunctionTable: RVA=0x{guard_cf_func_table_rva:X}, size={guard_cf_func_table_count} bytes")
    else:
        print(f"  CFG: no LoadConfig")
    print(f"  Reloc: RVA=0x{reloc_rva:X} Size=0x{reloc_size:X}")
    print(f"  Reloc type distribution: {reloc_counts}")
    if text_range:
        print(f"  Reloc entries in .text range: {reloc_text_count}")
    print()

if __name__ == "__main__":
    for p in sys.argv[1:]:
        if os.path.exists(p):
            parse_pe(p)
        else:
            print(f"not found: {p}")
