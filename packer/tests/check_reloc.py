#!/usr/bin/env python3
"""检查指定 RVA 是否被 .reloc 表覆盖"""
import sys
import struct
import os

def check_reloc(path, target_rvas):
    with open(path, 'rb') as f:
        data = f.read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    oh_off = e_lfanew + 24
    n_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_hdr_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    image_base = struct.unpack_from('<Q', data, oh_off + 24)[0]
    sec_off = oh_off + opt_hdr_size
    sections = []
    for i in range(n_sec):
        so = sec_off + i * 40
        name = data[so:so+8].rstrip(b'\x00').decode('latin1')
        vsize, vaddr, raw_size, raw_off = struct.unpack_from('<IIII', data, so + 8)
        sections.append((name, vaddr, vsize, raw_off, raw_size))
    dd_off = oh_off + 112
    reloc_rva, reloc_size = struct.unpack_from('<II', data, dd_off + 5*8)
    tls_rva, tls_size = struct.unpack_from('<II', data, dd_off + 9*8)

    def rva_to_raw(rva):
        for name, vaddr, vsize, raw_off, raw_size in sections:
            if vaddr <= rva < vaddr + max(vsize, raw_size):
                return raw_off + (rva - vaddr)
        return None

    # 加上 TLS directory 各字段的 RVA
    target_set = set(target_rvas)
    if tls_rva and tls_size:
        # IMAGE_TLS_DIRECTORY64 字段 RVA：
        # 0x00 StartAddressOfRawData (8字节 VA, 需要 reloc)
        # 0x08 EndAddressOfRawData (8字节 VA, 需要 reloc)
        # 0x10 AddressOfIndex (8字节 VA, 需要 reloc)
        # 0x18 AddressOfCallBacks (8字节 VA, 需要 reloc)
        target_set.add(tls_rva + 0x00)
        target_set.add(tls_rva + 0x08)
        target_set.add(tls_rva + 0x10)
        target_set.add(tls_rva + 0x18)
        target_set.add(tls_rva + 0x20)

    print(f"=== {os.path.basename(path)} ===")
    print(f"  ImageBase=0x{image_base:X}")
    print(f"  TLS dir RVA=0x{tls_rva:X}")
    if tls_rva:
        print(f"    +0x00 StartAddressOfRawData  RVA=0x{tls_rva+0x00:X}")
        print(f"    +0x08 EndAddressOfRawData    RVA=0x{tls_rva+0x08:X}")
        print(f"    +0x10 AddressOfIndex         RVA=0x{tls_rva+0x10:X}")
        print(f"    +0x18 AddressOfCallBacks     RVA=0x{tls_rva+0x18:X}")
        print(f"    +0x20 SizeOfZeroFill+Char    RVA=0x{tls_rva+0x20:X}")
    print(f"  Reloc RVA=0x{reloc_rva:X} Size=0x{reloc_size:X}")
    print(f"  Target RVAs to check: {[hex(t) for t in sorted(target_set)]}")

    # 遍历 reloc 表，记录每个 patch_rva
    covered = {}  # patch_rva -> type
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
                    patch_rva = block_rva + (e & 0xFFF)
                    if patch_rva in target_set:
                        covered[patch_rva] = t
                off += block_size

    for t in sorted(target_set):
        if t in covered:
            print(f"  RVA 0x{t:X}: COVERED (type={covered[t]})")
        else:
            print(f"  RVA 0x{t:X}: NOT COVERED by .reloc!")

if __name__ == "__main__":
    path = sys.argv[1]
    targets = [int(x, 16) for x in sys.argv[2:]]
    check_reloc(path, targets)
