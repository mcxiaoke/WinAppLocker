#!/usr/bin/env python3
"""详细 dump PE 的关键数据结构：TLS directory, LoadConfig, 重定位首块"""
import sys
import struct
import os

def dump_pe(path):
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
    def rva_to_raw(rva):
        for name, vaddr, vsize, raw_off, raw_size in sections:
            if vaddr <= rva < vaddr + max(vsize, raw_size):
                return raw_off + (rva - vaddr)
        return None
    # TLS
    tls_rva, tls_size = struct.unpack_from('<II', data, dd_off + 9*8)
    print(f"=== {os.path.basename(path)} TLS ===")
    print(f"  TLS dir RVA=0x{tls_rva:X} Size=0x{tls_size:X}")
    if tls_rva and tls_size:
        tls_raw = rva_to_raw(tls_rva)
        if tls_raw is not None:
            # IMAGE_TLS_DIRECTORY64 (x64):
            #   StartAddressOfRawData (8) - VA
            #   EndAddressOfRawData (8) - VA
            #   AddressOfIndex (8) - VA
            #   AddressOfCallBacks (8) - VA
            #   SizeOfZeroFill (4)
            #   Characteristics (4)
            start_va, end_va, idx_va, cb_va = struct.unpack_from('<QQQQ', data, tls_raw)
            print(f"  StartAddressOfRawData VA=0x{start_va:X}")
            print(f"  EndAddressOfRawData   VA=0x{end_va:X}")
            print(f"  AddressOfIndex        VA=0x{idx_va:X}")
            print(f"  AddressOfCallBacks    VA=0x{cb_va:X}")
            if cb_va:
                cb_rva = cb_va - image_base
                cb_raw = rva_to_raw(cb_rva)
                if cb_raw is not None:
                    print(f"  Callbacks array at file off 0x{cb_raw:X}:")
                    for i in range(8):
                        cb = struct.unpack_from('<Q', data, cb_raw + i*8)[0]
                        print(f"    [{i}] 0x{cb:X}")
                        if cb == 0:
                            break
            else:
                print(f"  AddressOfCallBacks is NULL (no callbacks)")
    # LoadConfig
    print(f"\n=== LoadConfig ===")
    lc_rva, lc_size = struct.unpack_from('<II', data, dd_off + 10*8)
    if lc_rva and lc_size:
        lc_raw = rva_to_raw(lc_rva)
        if lc_raw is not None:
            guard_flags = struct.unpack_from('<I', data, lc_raw + 0x100)[0]
            cookie_rva = struct.unpack_from('<I', data, lc_raw + 0x58)[0]  # SecurityCookie
            print(f"  LoadConfig RVA=0x{lc_rva:X} Size=0x{lc_size:X}")
            print(f"  GuardFlags=0x{guard_flags:08X}")
            print(f"  SecurityCookie (RVA in LC field)=0x{cookie_rva:X}")
            cf_table_rva, cf_table_count_bytes = struct.unpack_from('<II', data, lc_raw + 0x108)
            print(f"  GuardCFFunctionTable: RVA=0x{cf_table_rva:X}, size_in_bytes={cf_table_count_bytes}")
            # 前 10 个条目
            cf_raw = rva_to_raw(cf_table_rva)
            if cf_raw is not None:
                print(f"  First 10 entries:")
                for i in range(10):
                    # 每个条目 8 字节 (4 字节 RVA + 1 字节 flags + 3 字节 padding)
                    rva, flags = struct.unpack_from('<IB', data, cf_raw + i*8)
                    print(f"    [{i}] RVA=0x{rva:X} flags=0x{flags:02X}")

if __name__ == "__main__":
    for p in sys.argv[1:]:
        if os.path.exists(p):
            dump_pe(p)
        else:
            print(f"not found: {p}")
