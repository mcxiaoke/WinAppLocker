#!/usr/bin/env python3
"""检查 PE 的 DataDirectory 各项是否有内容，重点关注 DelayLoadImportTable"""
import sys
import struct
import os

DATA_DIR_NAMES = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
    "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
    "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR"
]

def dump(path):
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
    print(f"=== {os.path.basename(path)} DataDirectory ===")
    for i, name in enumerate(DATA_DIR_NAMES):
        rva, size = struct.unpack_from('<II', data, dd_off + i*8)
        if rva or size:
            # 找到所在节
            sec_name = "?"
            for sn, sv, svz, sro, srs in sections:
                if sv <= rva < sv + max(svz, srs):
                    sec_name = sn
                    break
            print(f"  [{i:2d}] {name:15s} RVA=0x{rva:08X} Size=0x{size:X} (in {sec_name})")
    # Dump delay import descriptor (32 bytes each)
    di_rva, di_size = struct.unpack_from('<II', data, dd_off + 13*8)
    if di_rva and di_size:
        print(f"\n  DelayLoad Import descriptors (each 32 bytes):")
        # find raw
        for sn, sv, svz, sro, srs in sections:
            if sv <= di_rva < sv + max(svz, srs):
                raw = sro + (di_rva - sv)
                # 每 32 字节一个 ImgDelayDescr
                # 字段：Attributes(4) DllNameRVA(4) ModuleHandleRVA(4) ImportAddressTableRVA(4) ImportNamesRVA(4) BoundImportAddressTableRVA(4) UnloadInformationTableRVA(4) TimeDateStamp(4)
                off = raw
                idx = 0
                while off + 32 <= len(data):
                    attrs, dll_rva, modh_rva, iat_rva, iname_rva, biat_rva, uit_rva, ts = struct.unpack_from('<IIIIIIII', data, off)
                    if attrs == 0 and dll_rva == 0:
                        break
                    # 旧式用 RVA，新式用 VA（取决于 Attributes bit 1）
                    is_va = bool(attrs & 1)
                    print(f"    [{idx}] attrs=0x{attrs:X} (VA={is_va})")
                    print(f"        DllName {'VA' if is_va else 'RVA'}=0x{dll_rva:X}")
                    print(f"        ModuleHandle {'VA' if is_va else 'RVA'}=0x{modh_rva:X}")
                    print(f"        IAT {'VA' if is_va else 'RVA'}=0x{iat_rva:X}")
                    print(f"        ImportNames {'VA' if is_va else 'RVA'}=0x{iname_rva:X}")
                    print(f"        BoundIAT {'VA' if is_va else 'RVA'}=0x{biat_rva:X}")
                    print(f"        UnloadInfo {'VA' if is_va else 'RVA'}=0x{uit_rva:X}")
                    print(f"        TimeDateStamp=0x{ts:X}")
                    # 尝试读 dll 名
                    try:
                        if is_va:
                            target = dll_rva - image_base
                        else:
                            target = dll_rva
                        for sn2, sv2, svz2, sro2, srs2 in sections:
                            if sv2 <= target < sv2 + max(svz2, srs2):
                                dn_raw = sro2 + (target - sv2)
                                dn = data[dn_raw:dn_raw+64].split(b'\x00')[0].decode('latin1', errors='replace')
                                print(f"        DllName str: '{dn}'")
                                break
                    except Exception as e:
                        print(f"        (failed to read name: {e})")
                    off += 32
                    idx += 1

if __name__ == "__main__":
    for p in sys.argv[1:]:
        if os.path.exists(p):
            dump(p)
