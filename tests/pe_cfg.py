#!/usr/bin/env python3
"""读取 LoadConfig 的 GuardFlags (DWORD at offset 0x70) 和相关字段"""
import sys
import struct
import os

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
    lc_rva, lc_size = struct.unpack_from('<II', data, dd_off + 10*8)
    def rva_to_raw(rva):
        for name, vaddr, vsize, raw_off, raw_size in sections:
            if vaddr <= rva < vaddr + max(vsize, raw_size):
                return raw_off + (rva - vaddr)
        return None
    print(f"=== {os.path.basename(path)} ===")
    if not (lc_rva and lc_size):
        print("  no LoadConfig")
        return
    lc_raw = rva_to_raw(lc_rva)
    # GuardFlags at offset 0x70 (DWORD)
    guard_flags = struct.unpack_from('<I', data, lc_raw + 0x70)[0]
    # GuardCFFunctionTable at offset 0x60 (ULONGLONG, VA in x64)
    cf_table_va = struct.unpack_from('<Q', data, lc_raw + 0x60)[0]
    cf_count = struct.unpack_from('<Q', data, lc_raw + 0x68)[0]
    # GuardCFCheckFunctionPointer at offset 0x50 (ULONGLONG, VA)
    cf_check_va = struct.unpack_from('<Q', data, lc_raw + 0x50)[0]
    # GuardCFDispatchFunctionPointer at offset 0x58 (ULONGLONG, VA)
    cf_dispatch_va = struct.unpack_from('<Q', data, lc_raw + 0x58)[0]
    # SecurityCookie at offset 0x38
    cookie_va = struct.unpack_from('<Q', data, lc_raw + 0x38)[0]
    print(f"  LoadConfig RVA=0x{lc_rva:X} Size=0x{lc_size:X}")
    print(f"  GuardFlags=0x{guard_flags:08X}")
    # GuardFlags 位定义：
    f = guard_flags
    print(f"    CF_INSTRUMENTED                    = {bool(f & 0x01)}")
    print(f"    CFW_INSTRUMENTED                   = {bool(f & 0x02)}")
    print(f"    CF_FUNCTION_TABLE_PRESENT         = {bool(f & 0x04)}")  # 0x04 实际值
    print(f"    SECURITY_COOKIE_UNUSED            = {bool(f & 0x08)}")
    print(f"    PROTECT_INSTRUMENTED_FUNCTIONS    = {bool(f & 0x10)}")
    print(f"    DELAYLOAD_IAT_IN_ITS_OWN_SECTION  = {bool(f & 0x20)}")
    print(f"    CF_ENABLE_LONG_DISPATCH_TABLE     = {bool(f & 0x40)}")
    print(f"    CF_LONG_DISPATCH_TABLE_PRESENT    = {bool(f & 0x80)}")
    print(f"    HIGH bit (size mask)              = 0x{(f >> 28) & 0xF:X}")
    print(f"  SecurityCookie VA=0x{cookie_va:X}")
    print(f"  GuardCFCheckFunctionPointer VA=0x{cf_check_va:X}")
    print(f"  GuardCFDispatchFunctionPointer VA=0x{cf_dispatch_va:X}")
    print(f"  GuardCFFunctionTable VA=0x{cf_table_va:X}")
    print(f"  GuardCFFunctionCount = {cf_count}")

if __name__ == "__main__":
    for p in sys.argv[1:]:
        if os.path.exists(p):
            dump(p)
