#!/usr/bin/env python3
"""用 pefile 正确解析 PE 关键字段，对比 Bandizip vs Notepad4"""
import sys
import os
import pefile


def diag(path):
    pe = pefile.PE(path)
    print(f"=== {os.path.basename(path)} ===")
    print(f"  ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
    print(f"  AddressOfEntryPoint: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
    print(f"  SizeOfImage: 0x{pe.OPTIONAL_HEADER.SizeOfImage:X}")
    dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
    print(f"  DllCharacteristics: 0x{dll_char:04X}")
    print(f"    DYNAMIC_BASE (ASLR):    {bool(dll_char & 0x40)}")
    print(f"    NX_COMPAT:              {bool(dll_char & 0x100)}")
    print(f"    GUARD_CF:               {bool(dll_char & 0x4000)}")
    print(f"    HIGH_ENTROPY_VA:        {bool(dll_char & 0x20)}")
    print(f"    TERMINAL_SERVER_AWARE:  {bool(dll_char & 0x8000)}")

    # DataDirectory
    print(f"\n  DataDirectory:")
    for i, name in enumerate([
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
        "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
        "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR"
    ]):
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
        if d.VirtualAddress or d.Size:
            print(f"    [{i:2d}] {name:14s} RVA=0x{d.VirtualAddress:08X} Size=0x{d.Size:X}")

    # TLS directory
    tls = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
    if tls.VirtualAddress:
        print(f"\n  TLS directory:")
        tls_dir = pe.DIRECTORY_ENTRY_TLS.struct
        print(f"    StartAddressOfRawData VA: 0x{tls_dir.StartAddressOfRawData:X}")
        print(f"    EndAddressOfRawData   VA: 0x{tls_dir.EndAddressOfRawData:X}")
        print(f"    AddressOfIndex        VA: 0x{tls_dir.AddressOfIndex:X}")
        print(f"    AddressOfCallBacks    VA: 0x{tls_dir.AddressOfCallBacks:X}")
        # 读 callbacks array
        cb_va = tls_dir.AddressOfCallBacks
        if cb_va:
            cb_rva = cb_va - pe.OPTIONAL_HEADER.ImageBase
            try:
                cb_data = pe.get_data(cb_rva, 64)
                import struct
                print(f"    Callbacks array @ RVA 0x{cb_rva:X}:")
                for i in range(8):
                    cb = struct.unpack_from('<Q', cb_data, i*8)[0]
                    if cb == 0:
                        print(f"      [{i}] NULL  (terminator)")
                        break
                    print(f"      [{i}] 0x{cb:X}")
            except Exception as e:
                print(f"    cannot read callbacks: {e}")

    # LoadConfig
    lc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[10]
    if lc.VirtualAddress:
        print(f"\n  LoadConfig:")
        lc_data = pe.get_data(lc.VirtualAddress, lc.Size)
        # x64 IMAGE_LOAD_CONFIG_DIRECTORY64 字段偏移：
        #   0x54: SecurityCookie (VA)
        #   0x6C: GuardCFCheckFunctionPointer (VA)
        #   0x74: GuardCFDispatchFunctionPointer (VA)
        #   0x7C: GuardCFFunctionTable (VA)
        #   0x84: GuardCFFunctionCount (8字节)
        #   0x8C: GuardFlags (4字节)
        import struct
        if lc.Size >= 0x90:
            cookie = struct.unpack_from('<Q', lc_data, 0x54)[0]
            cf_check = struct.unpack_from('<Q', lc_data, 0x6C)[0]
            cf_dispatch = struct.unpack_from('<Q', lc_data, 0x74)[0]
            cf_table = struct.unpack_from('<Q', lc_data, 0x7C)[0]
            cf_count = struct.unpack_from('<Q', lc_data, 0x84)[0]
            guard_flags = struct.unpack_from('<I', lc_data, 0x8C)[0]
            print(f"    Size: 0x{lc.Size:X}")
            print(f"    SecurityCookie VA:               0x{cookie:X}")
            print(f"    GuardCFCheckFunctionPointer VA:  0x{cf_check:X}")
            print(f"    GuardCFDispatchFunctionPointer:  0x{cf_dispatch:X}")
            print(f"    GuardCFFunctionTable VA:         0x{cf_table:X}")
            print(f"    GuardCFFunctionCount:            {cf_count}")
            print(f"    GuardFlags: 0x{guard_flags:08X}")
            f = guard_flags
            print(f"      CF_INSTRUMENTED:                    {bool(f & 0x01)}")
            print(f"      CFW_INSTRUMENTED:                   {bool(f & 0x02)}")
            print(f"      CF_FUNCTION_TABLE_PRESENT:         {bool(f & 0x04)}")
            print(f"      SECURITY_COOKIE_UNUSED:            {bool(f & 0x08)}")
            print(f"      PROTECT_INSTRUMENTED_FUNCTIONS:    {bool(f & 0x10)}")
            print(f"      DELAYLOAD_IAT_IN_ITS_OWN_SECTION:  {bool(f & 0x20)}")
            print(f"      CF_ENABLE_LONG_DISPATCH_TABLE:    {bool(f & 0x40)}")
            print(f"      CF_LONGJUMP_TABLE_PRESENT:         {bool(f & 0x80)}")
            print(f"      Stride (top 4 bits):               0x{(f >> 28) & 0xF:X}")
        # GuardCFFunctionTable 内容
        if cf_table and cf_count:
            stride = 4 << ((guard_flags >> 28) & 0xF)
            try:
                tbl_data = pe.get_data(cf_table - pe.OPTIONAL_HEADER.ImageBase,
                                       cf_count * stride)
                print(f"    First 10 GFIDS entries (stride={stride}):")
                for i in range(min(10, cf_count)):
                    rva = struct.unpack_from('<I', tbl_data, i*stride)[0]
                    print(f"      [{i}] RVA=0x{rva:X}")
            except Exception as e:
                print(f"    cannot read GFIDS: {e}")

    # .reloc 表：检查 TLS directory 各字段是否被 reloc
    reloc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    if reloc.VirtualAddress and tls.VirtualAddress:
        print(f"\n  .reloc table: RVA=0x{reloc.VirtualAddress:X} Size=0x{reloc.Size:X}")
        # 收集所有 reloc patch RVA
        reloc_rvas = {}
        reloc_dir = pe.DIRECTORY_ENTRY_BASERELOC
        for entry in reloc_dir:
            for ent in entry.entries:
                t = ent.type
                rva = ent.rva
                reloc_rvas[rva] = t
        # 检查 TLS directory 各字段
        tls_rva = tls.VirtualAddress
        for off, name in [(0x00, "StartAddressOfRawData"),
                          (0x08, "EndAddressOfRawData"),
                          (0x10, "AddressOfIndex"),
                          (0x18, "AddressOfCallBacks")]:
            rva = tls_rva + off
            if rva in reloc_rvas:
                print(f"    TLS+0x{off:02X} {name:24s} RVA=0x{rva:X}: COVERED type={reloc_rvas[rva]}")
            else:
                print(f"    TLS+0x{off:02X} {name:24s} RVA=0x{rva:X}: not covered")
        # 检查 LoadConfig 字段
        if lc.VirtualAddress:
            for off, name in [(0x54, "SecurityCookie"),
                              (0x6C, "GuardCFCheckFunctionPointer"),
                              (0x74, "GuardCFDispatchFunctionPointer"),
                              (0x7C, "GuardCFFunctionTable")]:
                rva = lc.VirtualAddress + off
                if rva in reloc_rvas:
                    print(f"    LC+0x{off:02X} {name:30s} RVA=0x{rva:X}: COVERED type={reloc_rvas[rva]}")
                else:
                    print(f"    LC+0x{off:02X} {name:30s} RVA=0x{rva:X}: not covered")

    pe.close()
    print()


if __name__ == "__main__":
    for p in sys.argv[1:]:
        if os.path.exists(p):
            try:
                diag(p)
            except Exception as e:
                print(f"ERROR for {p}: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"not found: {p}")
