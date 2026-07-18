#!/usr/bin/env python3
"""正确读取 IMAGE_LOAD_CONFIG_DIRECTORY64 各 VA 字段"""
import sys
import struct
import os

def dump_load_config(path):
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
    reloc_rva, reloc_size = struct.unpack_from('<II', data, dd_off + 5*8)
    tls_rva, tls_size = struct.unpack_from('<II', data, dd_off + 9*8)

    def rva_to_raw(rva):
        for name, vaddr, vsize, raw_off, raw_size in sections:
            if vaddr <= rva < vaddr + max(vsize, raw_size):
                return raw_off + (rva - vaddr)
        return None

    # 遍历 reloc 表，记录每个 patch_rva
    reloc_set = set()
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
                    if e >> 12 == 0:
                        continue
                    patch_rva = block_rva + (e & 0xFFF)
                    reloc_set.add(patch_rva)
                off += block_size

    print(f"=== {os.path.basename(path)} LoadConfig ===")
    print(f"  ImageBase=0x{image_base:X}, LC RVA=0x{lc_rva:X} Size=0x{lc_size:X}")
    if lc_rva and lc_size:
        lc_raw = rva_to_raw(lc_rva)
        if lc_raw is not None:
            # IMAGE_LOAD_CONFIG_DIRECTORY64 (PE32+)
            # 主要 VA 字段（用 Q 读出后看是否落在 image 范围）
            # 字段: 偏移(类型) - 名称
            # 0x00 (DWORD) Size
            # 0x18 (ULONGLONG) LockPrefixTable - VA
            # 0x30 (ULONGLONG) EditList - VA
            # 0x38 (ULONGLONG) SecurityCookie - VA
            # 0x40 (ULONGLONG) SEHandlerTable - VA
            # 0x48 (ULONGLONG) SEHandlerCount
            # 0x50 (ULONGLONG) GuardCFCheckFunctionPointer - VA
            # 0x58 (ULONGLONG) GuardCFDispatchFunctionPointer - VA
            # 0x60 (ULONGLONG) GuardCFFunctionTable - VA
            # 0x68 (ULONGLONG) GuardCFFunctionCount
            # 0x70 (DWORD) GuardFlags
            # 0x78 (ULONGLONG) GuardAddressTakenIatEntryTable - VA
            # 0x80 (ULONGLONG) GuardAddressTakenIatEntryCount
            # 0x88 (ULONGLONG) GuardLongJumpTargetTable - VA
            # 0x90 (ULONGLONG) GuardLongJumpTargetCount
            va_fields = [
                (0x18, "LockPrefixTable"),
                (0x30, "EditList"),
                (0x38, "SecurityCookie"),
                (0x40, "SEHandlerTable"),
                (0x48, "SEHandlerCount"),
                (0x50, "GuardCFCheckFunctionPointer"),
                (0x58, "GuardCFDispatchFunctionPointer"),
                (0x60, "GuardCFFunctionTable"),
                (0x68, "GuardCFFunctionCount"),
                (0x70, "GuardFlags (DWORD)"),
                (0x78, "GuardAddressTakenIatEntryTable"),
                (0x80, "GuardAddressTakenIatEntryCount"),
                (0x88, "GuardLongJumpTargetTable"),
                (0x90, "GuardLongJumpTargetCount"),
            ]
            for off, name in va_fields:
                if off + 8 > lc_size:
                    continue
                val = struct.unpack_from('<Q', data, lc_raw + off)[0]
                # 计算这个字段在文件中的 RVA（即 lc_rva + off）
                field_rva = lc_rva + off
                covered = "RELOC" if field_rva in reloc_set else "no-reloc"
                if val == 0:
                    print(f"  +0x{off:02X} {name:40s} = 0 (null)")
                else:
                    # 判断是否像 VA
                    if val >= image_base and val < image_base + 0x10000000:
                        rva = val - image_base
                        print(f"  +0x{off:02X} {name:40s} = VA 0x{val:X} (RVA 0x{rva:X}) [{covered}]")
                    else:
                        print(f"  +0x{off:02X} {name:40s} = 0x{val:X} [{covered}]")

if __name__ == "__main__":
    for p in sys.argv[1:]:
        if os.path.exists(p):
            dump_load_config(p)
        else:
            print(f"not found: {p}")
