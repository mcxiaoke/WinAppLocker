#!/usr/bin/env python3
"""
extract_lock_section.py - 从 PE 文件提取所有 .lock 节并按 RVA 顺序输出

替代 objcopy -O binary -j .lock，解决 MSVC link.exe 不合并不同特性的 .lock$X
子节导致 objcopy 输出包含中间 padding 的问题。

行为：
  1. 解析 PE 文件，找到所有名为 ".lock" 的节（按 VA 升序）
  2. 计算每节在 bin 中的偏移 = (节 RVA - 第一个 .lock 节 RVA)
     节间填充 0 字节匹配 PE 内存 RVA 布局
  3. 输出到指定 bin 文件

为什么按 RVA 偏移填充：
  MSVC link.exe 把不同特性的 .lock$X 子节分到多个独立的 .lock 节，
  每节有独立的 RVA（跳跃很大，如 0x1000/0x6000/0x7000）。
  stub_entry 中的 RIP-relative 引用是基于 PE RVA 计算的，
  必须保持 bin 中的偏移与 PE RVA 偏移一致，否则跨节引用会错位崩溃。

  GCC stub.ld 用 SUBALIGN(16) 把所有 .lock.* 合并到一个连续节，
  bin 中偏移天然等于 PE RVA 偏移，不存在此问题。

  MSVC bin 体积会膨胀（约 25KB vs GCC 5KB），但功能正确性优先。

用法：
  python extract_lock_section.py <input.exe> <output.bin>
"""
import struct
import sys
import pathlib


def extract_lock_sections(pe_path: str, out_path: str) -> int:
    """提取 PE 文件中所有 .lock 节，按 RVA 偏移布局输出。
    返回输出字节数。"""
    data = pathlib.Path(pe_path).read_bytes()

    # DOS 头：e_lfanew 在偏移 0x3C
    if data[:2] != b"MZ":
        raise ValueError(f"not a PE file: {pe_path}")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    # PE 头：Signature + COFF Header
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError(f"invalid PE signature at 0x{e_lfanew:x}")

    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    opt_hdr_size = struct.unpack_from("<H", data, coff_off + 16)[0]
    sec_table_off = coff_off + 20 + opt_hdr_size

    # IMAGE_SECTION_HEADER 结构（40 字节）：
    #   Name[8]              +0x00
    #   VirtualSize          +0x08
    #   VirtualAddress       +0x0C
    #   SizeOfRawData        +0x10
    #   PointerToRawData     +0x14
    sections = []
    for i in range(num_sections):
        off = sec_table_off + i * 40
        name_bytes = data[off:off + 8]
        # 节名以 null 结尾，最长 8 字符
        name = name_bytes.split(b"\0", 1)[0].decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", data, off + 8)[0]
        vaddr = struct.unpack_from("<I", data, off + 12)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        sections.append({
            "name": name,
            "vsize": vsize,
            "vaddr": vaddr,
            "raw_size": raw_size,
            "raw_ptr": raw_ptr,
        })

    # 找所有名为 .lock 的节，按 VA 升序
    lock_secs = sorted(
        [s for s in sections if s["name"] == ".lock"],
        key=lambda s: s["vaddr"],
    )

    if not lock_secs:
        raise ValueError(f"no .lock section in {pe_path}")

    # 基准 RVA（第一个 .lock 节）
    base_rva = lock_secs[0]["vaddr"]
    # bin 总大小 = 最后一节 RVA + vsize - 第一节 RVA
    last = lock_secs[-1]
    bin_size = (last["vaddr"] + last["vsize"]) - base_rva

    # 创建全 0 缓冲区，节间空白处保持 0
    out = bytearray(bin_size)

    # 把每节 raw data 写入对应偏移（offset_in_bin = RVA - base_rva）
    # 实际有效数据大小用 min(vsize, raw_size)，避免末尾 raw padding
    for s in lock_secs:
        offset_in_bin = s["vaddr"] - base_rva
        size = min(s["vsize"], s["raw_size"])
        if s["raw_ptr"] + size > len(data):
            raise ValueError(
                f"section .lock@{s['vaddr']:#x} raw range out of file"
            )
        out[offset_in_bin:offset_in_bin + size] = \
            data[s["raw_ptr"]:s["raw_ptr"] + size]
        print(
            f"  .lock VA=0x{s['vaddr']:08X} vsize=0x{s['vsize']:X} "
            f"raw=0x{s['raw_size']:X} -> bin[0x{offset_in_bin:X}:0x{offset_in_bin + size:X}] "
            f"({size} bytes)",
            file=sys.stderr,
        )

    # 末尾补齐到 16 字节对齐（便于后续对齐扫描）
    tail_pad = (16 - len(out) % 16) % 16
    if tail_pad:
        out.extend(b"\0" * tail_pad)

    pathlib.Path(out_path).write_bytes(bytes(out))
    return len(out)


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <input.exe> <output.bin>",
              file=sys.stderr)
        return 2
    total = extract_lock_sections(sys.argv[1], sys.argv[2])
    print(f"extracted {total} bytes -> {sys.argv[2]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
