#!/usr/bin/env python3
"""inspect_stub.py - 读 stub.bin 或加壳产物 exe 的 stub 身份信息

用法：
  python inspect_stub.py <stub.bin>                       # 读 stub.bin
  python inspect_stub.py <packed.exe>                     # 读加壳产物（自动找 .text2 节）
  python inspect_stub.py <input> --format=json            # 输出 JSON（manifest 生成用）
  python inspect_stub.py --summary <dir> [--winlock-root] # 批量打印目录下所有 stub.bin

功能（审查 A1 + A4 + A13）：
  - 读 stub.bin → 按 magic 搜索 stub_data_t，打印 identity
  - 读加壳产物 exe → 解析 PE 节表找 .text2 节，解析 stub_data_t，打印 identity
  - 支持 --format=json 输出结构化数据（manifest 生成用）
  - --winlock-root 未传时从脚本位置自动推断（cmake/ 上溯到 packer/）

为什么合并 inspect_stub_bin.py 和 inspect_stub.py：
  两个工具都是"读 stub_data_t 身份字段并打印"，差别只在输入类型。
  合并后少维护一个工具，且共享 patch_stub_identity.py 的常量和函数。
"""
import sys
import os
import struct
import argparse
import json

# 复用 patch_stub_identity.py 的常量和函数（两个脚本同目录）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from patch_stub_identity import (
    STUB_DATA_MAGIC, IDENTITY_FMT, IDENTITY_SIZE, CHECKSUM_SIZE,
    parse_config_h, find_stub_data,
)


def read_identity(data, offset, stub_data_size):
    """从 stub_data_t 结构里读 stub_identity_t 字段
    offset: stub_data_t 在 data 中的起始偏移
    stub_data_size: sizeof(stub_data_t)
    返回 dict（字段名 -> 值），字段名与 config.h stub_identity_t 一致"""
    identity_off = offset + stub_data_size - CHECKSUM_SIZE - IDENTITY_SIZE
    fields = struct.unpack_from(IDENTITY_FMT, data, identity_off)
    return {
        "stub_arch": fields[0],
        "stub_toolchain": fields[1],
        "stub_bin_ver": fields[2],
        "stub_build_time": fields[3],
        "stub_source_crc": fields[4],
        "stub_size": fields[5],
        # githash 是 8 字节 ASCII，去尾部 \0 后 decode
        "stub_githash": fields[6].rstrip(b"\0").decode("ascii", "replace"),
    }


def format_identity(id_dict):
    """格式化 identity 字典为可读字符串"""
    arch = "x64" if id_dict["stub_arch"] == 2 else "x86"
    toolchain = "MSVC" if id_dict["stub_toolchain"] == 1 else "MinGW"
    githash = id_dict["stub_githash"] if id_dict["stub_githash"] else "(none)"
    return (f"arch={arch} toolchain={toolchain} "
            f"bin_ver=0x{id_dict['stub_bin_ver']:04x} "
            f"build_time={id_dict['stub_build_time']} "
            f"source_crc=0x{id_dict['stub_source_crc']:08x} "
            f"stub_size={id_dict['stub_size']} githash={githash}")


# ---- PE 节表解析（packed.exe 模式用）----

# IMAGE_DOS_HEADER 关键字段偏移
DOS_E_LFANEW_OFF = 0x3C  # e_lfanew 偏移

# IMAGE_FILE_HEADER 大小和字段偏移
FILE_HEADER_SIZE = 20
FILE_HEADER_NUM_SECTIONS_OFF = 2   # NumberOfSections
FILE_HEADER_SIZE_OPT_OFF = 16      # SizeOfOptionalHeader

# IMAGE_NT_HEADERS 开头的 Signature
PE_SIGNATURE = b"PE\0\0"

# OptionalHeader Magic 值
PE32_MAGIC = 0x10B   # x86
PE32PLUS_MAGIC = 0x20B  # x64

# IMAGE_SECTION_HEADER 大小和字段偏移
SECTION_HEADER_SIZE = 40
SECTION_NAME_OFF = 0       # 8 字节节名
SECTION_VADDR_OFF = 12     # VirtualAddress
SECTION_VSIZE_OFF = 8      # Misc.VirtualSize
SECTION_RAW_OFF = 20       # PointerToRawData
SECTION_RAW_SIZE_OFF = 16  # SizeOfRawData


def find_lock_section(pe_data):
    """解析 PE 节表，找 .text2 节的 (raw_offset, raw_size)
    返回 (offset, size)，找不到返回 (-1, 0)

    MSVC link.exe 不合并不同特性的 .text2$X 子节（LNK4078 警告），
    导致 PE 中可能有多个独立的 .text2 节（.text2$text / .text2$data 等）。
    builder.c 也是取所有 .text2 节的并集 [min_rva, max_rva+vsize)，
    但 raw offset 不连续，这里只取第一个 .text2 节的 raw 范围（stub_data_t
    在 .text2$text 的开头，第一个 .text2 节就能找到）。
    """
    if len(pe_data) < DOS_E_LFANEW_OFF + 4:
        return -1, 0
    e_lfanew = struct.unpack_from("<I", pe_data, DOS_E_LFANEW_OFF)[0]
    if e_lfanew + len(PE_SIGNATURE) + FILE_HEADER_SIZE > len(pe_data):
        return -1, 0
    if pe_data[e_lfanew:e_lfanew + 4] != PE_SIGNATURE:
        return -1, 0

    # IMAGE_FILE_HEADER 紧跟 PE Signature
    fh_off = e_lfanew + 4
    n_sections = struct.unpack_from("<H", pe_data, fh_off + FILE_HEADER_NUM_SECTIONS_OFF)[0]
    size_opt = struct.unpack_from("<H", pe_data, fh_off + FILE_HEADER_SIZE_OPT_OFF)[0]

    # 节表紧跟 OptionalHeader 之后
    sec_table_off = fh_off + FILE_HEADER_SIZE + size_opt
    if sec_table_off + n_sections * SECTION_HEADER_SIZE > len(pe_data):
        return -1, 0

    # 遍历所有节，找 .text2 节（节名前 6 字节 == ".text2"）
    # builder.c 取并集，这里只取第一个（stub_data_t 在第一个 .text2 节里）
    for i in range(n_sections):
        off = sec_table_off + i * SECTION_HEADER_SIZE
        name = pe_data[off:off + 8]
        # 节名是 8 字节，不足补 \0，比较前 6 字节即可
        if name[:6] == b".text2" and (len(name) == 6 or name[6] == 0 or name[6:8] == b"\0\0"):
            # 排除 ".text2z" 等巧合（第 7 字节必须是 \0 或 .text2$ 子节分隔符）
            if name[6:7] != b"\0" and name[6:7] != b"$":
                continue
            raw_off = struct.unpack_from("<I", pe_data, off + SECTION_RAW_OFF)[0]
            raw_size = struct.unpack_from("<I", pe_data, off + SECTION_RAW_SIZE_OFF)[0]
            if raw_off + raw_size <= len(pe_data):
                return raw_off, raw_size
    return -1, 0


def find_stub_data_in_pe(pe_data, stub_data_version, stub_data_size):
    """从加壳产物 PE 的 .text2 节中找 stub_data_t
    返回 (offset_in_pe, stub_data_size)；找不到返回 (-1, 0)"""
    lock_off, lock_size = find_lock_section(pe_data)
    if lock_off < 0:
        return -1, 0
    # 在 .text2 节范围内搜索（find_stub_data 会做三重校验）
    lock_data = pe_data[lock_off:lock_off + lock_size]
    try:
        rel_off, _ = find_stub_data(lock_data, stub_data_version, stub_data_size)
        return lock_off + rel_off, stub_data_size
    except RuntimeError:
        return -1, 0


def main():
    parser = argparse.ArgumentParser(
        description="读 stub.bin 或加壳产物 exe 的 stub 身份信息")
    parser.add_argument("input", nargs="?", help="stub.bin 或 packed.exe")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="输出格式（text/json，默认 text）")
    parser.add_argument("--summary", metavar="DIR",
                        help="批量模式：列出目录下所有 stub_*.bin 的 identity")
    parser.add_argument("--winlock-root",
                        help="packer/ 目录路径（用于找 config.h），"
                             "不传则从脚本位置自动推断")
    args = parser.parse_args()

    # winlock_root 未传时从脚本位置自动推断（cmake/ 上溯到 packer/）
    winlock_root = args.winlock_root
    if not winlock_root:
        winlock_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # parse_config_h 返回 (version, bin_ver, sizeof)，这里只用 version 和 sizeof
    stub_data_version, _, stub_data_size = parse_config_h(winlock_root)

    # ---- 批量模式 ----
    if args.summary:
        results = []
        for f in sorted(os.listdir(args.summary)):
            if f.startswith("stub_") and f.endswith(".bin"):
                path = os.path.join(args.summary, f)
                with open(path, "rb") as fh:
                    data = fh.read()
                try:
                    off, _ = find_stub_data(data, stub_data_version, stub_data_size)
                    id_dict = read_identity(data, off, stub_data_size)
                    id_dict["file"] = f
                    results.append(id_dict)
                except RuntimeError as e:
                    # 找不到 stub_data_t 的文件跳过（如 stub_reflective_*.bin 不存在）
                    pass
        if args.format == "json":
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                print(f"{r['file']}: {format_identity(r)}")
        return

    # ---- 单文件模式 ----
    if not args.input:
        parser.error("需要 input 或 --summary")

    with open(args.input, "rb") as f:
        data = f.read()

    # 判断输入类型：PE 文件（MZ 魔数）还是 stub.bin
    if data[:2] == b"MZ":
        # PE 文件：解析节表找 .text2 节
        off, sz = find_stub_data_in_pe(data, stub_data_version, stub_data_size)
        if off < 0:
            print(f"[ERR] 在 PE 的 .text2 节中找不到 stub_data_t: {args.input}",
                  file=sys.stderr)
            sys.exit(1)
    else:
        # stub.bin
        try:
            off, sz = find_stub_data(data, stub_data_version, stub_data_size)
        except RuntimeError as e:
            print(f"[ERR] {e}: {args.input}", file=sys.stderr)
            sys.exit(1)

    id_dict = read_identity(data, off, sz)

    if args.format == "json":
        # JSON 模式追加文件名（manifest 生成用）
        id_dict["file"] = os.path.basename(args.input)
        print(json.dumps(id_dict, indent=2))
    else:
        print(f"{args.input}: {format_identity(id_dict)}")


if __name__ == "__main__":
    main()
