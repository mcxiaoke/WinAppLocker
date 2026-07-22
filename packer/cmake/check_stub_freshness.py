#!/usr/bin/env python3
"""check_stub_freshness.py - 校验 dist/ 里的 stub 是否与当前源码一致

用法：python check_stub_freshness.py --stub-dir <dir> --winlock-root <dir> [--strict]
  --stub-dir:     dist/ 目录路径（含 stub_inplace_x64.bin 等）
  --winlock-root: packer/ 目录路径
  --strict:       CRC 不匹配时返回非 0（CI 用），默认 warn-only

逻辑：
  1. 用 patch_stub_identity.find_stub_data 读 stub.bin 的 stub_source_crc 字段
  2. 用 patch_stub_identity.compute_source_crc 重算当前源码的 CRC32
  3. 对比，不一致则警告；--strict 模式下额外返回非 0 退出码

退出码：
  0 = 全部匹配（或 warn-only 模式下始终返回 0）
  1 = --strict 模式下检测到 CRC 不匹配
"""
import sys
import os
import argparse
import struct

# 复用 patch_stub_identity.py 的常量和函数
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from patch_stub_identity import (
    IDENTITY_FMT, IDENTITY_SIZE, CHECKSUM_SIZE,
    parse_config_h, find_stub_data, compute_source_crc,
)


def read_stub_source_crc(stub_bin_path, stub_data_version, stub_data_size):
    """从 stub.bin 读 stub_source_crc 字段
    返回 (source_crc, githash_str)；找不到返回 (None, None)"""
    with open(stub_bin_path, "rb") as f:
        data = f.read()
    try:
        off, _ = find_stub_data(data, stub_data_version, stub_data_size)
    except RuntimeError:
        return None, None
    identity_off = off + stub_data_size - CHECKSUM_SIZE - IDENTITY_SIZE
    fields = struct.unpack_from(IDENTITY_FMT, data, identity_off)
    # fields[4] = stub_source_crc，fields[6] = stub_githash[8]
    githash = fields[6].rstrip(b"\0").decode("ascii", "replace")
    return fields[4], githash


def main():
    parser = argparse.ArgumentParser(
        description="校验 dist/ stub 是否与当前源码一致")
    parser.add_argument("--stub-dir", required=True,
                        help="dist/ 目录路径")
    parser.add_argument("--winlock-root", required=True,
                        help="packer/ 目录路径（找 config.h 和源码）")
    parser.add_argument("--strict", action="store_true",
                        help="CRC 不匹配时返回非 0（CI 用），默认 warn-only")
    args = parser.parse_args()

    # parse_config_h 返回 (version, bin_ver, sizeof)
    stub_data_version, _, stub_data_size = parse_config_h(args.winlock_root)

    # 校验两个架构的 stub.bin
    stub_files = [
        ("stub_inplace_x64.bin", "x64"),
        ("stub_inplace_x86.bin", "x86"),
    ]

    mismatch_count = 0

    for bin_name, arch in stub_files:
        bin_path = os.path.join(args.stub_dir, bin_name)
        if not os.path.exists(bin_path):
            # 文件不存在不算错误（可能只构建了一个架构），跳过
            continue

        stub_crc, githash = read_stub_source_crc(
            bin_path, stub_data_version, stub_data_size)
        if stub_crc is None:
            print(f"[stub] WARN: {bin_name} 无法读取 stub_source_crc "
                  f"(magic+version+arch 校验未通过)", file=sys.stderr)
            continue

        src_crc = compute_source_crc(args.winlock_root, arch)

        if src_crc != stub_crc:
            mismatch_count += 1
            print(f"[stub] WARN: source CRC mismatch! {bin_name} "
                  f"stub=0x{stub_crc:08x} src=0x{src_crc:08x} "
                  f"githash={githash} — stub is stale, rebuild recommended",
                  file=sys.stderr)
        else:
            print(f"[stub] OK: {bin_name} source_crc=0x{stub_crc:08x} "
                  f"githash={githash} matches current source")

    # --strict 模式：CRC 不匹配时返回 1，让 CI 能 fail
    if args.strict and mismatch_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
