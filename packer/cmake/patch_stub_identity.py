#!/usr/bin/env python3
"""patch_stub_identity.py - POST_BUILD 注入 stub 身份字段

用法：python patch_stub_identity.py <stub.bin> <arch> <toolchain> <winlock_root>
  arch:        x86 或 x64
  toolchain:   MSVC 或 MinGW
  winlock_root: packer/ 目录绝对路径（用于找源码和 config.h）

字段注入策略（审查 B 简化方案）：
  - stub_arch       编译期已注入（CMake/MinGW -D），脚本只校验
  - stub_toolchain  编译期已注入，脚本只校验
  - stub_bin_ver    脚本写入（从 config.h 读 STUB_BIN_VER）
  - stub_build_time 脚本写入（当前 Unix 时间戳）
  - stub_source_crc 脚本写入（CRC32 of 所有 #include 的源文件，行尾归一化为 LF）
  - stub_size       脚本写入（stub.bin 文件大小）
  - stub_githash    脚本写入（git rev-parse --short=8 HEAD，无 git 全 0）

幂等性：patch 前先清零 stub_size 字段，确保重复运行时 find_stub_data 仍能定位
（否则旧 stub_size 与新文件大小不匹配会让搜索失败——但本脚本搜索条件不校验
stub_size，仅靠 magic+version+arch 三重校验定位，因此 stub_size 清零主要是
保持语义一致，便于 inspect 工具识别"已 patch"状态）。
"""
import sys
import os
import struct
import subprocess
import binascii
import re
import time

# "WINLOCK!" 小端 uint64
STUB_DATA_MAGIC = 0x214B434F4C4E4957

# stub_identity_t 字段顺序（与 config.h 一致，6×uint32 + 8 bytes = 32 字节）
# < 表示小端 + 无对齐填充（pragma pack(8) 在 32 字节内本就无填充）
IDENTITY_FMT = "<IIIIII8s"
assert struct.calcsize(IDENTITY_FMT) == 32, "stub_identity_t 必须是 32 字节"

IDENTITY_SIZE = 32    # sizeof(stub_identity_t)
CHECKSUM_SIZE = 8     # sizeof(uint64_t checksum)
# stub_size 字段在 identity 结构中的偏移：5 × sizeof(uint32_t) = 20
# （arch/toolchain/bin_ver/build_time/source_crc 各 4 字节之后）
STUB_SIZE_OFF_IN_IDENTITY = 20


def stub_source_files(winlock_root, arch):
    """stub 源文件列表（CRC 覆盖范围，审查 M4）
    覆盖 stub.c 的所有直接 #include 依赖：config.h / sha256.h / peb_walk.h /
    xtea.h / winlock_compat.h，以及架构相关的 stub_asm_${ARCH}.asm。"""
    return [
        os.path.join(winlock_root, "inplace", "stub.c"),
        os.path.join(winlock_root, "inplace", f"stub_asm_{arch}.asm"),
        os.path.join(winlock_root, "common", "config.h"),
        os.path.join(winlock_root, "common", "sha256.h"),
        os.path.join(winlock_root, "common", "peb_walk.h"),
        os.path.join(winlock_root, "common", "xtea.h"),
        os.path.join(winlock_root, "common", "winlock_compat.h"),
    ]


def parse_config_h(winlock_root):
    """从 config.h 解析 STUB_DATA_VERSION、STUB_BIN_VER、STUB_DATA_SIZEOF
    返回 (version, bin_ver, sizeof) 三元组（审查 A5）"""
    config_path = os.path.join(winlock_root, "common", "config.h")
    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()
    ver_match = re.search(r"#define\s+STUB_DATA_VERSION\s+(\d+)", content)
    binver_match = re.search(r"#define\s+STUB_BIN_VER\s+(0x[0-9a-fA-F]+|\d+)", content)
    sizeof_match = re.search(r"#define\s+STUB_DATA_SIZEOF\s+(\d+)", content)
    if not ver_match or not binver_match or not sizeof_match:
        raise RuntimeError("无法从 config.h 解析 STUB_DATA_VERSION/STUB_BIN_VER/STUB_DATA_SIZEOF")
    return (int(ver_match.group(1)),
            int(binver_match.group(1), 0),
            int(sizeof_match.group(1)))


def compute_source_crc(winlock_root, arch):
    """计算 stub_source_crc（行尾归一化为 LF，审查 A10）
    拼接所有源文件的 CRC32，单个文件用 binascii.crc32 续算。"""
    crc = 0
    for path in stub_source_files(winlock_root, arch):
        if not os.path.exists(path):
            raise RuntimeError(f"源文件不存在: {path}")
        with open(path, "rb") as f:
            data = f.read()
        # 行尾归一化：CRLF -> LF（防止 Windows/Linux/编辑器混用导致 CRC 不一致）
        data = data.replace(b"\r\n", b"\n")
        crc = binascii.crc32(data, crc)
    return crc & 0xffffffff


def find_stub_data(data, stub_data_version, stub_data_size):
    """8 字节对齐搜索 magic + version + arch 范围校验（审查 A8）
    返回 (offset, stub_data_size)；找不到抛 RuntimeError。

    三重校验：
      1. magic == "WINLOCK!"（防误报）
      2. version == STUB_DATA_VERSION（防结构版本漂移导致字段偏移错位）
      3. stub_arch ∈ {1, 2}（防 magic+version 巧合匹配的误报）

    注意：不校验 stub_size（patch 前为 0，patch 后为文件大小，脚本本身要写入
    stub_size，避免先有鸡还是先有蛋问题）。builder.c 里再额外加 stub_size 校验。
    """
    magic_bytes = struct.pack("<Q", STUB_DATA_MAGIC)
    identity_off_in_struct = stub_data_size - CHECKSUM_SIZE - IDENTITY_SIZE

    i = 0
    while i + stub_data_size <= len(data):
        if data[i:i+8] == magic_bytes:
            # 校验 version
            candidate_ver = struct.unpack_from("<H", data, i + 8)[0]
            if candidate_ver != stub_data_version:
                i += 8
                continue
            # 校验 stub_arch 范围（1 或 2）
            identity_off = i + identity_off_in_struct
            arch_val = struct.unpack_from("<I", data, identity_off)[0]
            if arch_val not in (1, 2):
                i += 8
                continue
            return i, stub_data_size
        i += 8
    raise RuntimeError("magic+version+arch 三重校验未通过，无法定位 stub_data_t")


def get_githash(winlock_root):
    """获取 git commit short hash（8 字节 ASCII），无 git 或不在仓库则返回空字符串"""
    try:
        githash_str = subprocess.check_output(
            ["git", "rev-parse", "--short=8", "HEAD"],
            cwd=winlock_root, stderr=subprocess.DEVNULL
        ).decode().strip()
        return githash_str
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return ""


def main():
    if len(sys.argv) != 5:
        print("用法: python patch_stub_identity.py <stub.bin> <arch> <toolchain> <winlock_root>",
              file=sys.stderr)
        sys.exit(1)
    stub_bin_path = sys.argv[1]
    arch = sys.argv[2]        # x86 / x64
    toolchain = sys.argv[3]   # MSVC / MinGW
    winlock_root = sys.argv[4]

    # 校验 arch / toolchain 参数
    arch_map = {"x86": 1, "x64": 2}
    toolchain_map = {"MSVC": 1, "MinGW": 2}
    if arch not in arch_map:
        print(f"[ERR] arch 必须是 x86 或 x64，实际: {arch}", file=sys.stderr)
        sys.exit(1)
    if toolchain not in toolchain_map:
        print(f"[ERR] toolchain 必须是 MSVC 或 MinGW，实际: {toolchain}", file=sys.stderr)
        sys.exit(1)
    arch_val = arch_map[arch]
    toolchain_val = toolchain_map[toolchain]

    # 从 config.h 解析常量
    stub_data_version, stub_bin_ver, stub_data_size = parse_config_h(winlock_root)

    # 计算源码 CRC32
    source_crc = compute_source_crc(winlock_root, arch)

    # 构建时间戳
    build_time = int(time.time())

    # githash（无 git 则全 0）
    githash_str = get_githash(winlock_root)
    githash_bytes = githash_str.encode("ascii")[:8].ljust(8, b"\0")

    # 读 stub.bin
    with open(stub_bin_path, "rb") as f:
        data = bytearray(f.read())
    stub_size = len(data)

    # 定位 stub_data_t（三重校验：magic + version + arch 范围）
    offset, _ = find_stub_data(data, stub_data_version, stub_data_size)
    identity_off = offset + stub_data_size - CHECKSUM_SIZE - IDENTITY_SIZE

    # 幂等：patch 前先清零 stub_size 字段（审查 A11）
    struct.pack_into("<I", data, identity_off + STUB_SIZE_OFF_IN_IDENTITY, 0)

    # 校验编译期注入的 stub_arch / stub_toolchain 是否匹配
    existing = struct.unpack_from(IDENTITY_FMT, data, identity_off)
    if existing[0] != arch_val:
        raise RuntimeError(
            f"stub_arch 不匹配: 文件里={existing[0]} 期望={arch_val} ({arch})\n"
            f"  可能是 CMake/MinGW -DSTUB_ARCH 注入错误，或 stub.bin 不是预期的架构")
    if existing[1] != toolchain_val:
        raise RuntimeError(
            f"stub_toolchain 不匹配: 文件里={existing[1]} 期望={toolchain_val} ({toolchain})\n"
            f"  可能是 CMake/MinGW -DSTUB_TOOLCHAIN 注入错误，或 stub.bin 不是预期的工具链")

    # 写入 5 个字段（stub_arch / stub_toolchain 保持不变）
    new_identity = (
        arch_val,           # stub_arch（不变）
        toolchain_val,      # stub_toolchain（不变）
        stub_bin_ver,       # stub_bin_ver
        build_time,         # stub_build_time
        source_crc,         # stub_source_crc
        stub_size,          # stub_size
        githash_bytes,      # stub_githash
    )
    struct.pack_into(IDENTITY_FMT, data, identity_off, *new_identity)

    # 写回
    with open(stub_bin_path, "wb") as f:
        f.write(data)

    githash_display = githash_str if githash_str else "(none)"
    print(f"[OK] patched {os.path.basename(stub_bin_path)}: "
          f"arch={arch} toolchain={toolchain} bin_ver=0x{stub_bin_ver:04x} "
          f"build_time={build_time} source_crc=0x{source_crc:08x} "
          f"stub_size={stub_size} githash={githash_display}")


if __name__ == "__main__":
    main()
