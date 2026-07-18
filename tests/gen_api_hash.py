#!/usr/bin/env python3
"""gen_api_hash.py - 生成 DJB15 API/模块名 hash 常量

借鉴 peldr 的 HashStr（loader.c:99-114）：
  - seed = 1993
  - 大小写不敏感（ASCII_FOLD_MASK）
  - h = ((h << 4) - h) + c   即 h = h * 15 + c

用法：
    python tools/gen_api_hash.py
    python tools/gen_api_hash.py MyCustomApiName

输出可以直接粘贴到 config.h 的 HASH_* 段。
"""
import sys

SEED = 1993


def hash_str(s: str) -> int:
    """DJB15 大小写不敏感 hash，匹配 stub.c 里的 hash_ascii 实现"""
    h = SEED
    for c in s.encode("ascii"):
        # ASCII_FOLD_MASK: 'A' <= c <= 'Z' 时 mask=0x20
        if ord("A") <= c <= ord("Z"):
            c |= 0x20
        h = ((h << 4) - h) + c
        h &= 0xFFFFFFFF
    return h


# 默认导出列表（与 stub.c 中实际用到的 API 一致）
DEFAULT_APIS = [
    "GetProcAddress",
    "LoadLibraryA",
    "VirtualProtect",
    "ExitProcess",
    "DialogBoxIndirectParamW",
    "EndDialog",
    "GetDlgItemTextW",
    "MessageBoxW",
]
DEFAULT_MODULES = ["kernel32.dll", "user32.dll"]


def main():
    args = sys.argv[1:]
    if args:
        # 单独 hash 模式：打印每个参数的 hash
        for s in args:
            print(f"{s:<32} -> 0x{hash_str(s):08X}")
        return
    # 默认：生成 config.h 片段
    print("// API hash (DJB15, seed=1993, case-insensitive)")
    for n in DEFAULT_APIS:
        h = hash_str(n)
        print(f"#define HASH_{n.upper():<30} 0x{h:08X}U")
    print()
    print("// Module hash (same algorithm)")
    for m in DEFAULT_MODULES:
        h = hash_str(m)
        name = m.upper().replace(".", "_")
        print(f"#define HASH_MOD_{name:<20} 0x{h:08X}U")


if __name__ == "__main__":
    main()
