#!/usr/bin/env python3
"""临时禁用 PE 的 DYNAMIC_BASE 标志，测试 ASLR 路径是否是问题根因"""
import sys
import struct

def flip_aslr(path, disable=True):
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    oh_off = e_lfanew + 24
    dll_char_off = oh_off + 70
    dll_char = struct.unpack_from('<H', data, dll_char_off)[0]
    old = dll_char
    if disable:
        dll_char &= ~0x0040  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        dll_char &= ~0x0020  # HIGH_ENTROPY_VA
    else:
        dll_char |= 0x0040
        dll_char |= 0x0020
    struct.pack_into('<H', data, dll_char_off, dll_char)
    out = path + ".noaslr.exe" if disable else path + ".aslr.exe"
    with open(out, 'wb') as f:
        f.write(data)
    print(f"{path}: DllChar 0x{old:04X} -> 0x{dll_char:04X}, saved to {out}")

if __name__ == "__main__":
    for p in sys.argv[1:]:
        flip_aslr(p)
