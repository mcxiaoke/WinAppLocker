#!/usr/bin/env python3
# fix_checksum.py - 重新计算 PE 的 CheckSum 并写回
# 用法: python fix_checksum.py <pe_file>
import pefile
import sys
import shutil
import os

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_checksum.py <pe_file>")
        sys.exit(1)
    path = sys.argv[1]
    backup = path + '.bak_nocksum'
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
        print(f"[*] Backup: {backup}")

    pe = pefile.PE(path)
    # pefile 没有直接计算 checksum 的 API,用 generate_checksum
    new_cksum = pe.generate_checksum()
    old_cksum = pe.OPTIONAL_HEADER.CheckSum
    print(f"[*] Old CheckSum: 0x{old_cksum:08X}")
    print(f"[*] New CheckSum: 0x{new_cksum:08X}")
    if old_cksum == new_cksum:
        print("[*] CheckSum already correct, nothing to do.")
        pe.close()
        return
    pe.OPTIONAL_HEADER.CheckSum = new_cksum
    pe.write(path)
    pe.close()
    print(f"[+] Written: {path}")

if __name__ == '__main__':
    main()
