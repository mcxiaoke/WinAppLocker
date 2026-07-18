"""pe_info.py - 快速查看 PE 关键字段"""
import sys
import pefile

def main():
    if len(sys.argv) < 2:
        print("Usage: pe_info.py <file.exe>")
        sys.exit(1)
    p = pefile.PE(sys.argv[1])
    machine = p.FILE_HEADER.Machine
    arch = "x86 (PE32)" if machine == 0x14c else "x64 (PE32+)" if machine == 0x8664 else f"? (0x{machine:04X})"
    print(f"File: {sys.argv[1]}")
    print(f"Machine: 0x{machine:04X}  -> {arch}")
    print(f"Sections: {len(p.sections)}")
    print(f"ImageBase: 0x{p.OPTIONAL_HEADER.ImageBase:X}")
    print(f"AddressOfEntryPoint: 0x{p.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
    print(f"SizeOfImage: 0x{p.OPTIONAL_HEADER.SizeOfImage:X}")
    print(f"DllCharacteristics: 0x{p.OPTIONAL_HEADER.DllCharacteristics:04X}")
    dc = p.OPTIONAL_HEADER.DllCharacteristics
    flags = []
    if dc & 0x0020: flags.append("HIGH_ENTROPY_VA")
    if dc & 0x0040: flags.append("DYNAMIC_BASE(ASLR)")
    if dc & 0x0100: flags.append("NX(CFG_COMPAT)")
    if dc & 0x0400: flags.append("NO_SEH")
    if dc & 0x4000: flags.append("GUARD_CF")
    if dc & 0x8000: flags.append("TERMINAL_SERVER_AWARE")
    print(f"  Flags: {', '.join(flags) if flags else '(none)'}")
    print(f"Subsystem: {p.OPTIONAL_HEADER.Subsystem}")
    print("Sections:")
    for s in p.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', 'replace')
        print(f"  [{name:8s}] VA=0x{s.VirtualAddress:X} VSize=0x{s.Misc_VirtualSize:X} "
              f"RawOff=0x{s.PointerToRawData:X} RawSize=0x{s.SizeOfRawData:X} "
              f"Char=0x{s.Characteristics:08X}")
    # TLS
    tls = p.OPTIONAL_HEADER.DATA_DIRECTORY[9]
    print(f"TLS dir: VA=0x{tls.VirtualAddress:X} Size=0x{tls.Size:X}")
    if tls.VirtualAddress and tls.Size:
        if machine == 0x8664:
            tls_dir = p.get_data(9)
            if len(tls_dir) >= 24:
                aoc = int.from_bytes(tls_dir[24:32], 'little')
                print(f"  AddressOfCallBacks: 0x{aoc:X}")
        else:
            tls_dir = p.get_data(9)
            if len(tls_dir) >= 12:
                aoc = int.from_bytes(tls_dir[12:16], 'little')
                print(f"  AddressOfCallBacks: 0x{aoc:X}")
    # Reloc
    reloc = p.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    print(f"Reloc dir: VA=0x{reloc.VirtualAddress:X} Size=0x{reloc.Size:X}")

if __name__ == "__main__":
    main()
