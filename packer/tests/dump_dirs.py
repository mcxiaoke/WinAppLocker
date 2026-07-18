"""dump PE data directories for comparison"""
import struct
import sys

def dump_data_dirs(path):
    with open(path, 'rb') as f:
        data = f.read()
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from('<H', data, opt_off)[0]
    print(f'PE Magic: 0x{magic:04X}')
    if magic == 0x20b:  # PE32+
        dd_off = opt_off + 112
        num_rva_off = opt_off + 108
        soh_off = opt_off + 60
        soi_off = opt_off + 56
        sa_off = opt_off + 32
        fa_off = opt_off + 36
    else:  # PE32
        dd_off = opt_off + 96
        num_rva_off = opt_off + 92
        soh_off = opt_off + 64
        soi_off = opt_off + 56
        sa_off = opt_off + 32
        fa_off = opt_off + 36

    sa = struct.unpack_from('<I', data, sa_off)[0]
    fa = struct.unpack_from('<I', data, fa_off)[0]
    soi = struct.unpack_from('<I', data, soi_off)[0]
    soh = struct.unpack_from('<I', data, soh_off)[0]
    num_rva = struct.unpack_from('<I', data, num_rva_off)[0]
    print(f'SectionAlignment: 0x{sa:X}')
    print(f'FileAlignment: 0x{fa:X}')
    print(f'SizeOfImage: 0x{soi:X}')
    print(f'SizeOfHeaders: 0x{soh:X}')
    print(f'NumberOfRvaAndSizes: {num_rva}')

    names = ['EXPORT','IMPORT','RESOURCE','EXCEPTION','SECURITY','BASERELOC',
             'DEBUG','ARCH','GLOBALPTR','TLS','LOAD_CONFIG','BOUND_IMPORT',
             'IAT','DELAY_IMPORT','CLR','RESERVED']
    for i in range(min(num_rva, 16)):
        rva, sz = struct.unpack_from('<II', data, dd_off + i*8)
        nm = names[i] if i < len(names) else str(i)
        print(f'  [{i:2d}] {nm:<14} RVA=0x{rva:08X} Size=0x{sz:08X}')

if __name__ == '__main__':
    for path in sys.argv[1:]:
        print(f'=== {path} ===')
        dump_data_dirs(path)
        print()
