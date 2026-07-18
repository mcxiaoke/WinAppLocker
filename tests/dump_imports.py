"""dump PE imports (fixed)"""
import struct
import sys

def rva_to_raw(rva, sections):
    for va, vsz, raw, rsz in sections:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None

def read_imports(path):
    with open(path, 'rb') as f:
        data = f.read()
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from('<H', data, opt_off)[0]
    if magic == 0x20b:
        dd_off = opt_off + 112
    else:
        dd_off = opt_off + 96

    n_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
    sz_opt = struct.unpack_from('<H', data, pe_off + 0x14)[0]
    sec_off = pe_off + 0x18 + sz_opt
    sections = []
    for i in range(n_sec):
        so = sec_off + i * 40
        va, vsz, raw, rsz = struct.unpack_from('<IIII', data, so + 8)
        sections.append((va, vsz, raw, rsz))

    # Standard imports - DataDirectory[1]
    imp_rva, _ = struct.unpack_from('<II', data, dd_off + 8)
    print(f"IMPORT dir RVA=0x{imp_rva:X}")
    if imp_rva:
        imp_raw = rva_to_raw(imp_rva, sections)
        print(f"  Raw=0x{imp_raw:X}")
        if imp_raw:
            print("Standard imports:")
            off = imp_raw
            while True:
                oft, ts, fwd, name_rva, ft = struct.unpack_from('<IIIII', data, off)
                if name_rva == 0 and oft == 0:
                    break
                nr = rva_to_raw(name_rva, sections)
                if nr is None:
                    print(f"  <bad name RVA 0x{name_rva:X}>")
                    off += 20
                    continue
                end = data.index(b'\0', nr)
                name = data[nr:end].decode('ascii', errors='replace')
                print(f"  {name}")
                off += 20

    # Delay imports - DataDirectory[13]
    di_rva, di_size = struct.unpack_from('<II', data, dd_off + 13*8)
    print(f"\nDELAY_IMPORT dir RVA=0x{di_rva:X} Size=0x{di_size:X}")
    if di_rva:
        di_raw = rva_to_raw(di_rva, sections)
        print(f"  Raw=0x{di_raw:X}")
        if di_raw:
            print("Delay imports:")
            off = di_raw
            while True:
                # IMAGE_DELAY_IMPORT_DESCRIPTOR is 32 bytes
                attrs, name_rva, hmod_rva, iat_rva, int_rva, biat_rva, uit_rva, ts = \
                    struct.unpack_from('<IIIIIIII', data, off)
                if name_rva == 0:
                    break
                nr = rva_to_raw(name_rva, sections)
                if nr is None:
                    print(f"  <bad name RVA 0x{name_rva:X}>")
                    off += 32
                    continue
                end = data.index(b'\0', nr)
                name = data[nr:end].decode('ascii', errors='replace')
                print(f"  {name} (attrs=0x{attrs:X})")
                off += 32

if __name__ == '__main__':
    for p in sys.argv[1:]:
        print(f"\n=== {p} ===")
        read_imports(p)
