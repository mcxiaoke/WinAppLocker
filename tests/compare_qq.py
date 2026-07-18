#!/usr/bin/env python3
# compare_qq.py - 对比 qq.exe 和 qq_locked.exe 的 PE 结构差异
# 找出可能导致 "init failed 0x00000002" 的原因
import pefile
import sys

def dump_pe(path, label):
    print(f"\n{'='*60}\n{label}: {path}\n{'='*60}")
    pe = pefile.PE(path)

    print(f"\n[Basic]")
    print(f"  Machine: 0x{pe.FILE_HEADER.Machine:04X}")
    print(f"  ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
    print(f"  AddressOfEntryPoint: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
    print(f"  SizeOfImage: 0x{pe.OPTIONAL_HEADER.SizeOfImage:08X}")
    print(f"  SizeOfHeaders: 0x{pe.OPTIONAL_HEADER.SizeOfHeaders:08X}")
    print(f"  CheckSum: 0x{pe.OPTIONAL_HEADER.CheckSum:08X}")
    print(f"  Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
    print(f"  DllCharacteristics: 0x{pe.OPTIONAL_HEADER.DllCharacteristics:04X}")
    print(f"  NumberOfRvaAndSizes: {pe.OPTIONAL_HEADER.NumberOfRvaAndSizes}")

    print(f"\n[Sections]")
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('latin1', 'replace')
        print(f"  {name:10s} VA=0x{s.VirtualAddress:08X} VS=0x{s.Misc_VirtualSize:08X} "
              f"RawOff=0x{s.PointerToRawData:08X} RawSize=0x{s.SizeOfRawData:08X} "
              f"Char=0x{s.Characteristics:08X}")

    print(f"\n[DataDirectories]")
    for i, d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        names = pefile.DIRECTORY_ENTRY if hasattr(pefile, 'DIRECTORY_ENTRY') else {}
        nm = ''
        # pefile 的 directory 名字
        for attr in dir(pefile):
            if attr.startswith('IMAGE_DIRECTORY_ENTRY_') and getattr(pefile, attr) == i:
                nm = attr[len('IMAGE_DIRECTORY_ENTRY_'):]
                break
        if d.VirtualAddress or d.Size:
            print(f"  [{i:2d}] {nm:20s} VA=0x{d.VirtualAddress:08X} Size=0x{d.Size:08X}")

    # 导入表
    print(f"\n[Imports]")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('latin1', 'replace')
            funcs = [imp.name.decode('latin1') if imp.name else f'ord#{imp.ordinal}'
                     for imp in entry.imports[:5]]
            more = f' (+{len(entry.imports)-5} more)' if len(entry.imports) > 5 else ''
            print(f"  {dll}: {', '.join(funcs)}{more}")
    else:
        print("  (none)")

    # 资源
    print(f"\n[Resources]")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        def walk(entries, depth=0, parent_name=''):
            for e in entries:
                if e.name is not None:
                    nm = f'str#{e.name.string.decode("latin1","replace")}'
                else:
                    # standard type/id
                    if depth == 0:
                        nm = pefile.RESOURCE_TYPE.get(e.struct.Id, f'Type{e.struct.Id}')
                    else:
                        nm = f'ID_{e.struct.Id}'
                if e.struct.DataIsDirectory:
                    print(f"  {'  '*depth}{nm}/")
                    walk(e.directory.entries, depth+1, nm)
                else:
                    d = e.data
                    print(f"  {'  '*depth}{nm}: off=0x{d.struct.OffsetToData:08X} size=0x{d.struct.Size:08X}")
        walk(pe.DIRECTORY_ENTRY_RESOURCE.entries)
    else:
        print("  (none)")

    # TLS
    print(f"\n[TLS]")
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        t = pe.DIRECTORY_ENTRY_TLS.struct
        print(f"  StartAddressOfRawData: 0x{t.StartAddressOfRawData:08X}")
        print(f"  EndAddressOfRawData:   0x{t.EndAddressOfRawData:08X}")
        print(f"  AddressOfIndex:        0x{t.AddressOfIndex:08X}")
        print(f"  AddressOfCallBacks:     0x{t.AddressOfCallBacks:08X}")
    else:
        print("  (none)")

    # 加载配置
    print(f"\n[LoadConfig]")
    if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
        lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        print(f"  Size: 0x{lc.Size:08X}")
        print(f"  SecurityCookie: 0x{lc.SecurityCookie:08X}")
    else:
        print("  (none)")

    pe.close()

if __name__ == '__main__':
    orig = r'C:\Home\Apps\QQ\Bin\qq.exe'
    locked = r'C:\Home\Apps\QQ\Bin\qq_locked.exe'
    dump_pe(orig, "ORIGINAL")
    dump_pe(locked, "LOCKED")
