#!/usr/bin/env python3
"""analyze_samples.py - 批量解析 temp/samples/*.exe 的 PE 结构

输出字段：
 1. Machine (x86 / x64 / ARM64)
 2. Subsystem (GUI / CUI)
 3. .rsrc 节是否存在 + 是否包含 RT_MANIFEST (资源类型 24)
    - 顺便检测 manifest 中是否声明 comctl32 v6 (依赖 comctl32 + 版本 6)
 4. 延迟导入表 (DataDirectory[13] = IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
 5. TLS directory (DataDirectory[9])
 6. .NET CLR (DataDirectory[14] = COM_DESCRIPTOR)
 7. reloc 表 IMAGE_REL_BASED_* 类型分布
 8. Import 的 DLL 列表

最后给出阶段 2（packer 加壳）需要重点验证的样本清单：
 - 延迟导入非空
 - TLS 非空
 - manifest 引用 comctl32 v6
 - .NET CLR
 - 其它异常情况
"""
import os
import sys
import glob
import struct

# 优先用 pefile，不可用时退回自实现 PE 解析（关键路径）
try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False


# --- Machine / Subsystem 映射 ---
MACHINE_MAP = {
    0x014C: "x86 (I386)",
    0x8664: "x64 (AMD64)",
    0xAA64: "ARM64",
    0x01C0: "ARM (Thumb)",
    0x01C4: "ARM (Thumb2)",
    0x0200: "IA64",
}
SUBSYSTEM_MAP = {
    2: "GUI",
    3: "CUI",
    5: "OS/2 CUI",
    7: "Posix CUI",
    9: "WindowsCE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "XBOX",
    16: "Windows Boot Application",
}

# --- IMAGE_REL_BASED_* 类型 ---
RELOC_TYPE_NAMES = {
    0: "ABSOLUTE (padding)",
    1: "HIGH (16-bit high)",
    2: "LOW (16-bit low)",
    3: "HIGHLOW (32-bit)",
    4: "HIGHADJ",
    5: "MIPS_JMPADDR",
    10: "DIR64 (64-bit)",
    20: "ARM_MOV32",
    22: "ARM_MOV32A",
    23: "ARM_MOV32W",
    32: "RISC_V_HIGHLOW",
    34: "RISC_V_DIR64",
}


def machine_str(m):
    return MACHINE_MAP.get(m, f"Unknown(0x{m:04X})")


def subsystem_str(s):
    return SUBSYSTEM_MAP.get(s, f"Unknown({s})")


def detect_comctl32_v6(manifest_text):
    """检测 manifest 是否声明了 comctl32 v6 依赖。

    正确写法：在 <dependency> 中引用
    Microsoft.Windows.Common-Controls 版本 6.0.x.x
    （注意 manifest 中并不直接出现 "comctl32" 字样，而是引用程序集名）
    """
    if not manifest_text:
        return False
    low = manifest_text.lower()
    has_cc = "microsoft.windows.common-controls" in low
    # version="6.0.0.0" 或 version='6.0.0.0' 都接受
    has_v6 = ('version="6' in low) or ("version='6" in low)
    return has_cc and has_v6


# ----------------------------------------------------------------------
# pefile 路径
# ----------------------------------------------------------------------
def analyze_with_pefile(path):
    """用 pefile 模块解析"""
    pe = pefile.PE(path, fast_load=False)
    info = {}

    info["file"] = os.path.basename(path)
    info["size"] = os.path.getsize(path)
    info["machine"] = pe.FILE_HEADER.Machine
    info["machine_str"] = machine_str(pe.FILE_HEADER.Machine)
    info["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
    info["subsystem_str"] = subsystem_str(pe.OPTIONAL_HEADER.Subsystem)

    # 节列表
    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin1", "replace")
        sections.append(name)
    info["sections"] = sections
    info["has_rsrc"] = ".rsrc" in sections

    # DataDirectory
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    info["dd_delay_import"] = (dd[13].VirtualAddress, dd[13].Size)
    info["dd_tls"] = (dd[9].VirtualAddress, dd[9].Size)
    info["dd_clr"] = (dd[14].VirtualAddress, dd[14].Size)

    # 延迟导入的 DLL 列表
    delay_dlls = []
    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            try:
                name = entry.dll.decode("latin1", "replace")
            except Exception:
                name = "?"
            delay_dlls.append(name)
    info["delay_dlls"] = delay_dlls

    # 普通 Import 的 DLL 列表
    import_dlls = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                name = entry.dll.decode("latin1", "replace")
            except Exception:
                name = "?"
            import_dlls.append(name)
    info["import_dlls"] = import_dlls

    # RT_MANIFEST (资源类型 24)
    info["has_manifest"] = False
    info["manifest_comctl32_v6"] = False
    info["manifest_text"] = None
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        # 遍历资源类型
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            # res_type.id 可能是 int 或 None (字符串名)
            if res_type.id == pefile.RESOURCE_TYPE["RT_MANIFEST"]:
                info["has_manifest"] = True
                # 提取 manifest 文本
                try:
                    for res_id in res_type.directory.entries:
                        for res_lang in res_id.directory.entries:
                            data_rva = res_lang.data.struct.OffsetToData
                            size = res_lang.data.struct.Size
                            mdata = pe.get_data(data_rva, size)
                            text = mdata.decode("utf-8", errors="replace")
                            info["manifest_text"] = text
                            info["manifest_comctl32_v6"] = detect_comctl32_v6(text)
                            break
                        break
                except Exception as e:
                    info["manifest_text"] = f"<read fail: {e}>"
                break

    # reloc 类型统计
    reloc_counts = {}
    if dd[5].VirtualAddress and dd[5].Size:
        try:
            reloc_data = pe.get_data(dd[5].VirtualAddress, dd[5].Size)
            off = 0
            while off + 8 <= len(reloc_data):
                page_rva, block_size = struct.unpack_from("<II", reloc_data, off)
                if block_size == 0:
                    break
                # block_size 包括 8 字节头
                entry_count = (block_size - 8) // 2
                for i in range(entry_count):
                    entry = struct.unpack_from("<H", reloc_data, off + 8 + i * 2)[0]
                    rtype = (entry >> 12) & 0xF
                    reloc_counts[rtype] = reloc_counts.get(rtype, 0) + 1
                off += block_size
        except Exception:
            pass
    info["reloc_counts"] = reloc_counts

    pe.close()
    return info


# ----------------------------------------------------------------------
# 纯 struct 路径（pefile 不可用时的兜底）
# ----------------------------------------------------------------------
def rva_to_raw(rva, sections):
    for name, vaddr, vsize, raw_off, raw_size in sections:
        if vaddr <= rva < vaddr + max(vsize, raw_size):
            return raw_off + (rva - vaddr)
    return None


def read_cstr(data, off, max_len=256):
    end = data.find(b"\x00", off)
    if end < 0 or end - off > max_len:
        end = off + max_len
    return data[off:end].decode("latin1", "replace")


def analyze_with_struct(path):
    """纯 struct 解析 PE（足够覆盖本任务需要的字段）"""
    with open(path, "rb") as f:
        data = f.read()
    info = {"file": os.path.basename(path), "size": len(data)}

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    # PE\0\0 验证
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE file")
    n_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    info["machine"] = machine
    info["machine_str"] = machine_str(machine)

    oh_off = e_lfanew + 24
    magic = struct.unpack_from("<H", data, oh_off)[0]
    is_pe32plus = magic == 0x20B
    info["is_pe32plus"] = is_pe32plus

    # Subsystem 偏移：
    # PE32:  oh_off + 68
    # PE32+: oh_off + 68
    subsystem = struct.unpack_from("<H", data, oh_off + 68)[0]
    info["subsystem"] = subsystem
    info["subsystem_str"] = subsystem_str(subsystem)

    # DataDirectory 偏移：
    # PE32:  oh_off + 96
    # PE32+: oh_off + 112
    dd_off = oh_off + (112 if is_pe32plus else 96)

    sec_off = oh_off + opt_hdr_size
    sections = []
    for i in range(n_sec):
        so = sec_off + i * 40
        name = data[so : so + 8].rstrip(b"\x00").decode("latin1", "replace")
        vsize, vaddr, raw_size, raw_off = struct.unpack_from("<IIII", data, so + 8)
        sections.append((name, vaddr, vsize, raw_off, raw_size))
    info["sections"] = [s[0] for s in sections]
    info["has_rsrc"] = ".rsrc" in info["sections"]

    def dd(idx):
        return struct.unpack_from("<II", data, dd_off + idx * 8)

    info["dd_delay_import"] = dd(13)
    info["dd_tls"] = dd(9)
    info["dd_clr"] = dd(14)

    # Import DLL 列表 (DataDirectory[1])
    import_dlls = []
    imp_rva, imp_size = dd(1)
    if imp_rva and imp_size:
        raw = rva_to_raw(imp_rva, sections)
        if raw is not None:
            i = 0
            while raw + i * 20 + 20 <= len(data):
                ilt, tds, fwd, name_rva, fta = struct.unpack_from(
                    "<IIIII", data, raw + i * 20
                )
                if ilt == 0 and name_rva == 0:
                    break
                nr = rva_to_raw(name_rva, sections)
                if nr is not None:
                    import_dlls.append(read_cstr(data, nr))
                i += 1
    info["import_dlls"] = import_dlls

    # Delay Import DLL 列表 (DataDirectory[13])
    delay_dlls = []
    di_rva, di_size = info["dd_delay_import"]
    if di_rva and di_size:
        # ImageBase
        image_base = (
            struct.unpack_from("<Q", data, oh_off + 24)[0]
            if is_pe32plus
            else struct.unpack_from("<I", data, oh_off + 28)[0]
        )
        raw = rva_to_raw(di_rva, sections)
        if raw is not None:
            i = 0
            while raw + i * 32 + 32 <= len(data):
                attrs, dll_rva, modh, iat, iname, biat, uit, tds = struct.unpack_from(
                    "<IIIIIIII", data, raw + i * 32
                )
                if attrs == 0 and dll_rva == 0:
                    break
                # attrs bit 1 = RVAs are VAs
                target_rva = dll_rva
                if attrs & 1:
                    target_rva = dll_rva - image_base
                nr = rva_to_raw(target_rva, sections)
                if nr is not None:
                    delay_dlls.append(read_cstr(data, nr))
                i += 1
    info["delay_dlls"] = delay_dlls

    # RT_MANIFEST 在 .rsrc 中
    info["has_manifest"] = False
    info["manifest_comctl32_v6"] = False
    info["manifest_text"] = None
    rsrc_rva, rsrc_size = dd(2)
    if rsrc_rva and rsrc_size:
        rsrc_raw = rva_to_raw(rsrc_rva, sections)
        if rsrc_raw is not None:
            # 解析 IMAGE_RESOURCE_DIRECTORY
            def parse_dir(dir_off, level=0, target_type=None):
                # dir_off 是相对 rsrc_raw 的偏移
                if dir_off + 16 > len(data) - rsrc_raw:
                    return None
                base = rsrc_raw + dir_off
                num_named, num_id = struct.unpack_from("<HH", data, base + 12)
                # 实际上：num_named 在前，num_id 在后
                # IMAGE_RESOURCE_DIRECTORY: Characteristics(4) TimeDateStamp(4) MajorVersion(2) MinorVersion(2) NumberOfNamedEntries(2) NumberOfIdEntries(2)
                num_named, num_id = struct.unpack_from("<HH", data, base + 12)
                total = num_named + num_id
                entries_off = base + 16
                for i in range(total):
                    name_or_id, off_to_data = struct.unpack_from(
                        "<II", data, entries_off + i * 8
                    )
                    # 高位为 1 表示是 name (字符串), 否则是 ID
                    is_named = (name_or_id & 0x80000000) != 0
                    if not is_named:
                        rid = name_or_id & 0x7FFFFFFF
                    else:
                        rid = None
                    # off_to_data 高位为 1 表示子目录
                    is_subdir = (off_to_data & 0x80000000) != 0
                    sub_off = off_to_data & 0x7FFFFFFF
                    if level == 0:
                        # 这里 rid 是资源类型
                        if rid == 24:  # RT_MANIFEST
                            return parse_dir(sub_off, level + 1, target_type=24)
                    elif level == 1:
                        # 找第一个子目录（language 层）
                        return parse_dir(sub_off, level + 1, target_type=target_type)
                    elif level == 2:
                        # 这是 IMAGE_RESOURCE_DATA_ENTRY
                        data_rva, size, codepage, reserved = struct.unpack_from(
                            "<IIII", data, rsrc_raw + sub_off
                        )
                        return data_rva, size
                return None

            manifest = parse_dir(0)
            if manifest is not None:
                info["has_manifest"] = True
                m_rva, m_size = manifest
                m_raw = rva_to_raw(m_rva, sections)
                if m_raw is not None:
                    m_text = data[m_raw : m_raw + m_size].decode(
                        "utf-8", errors="replace"
                    )
                    info["manifest_text"] = m_text
                    info["manifest_comctl32_v6"] = detect_comctl32_v6(m_text)

    # reloc 类型统计
    reloc_counts = {}
    rel_rva, rel_size = dd(5)
    if rel_rva and rel_size:
        rel_raw = rva_to_raw(rel_rva, sections)
        if rel_raw is not None:
            off = 0
            while off + 8 <= rel_size:
                page_rva, block_size = struct.unpack_from(
                    "<II", data, rel_raw + off
                )
                if block_size == 0:
                    break
                entry_count = (block_size - 8) // 2
                for i in range(entry_count):
                    if off + 8 + i * 2 + 2 > rel_size:
                        break
                    entry = struct.unpack_from(
                        "<H", data, rel_raw + off + 8 + i * 2
                    )[0]
                    rtype = (entry >> 12) & 0xF
                    reloc_counts[rtype] = reloc_counts.get(rtype, 0) + 1
                off += block_size
    info["reloc_counts"] = reloc_counts

    return info


# ----------------------------------------------------------------------
# 表格打印
# ----------------------------------------------------------------------
def fmt_reloc_summary(counts):
    if not counts:
        return "(none)"
    parts = []
    for rtype in sorted(counts.keys()):
        name = RELOC_TYPE_NAMES.get(rtype, f"TYPE_{rtype}")
        parts.append(f"{name}={counts[rtype]}")
    return ", ".join(parts)


def fmt_dll_list(dlls, limit=12):
    if not dlls:
        return "(none)"
    dlls = list(dlls)
    if len(dlls) <= limit:
        return ", ".join(dlls)
    return ", ".join(dlls[:limit]) + f"  ... (+{len(dlls) - limit})"


def print_section(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def print_table(rows):
    """简单等宽表格打印"""
    if not rows:
        return
    headers = list(rows[0].keys())
    widths = {}
    for h in headers:
        widths[h] = max(len(h), max(len(str(r.get(h, ""))) for r in rows))
    # 截断过宽
    max_w = 60
    for h in headers:
        if widths[h] > max_w:
            widths[h] = max_w

    def cell(h, v):
        s = str(v) if v is not None else ""
        if len(s) > widths[h]:
            s = s[: widths[h] - 3] + "..."
        return s.ljust(widths[h])

    line = "+" + "+".join("-" * (widths[h] + 2) for h in headers) + "+"
    print(line)
    print("| " + " | ".join(h.ljust(widths[h]) for h in headers) + " |")
    print(line)
    for r in rows:
        print("| " + " | ".join(cell(h, r.get(h, "")) for h in headers) + " |")
    print(line)


def main():
    samples_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "temp",
        "samples",
    )
    # 允许命令行覆盖
    if len(sys.argv) > 1:
        paths = sys.argv[1:]
    else:
        paths = sorted(glob.glob(os.path.join(samples_dir, "*.exe")))

    if not paths:
        print(f"no .exe under {samples_dir}")
        sys.exit(1)

    print(f"使用 Python: {sys.executable}")
    print(f"pefile 可用: {HAVE_PEFILE}  (版本: {getattr(pefile, '__version__', '?') if HAVE_PEFILE else 'N/A'})")
    print(f"待分析样本数: {len(paths)}")

    infos = []
    for p in paths:
        try:
            if HAVE_PEFILE:
                info = analyze_with_pefile(p)
            else:
                info = analyze_with_struct(p)
            info["error"] = None
        except Exception as e:
            info = {
                "file": os.path.basename(p),
                "size": os.path.getsize(p),
                "error": f"{type(e).__name__}: {e}",
            }
        infos.append(info)

    # ---------- 详细列表 ----------
    print_section("PE 关键字段一览")
    rows = []
    for it in infos:
        if it.get("error"):
            rows.append({"File": it["file"], "Error": it["error"]})
            continue
        rows.append(
            {
                "File": it["file"],
                "Size": it["size"],
                "Machine": it["machine_str"],
                "Subsystem": it["subsystem_str"],
                ".rsrc": "Y" if it["has_rsrc"] else "N",
                "Manifest": "Y" if it["has_manifest"] else "N",
                "Ctlv6": "Y" if it["manifest_comctl32_v6"] else "N",
                "DelayImp": f"Y({len(it['delay_dlls'])})" if it["delay_dlls"] else "N",
                "TLS": "Y" if (it["dd_tls"][0] and it["dd_tls"][1]) else "N",
                "CLR": "Y" if (it["dd_clr"][0] and it["dd_clr"][1]) else "N",
            }
        )
    print_table(rows)

    # ---------- 延迟导入详情 ----------
    print_section("延迟导入 (Delay Import) 详情")
    any_delay = False
    for it in infos:
        if it.get("error"):
            continue
        if it["delay_dlls"]:
            any_delay = True
            print(f"  [{it['file']}] ({len(it['delay_dlls'])} 个):")
            for d in it["delay_dlls"]:
                print(f"      - {d}")
    if not any_delay:
        print("  (所有样本都没有延迟导入)")

    # ---------- Import DLL 列表 ----------
    print_section("Import DLL 列表")
    for it in infos:
        if it.get("error"):
            continue
        print(f"  [{it['file']}] ({len(it['import_dlls'])} 个):")
        if it["import_dlls"]:
            for d in it["import_dlls"]:
                print(f"      - {d}")
        else:
            print("      (none)")

    # ---------- TLS 详情 ----------
    print_section("TLS Directory 详情")
    any_tls = False
    for it in infos:
        if it.get("error"):
            continue
        rva, size = it["dd_tls"]
        if rva and size:
            any_tls = True
            print(f"  [{it['file']}] TLS dir: RVA=0x{rva:08X} Size=0x{size:X}")
    if not any_tls:
        print("  (所有样本都没有 TLS Directory)")

    # ---------- .NET CLR 详情 ----------
    print_section(".NET CLR (COM Descriptor) 详情")
    any_clr = False
    for it in infos:
        if it.get("error"):
            continue
        rva, size = it["dd_clr"]
        if rva and size:
            any_clr = True
            print(f"  [{it['file']}] CLR dir: RVA=0x{rva:08X} Size=0x{size:X}")
    if not any_clr:
        print("  (所有样本都没有 CLR)")

    # ---------- Manifest 详情 ----------
    print_section("RT_MANIFEST 详情")
    any_manifest = False
    for it in infos:
        if it.get("error"):
            continue
        if it["has_manifest"]:
            any_manifest = True
            v6 = "YES comctl32 v6" if it["manifest_comctl32_v6"] else "no v6"
            mlen = len(it["manifest_text"]) if it["manifest_text"] else 0
            print(f"  [{it['file']}] manifest 存在 ({mlen} bytes) - {v6}")
    if not any_manifest:
        print("  (所有样本都没有 manifest)")

    # ---------- Reloc 类型分布 ----------
    print_section("Reloc 类型分布")
    for it in infos:
        if it.get("error"):
            continue
        print(f"  [{it['file']}]")
        if it["reloc_counts"]:
            total = sum(it["reloc_counts"].values())
            print(f"      总条目数: {total}")
            for rtype in sorted(it["reloc_counts"].keys()):
                name = RELOC_TYPE_NAMES.get(rtype, f"TYPE_{rtype}")
                cnt = it["reloc_counts"][rtype]
                pct = (cnt * 100.0 / total) if total else 0
                print(f"      type={rtype:2d} {name:30s} count={cnt:6d} ({pct:5.1f}%)")
        else:
            print("      (no reloc)")

    # ---------- 阶段 2 需要重点验证的样本 ----------
    print_section("阶段 2 (packer 加壳) 重点验证样本")
    focus = []
    for it in infos:
        if it.get("error"):
            continue
        reasons = []
        if it["delay_dlls"]:
            reasons.append(
                f"延迟导入({len(it['delay_dlls'])}个: {','.join(it['delay_dlls'][:3])})"
            )
        rva, size = it["dd_tls"]
        if rva and size:
            reasons.append("TLS Directory 存在")
        rva, size = it["dd_clr"]
        if rva and size:
            reasons.append(".NET CLR (COM Descriptor)")
        if it["manifest_comctl32_v6"]:
            reasons.append("comctl32 v6 manifest")
        if it["has_manifest"] and not it["manifest_comctl32_v6"]:
            # 有 manifest 但不是 v6 也要关注，避免后续壳解析失败
            reasons.append("有 manifest (非 v6，仍需处理)")
        if reasons:
            focus.append((it["file"], it["machine_str"], it["subsystem_str"], reasons))
    if focus:
        for fname, m, s, reasons in focus:
            print(f"  - {fname:30s} [{m:14s} / {s:3s}]")
            for r in reasons:
                print(f"        * {r}")
    else:
        print("  (没有需要特别验证的样本)")

    # ---------- 总结表格 (CSV 友好) ----------
    print_section("总结 CSV")
    print("File,Size,Machine,Subsystem,rsrc,Manifest,comctl32_v6,DelayImp,DelayImpDLLs,TLS,CLR,ImportDLLs,RelocSummary")
    for it in infos:
        if it.get("error"):
            print(f"{it['file']},ERROR,{it['error']}")
            continue
        rva, size = it["dd_tls"]
        csv = ",".join(
            [
                it["file"],
                str(it["size"]),
                it["machine_str"],
                it["subsystem_str"],
                "Y" if it["has_rsrc"] else "N",
                "Y" if it["has_manifest"] else "N",
                "Y" if it["manifest_comctl32_v6"] else "N",
                f"{len(it['delay_dlls'])}",
                ";".join(it["delay_dlls"]),
                "Y" if (rva and size) else "N",
                "Y" if (it["dd_clr"][0] and it["dd_clr"][1]) else "N",
                ";".join(it["import_dlls"]),
                fmt_reloc_summary(it["reloc_counts"]).replace(",", "/"),
            ]
        )
        print(csv)


if __name__ == "__main__":
    main()
