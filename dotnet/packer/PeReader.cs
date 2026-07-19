using System;
using AsmResolver.PE;
using AsmResolver.PE.File;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// 原 EXE 信息：子系统 / 机器类型 / 是否 .NET / 安全特性 / 数据目录。
    /// </summary>
    internal sealed class PeInfo
    {
        public ushort Subsystem;
        public ushort Machine;
        public bool IsDotNet;
        public bool IsGui => Subsystem == (ushort)SubSystem.WindowsGui;

        // DllCharacteristics 标志位（ASLR / DEP / CFG / HighEntropyVA）
        public bool IsAslr;            // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
        public bool IsDep;             // IMAGE_DLLCHARACTERISTICS_NX_COMPAT   = 0x0100
        public bool IsHighEntropyVA;   // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
        public bool IsCfg;             // IMAGE_DLLCHARACTERISTICS_GUARD_CF   = 0x4000

        // 数据目录是否存在（Size > 0）
        public bool HasTls;            // IMAGE_DIRECTORY_ENTRY_TLS (index 9)
        public bool IsSigned;          // IMAGE_DIRECTORY_ENTRY_SECURITY (index 4) — Authenticode 签名
        public bool HasReloc;          // IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) — ASLR 重定位表

        /// <summary>
        /// Chromium 系浏览器特征：导入表引用 *_elf.dll（chrome_elf.dll/doubao_elf.dll 等）。
        /// 这类程序依赖版本化子目录下的 DLL（如 145.0.7632.68\chrome_elf.dll），
        /// 反射式 loader 无法模拟 Chrome 自定义的 DLL 加载逻辑，加壳后必定 crash。
        /// 典型例子：Chrome / Edge / Doubao / Brave 等 Chromium 原生浏览器。
        /// 注意：Electron 程序不在此列（Electron 主 EXE 不引用 *_elf.dll）。
        /// </summary>
        public bool IsChromiumLike;

        // 文件大小（字节）
        public long FileSize;

        /// <summary>架构可读名称：x86 / x64 / ARM64 / ARM / Unknown</summary>
        public string MachineName
        {
            get
            {
                switch (Machine)
                {
                    case 0x014c: return "x86";
                    case 0x8664: return "x64";
                    case 0xAA64: return "ARM64";
                    case 0x01c0: return "ARM";
                    case 0x01c4: return "ARM Thumb-2";
                    default: return $"0x{Machine:X4}";
                }
            }
        }

        /// <summary>子系统可读名称：GUI / Console / 其他</summary>
        public string SubsystemName
        {
            get
            {
                switch (Subsystem)
                {
                    case 2: return "GUI";
                    case 3: return "Console";
                    default: return $"0x{Subsystem:X4}";
                }
            }
        }
    }

    /// <summary>
    /// stub 选择偏好（按子系统）。
    /// Auto = 根据 PE 子系统自动选择；Gui/Console = 强制；Test = 测试 stub（内置密码）。
    /// 注意：与 StubManifest.StubKind（加壳方案）不同，此处仅表示子系统偏好。
    /// </summary>
    public enum StubPreference
    {
        Auto = 0,
        Gui = 1,
        Console = 2,
        Test = 3
    }

    /// <summary>
    /// PE 解析：使用 AsmResolver.PE 6.0 提取子系统、机器类型、检测 .NET 托管，
    /// 并用原始字节读取 DllCharacteristics 和关键数据目录（Security / TLS / Reloc）。
    /// </summary>
    internal static class PeReader
    {
        // DllCharacteristics 位掩码
        private const ushort DLL_CHAR_HIGH_ENTROPY_VA = 0x0020;
        private const ushort DLL_CHAR_DYNAMIC_BASE    = 0x0040; // ASLR
        private const ushort DLL_CHAR_NX_COMPAT       = 0x0100; // DEP
        private const ushort DLL_CHAR_GUARD_CF         = 0x4000; // CFG

        // 数据目录索引
        private const int DIR_SECURITY  = 4;  // Authenticode 签名
        private const int DIR_BASERELOC = 5;  // .reloc 重定位表（ASLR 必需）
        private const int DIR_TLS       = 9;  // TLS callbacks
        private const int DIR_IMPORT    = 1;  // Import Directory（导入表）

        public static PeInfo Parse(byte[] peBytes)
        {
            var peFile = PEFile.FromBytes(peBytes);
            var peImage = PEImage.FromFile(peFile);

            var info = new PeInfo
            {
                Subsystem = (ushort)peFile.OptionalHeader.SubSystem,
                Machine = (ushort)peFile.FileHeader.Machine,
                IsDotNet = peImage.DotNetDirectory != null,
                FileSize = peBytes.Length,
            };

            // DllCharacteristics 用原始字节读取，避免对 AsmResolver 枚举 API 的依赖
            ushort dllChar = ReadDllCharacteristics(peBytes);
            info.IsAslr = (dllChar & DLL_CHAR_DYNAMIC_BASE) != 0;
            info.IsDep = (dllChar & DLL_CHAR_NX_COMPAT) != 0;
            info.IsHighEntropyVA = (dllChar & DLL_CHAR_HIGH_ENTROPY_VA) != 0;
            info.IsCfg = (dllChar & DLL_CHAR_GUARD_CF) != 0;

            // 关键数据目录
            ReadDataDirectory(peBytes, DIR_SECURITY,  out bool sec, out _);
            ReadDataDirectory(peBytes, DIR_BASERELOC, out bool reloc, out _);
            ReadDataDirectory(peBytes, DIR_TLS,       out bool tls, out _);
            info.IsSigned = sec;
            info.HasReloc = reloc;
            info.HasTls = tls;

            // Chromium 系浏览器检测：导入表是否引用 *_elf.dll
            info.IsChromiumLike = DetectChromiumLike(peBytes);

            return info;
        }

        /// <summary>
        /// 检测 Chromium 系浏览器（Chrome / Edge / Doubao / Brave 等）。
        ///
        /// 特征：导入表引用 *_elf.dll（chrome_elf.dll / doubao_elf.dll 等）。
        /// 这类程序的 *_elf.dll 在版本化子目录（如 145.0.7632.68\），
        /// 浏览器自己有特殊 DLL 加载逻辑，反射式 loader 无法模拟。
        ///
        /// 检测方式：解析 PE 导入表，遍历每个导入的 DLL 名字，
        /// 匹配 *_elf.dll 后缀（大小写不敏感）。
        /// </summary>
        private static bool DetectChromiumLike(byte[] pe)
        {
            try
            {
                int nt = ReadInt32(pe, 0x3C);
                int optStart = nt + 24;
                if (optStart + 2 > pe.Length) return false;
                ushort magic = ReadUInt16(pe, optStart);

                int dataDirStart;
                if (magic == 0x20b) dataDirStart = optStart + 112;      // PE32+
                else if (magic == 0x10b) dataDirStart = optStart + 96;  // PE32
                else return false;

                // DataDirectory[1] = Import Directory
                int importEntryOffset = dataDirStart + DIR_IMPORT * 8;
                if (importEntryOffset + 8 > pe.Length) return false;
                uint importRva = ReadUInt32(pe, importEntryOffset);
                uint importSize = ReadUInt32(pe, importEntryOffset + 4);
                if (importRva == 0 || importSize == 0) return false;

                // RVA 转文件偏移
                int importFileOffset = RvaToFileOffset(pe, nt, importRva);
                if (importFileOffset < 0) return false;

                // 遍历 IMAGE_IMPORT_DESCRIPTOR（20 字节/项）
                // 结构：OriginalFirstThunk(4) + TimeDateStamp(4) + ForwarderChain(4) + Name(4) + FirstThunk(4)
                // Name 字段（offset 12）是 DLL 名字的 RVA
                // 表以全 0 项结束
                int maxDescriptors = (int)(importSize / 20) + 1;
                for (int i = 0; i < maxDescriptors && i < 1024; i++)
                {
                    int descOffset = importFileOffset + i * 20;
                    if (descOffset + 20 > pe.Length) break;
                    uint nameRva = ReadUInt32(pe, descOffset + 12);
                    if (nameRva == 0) break;  // 结束标记

                    int nameFileOffset = RvaToFileOffset(pe, nt, nameRva);
                    if (nameFileOffset < 0 || nameFileOffset >= pe.Length) continue;

                    string dllName = ReadAsciiString(pe, nameFileOffset);
                    if (string.IsNullOrEmpty(dllName)) continue;

                    // 匹配 *_elf.dll（Chrome/Doubao/Edge 等 Chromium 系浏览器特征）
                    if (dllName.EndsWith("_elf.dll", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>
        /// PE RVA 转文件偏移：遍历节表，找包含该 RVA 的节，
        /// 返回 RVA - 节.VirtualAddress + 节.PointerToRawData。
        /// 找不到返回 -1。
        /// </summary>
        private static int RvaToFileOffset(byte[] pe, int ntHeaderOffset, uint rva)
        {
            int fileHeaderOffset = ntHeaderOffset + 4;  // 跳过 PE 签名
            if (fileHeaderOffset + 20 > pe.Length) return -1;
            ushort numSections = ReadUInt16(pe, fileHeaderOffset + 2);
            ushort optHeaderSize = ReadUInt16(pe, fileHeaderOffset + 16);
            int sectionTableOffset = ntHeaderOffset + 24 + optHeaderSize;

            for (int i = 0; i < numSections; i++)
            {
                int secOffset = sectionTableOffset + i * 40;
                if (secOffset + 40 > pe.Length) break;
                uint virtualSize = ReadUInt32(pe, secOffset + 8);
                uint virtualAddress = ReadUInt32(pe, secOffset + 12);
                uint rawSize = ReadUInt32(pe, secOffset + 16);
                uint rawOffset = ReadUInt32(pe, secOffset + 20);

                // 优先用 VirtualSize 判断（实际映射大小）
                uint sectionSize = virtualSize > 0 ? virtualSize : rawSize;
                if (rva >= virtualAddress && rva < virtualAddress + sectionSize)
                {
                    return (int)(rva - virtualAddress + rawOffset);
                }
            }
            return -1;
        }

        /// <summary>读 null-terminated ASCII 字符串</summary>
        private static string ReadAsciiString(byte[] pe, int offset)
        {
            int end = offset;
            while (end < pe.Length && pe[end] != 0) end++;
            return System.Text.Encoding.ASCII.GetString(pe, offset, end - offset);
        }

        /// <summary>
        /// 从原始 PE 字节读取 DllCharacteristics（WORD）。
        /// 该字段在 PE32 和 PE32+ 中偏移相同：NT 头基址 + 24（OptionalHeader 起点）+ 70 = +94。
        /// </summary>
        private static ushort ReadDllCharacteristics(byte[] pe)
        {
            try
            {
                int nt = ReadInt32(pe, 0x3C);            // e_lfanew → IMAGE_NT_HEADERS
                int dllCharOffset = nt + 24 + 70;        // OptionalHeader.DllCharacteristics
                if (dllCharOffset + 2 > pe.Length) return 0;
                return ReadUInt16(pe, dllCharOffset);
            }
            catch { return 0; }
        }

        /// <summary>
        /// 读取指定数据目录是否存在及其大小。
        /// 数据目录起点（相对于 OptionalHeader 起点 optStart = NT+24）：
        ///   - PE32  (Magic=0x10b): optStart + 96  （PE32 OptionalHeader 固定字段 96 字节）
        ///   - PE32+ (Magic=0x20b): optStart + 112 （PE32+ OptionalHeader 固定字段 112 字节，BaseOfData 缺失、各 Stack/Heap 字段为 QWORD）
        /// 每个数据目录 8 字节：DWORD VirtualAddress + DWORD Size。
        /// 注意：Security 目录的 VirtualAddress 是文件偏移而非 RVA，但只要 Size > 0 即代表已签名。
        /// </summary>
        private static void ReadDataDirectory(byte[] pe, int index, out bool present, out uint size)
        {
            present = false;
            size = 0;
            try
            {
                int nt = ReadInt32(pe, 0x3C);
                int optStart = nt + 24;
                if (optStart + 2 > pe.Length) return;
                ushort magic = ReadUInt16(pe, optStart); // 0x10b = PE32, 0x20b = PE32+

                int dataDirStart;
                if (magic == 0x20b) dataDirStart = optStart + 112; // PE32+
                else if (magic == 0x10b) dataDirStart = optStart + 96; // PE32
                else return;

                int entryOffset = dataDirStart + index * 8;
                if (entryOffset + 8 > pe.Length) return;
                uint va = ReadUInt32(pe, entryOffset);
                uint sz = ReadUInt32(pe, entryOffset + 4);
                if (sz != 0)
                {
                    present = true;
                    size = sz;
                }
            }
            catch { }
        }

        // 小端整数读取辅助
        private static ushort ReadUInt16(byte[] pe, int offset)
        {
            return (ushort)(pe[offset] | (pe[offset + 1] << 8));
        }

        private static uint ReadUInt32(byte[] pe, int offset)
        {
            return (uint)(pe[offset] | (pe[offset + 1] << 8) |
                          (pe[offset + 2] << 16) | (pe[offset + 3] << 24));
        }

        private static int ReadInt32(byte[] pe, int offset)
        {
            return (int)ReadUInt32(pe, offset);
        }
    }
}
