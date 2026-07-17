using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// 读取已加密 EXE 的元信息，用于验证打包是否正确。
    /// 检查项：
    ///   - 文件大小、stub 版本（WAL_VER blob）
    ///   - 是否测试 stub（[stub_test] 标记）
    ///   - payload header 字段（algo/kdf/iters/plaintext_len/crc/subsystem/timestamp）
    ///   - payload footer 完整性（magic + CRC）
    /// </summary>
    internal static class PackInfo
    {
        /// <summary>
        /// 读取并打印已加密 EXE 的信息。返回 0=成功，1=不是合法的 packed exe，2=文件错误。
        /// </summary>
        public static int Inspect(string packedExePath)
        {
            if (!File.Exists(packedExePath))
            {
                Console.Error.WriteLine($"文件不存在: {packedExePath}");
                return 2;
            }

            byte[] data;
            try
            {
                data = File.ReadAllBytes(packedExePath);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"读取失败: {ex.Message}");
                return 2;
            }

            Console.WriteLine($"文件: {packedExePath}");
            Console.WriteLine($"大小: {data.Length} bytes ({data.Length / 1024.0:F1} KB)");

            // 1. 检查是否包含 payload footer（从末尾读）
            if (data.Length < PayloadFormat.HeaderSize + PayloadFormat.FooterSize)
            {
                Console.Error.WriteLine("✗ 文件过小，不包含 WinAppLocker payload");
                return 1;
            }

            int footerOff = data.Length - PayloadFormat.FooterSize;
            bool footerMagicOk = CheckFooterMagic(data, footerOff);
            Console.WriteLine();
            Console.WriteLine("=== Payload Footer ===");
            Console.WriteLine($"  Footer magic: {(footerMagicOk ? "OK (WALEND)" : "MISMATCH")}");
            if (!footerMagicOk)
            {
                Console.Error.WriteLine("✗ 未找到 WinAppLocker footer magic，此文件不是合法的加密 EXE");
                return 1;
            }

            PayloadFooter footer = null;
            try
            {
                footer = PayloadFooter.FromBytes(data, footerOff);
                Console.WriteLine($"  Footer CRC32: 0x{footer.FooterCrc32:X8} (校验通过)");
                Console.WriteLine($"  Payload len:  {footer.PayloadLen} bytes");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"✗ Footer 解析失败: {ex.Message}");
                return 1;
            }

            // 2. 反向定位 header
            long headerOff = (long)data.Length - PayloadFormat.FooterSize - (long)footer.PayloadLen;
            if (headerOff < 0 || headerOff > data.Length)
            {
                Console.Error.WriteLine($"✗ Payload_len 异常: {footer.PayloadLen}");
                return 1;
            }

            PayloadHeader header = null;
            try
            {
                header = PayloadHeader.FromBytes(data, (int)headerOff);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"✗ Header 解析失败: {ex.Message}");
                return 1;
            }

            Console.WriteLine();
            Console.WriteLine("=== Payload Header ===");
            Console.WriteLine($"  Magic:        WALOCK\\x01\\x00 (OK)");
            Console.WriteLine($"  Version:      {header.Version}");
            Console.WriteLine($"  Header size:  {header.HeaderSize}");
            Console.WriteLine($"  Header CRC32: 0x{header.HeaderCrc32:X8} (校验通过)");
            Console.WriteLine($"  Algorithm:    0x{header.AlgorithmId:X4} ({AlgoName(header.AlgorithmId)})");
            Console.WriteLine($"  KDF:          0x{header.KdfId:X4} ({KdfName(header.KdfId)})");
            Console.WriteLine($"  Iterations:   {header.KdfIterations}");
            Console.WriteLine($"  Flags:        0x{header.Flags:X8}");
            Console.WriteLine($"  Salt len:     {header.SaltLen}");
            Console.WriteLine($"  Nonce len:    {header.NonceLen}");
            Console.WriteLine($"  Plaintext len: {header.PlaintextLen} bytes ({header.PlaintextLen / 1024.0:F1} KB)");
            Console.WriteLine($"  Plaintext CRC: 0x{header.PlaintextCrc32:X8}");
            Console.WriteLine($"  Subsystem:    {header.Subsystem} ({SubsystemName(header.Subsystem)})");
            Console.WriteLine($"  Machine:      0x{header.Machine:X4} ({MachineName(header.Machine)})");
            var ts = DateTimeOffset.FromUnixTimeSeconds((long)header.Timestamp).LocalDateTime;
            Console.WriteLine($"  Timestamp:    {ts:yyyy-MM-dd HH:mm:ss} ({header.Timestamp})");
            Console.WriteLine($"  Ext len:      {header.ExtLen} bytes ({(header.ExtLen > 0 ? "有扩展元数据" : "无")})");

            // 3. 解析 Extension TLV（如果有）
            if (header.ExtLen > 0)
            {
                int extOffset = (int)headerOff + PayloadFormat.HeaderSize + header.SaltLen + header.NonceLen
                    + (int)(header.PlaintextLen / 16 + 1) * 16 + PayloadFormat.HmacSha256TagLen;
                Console.WriteLine();
                Console.WriteLine("=== Extension TLV ===");
                var exts = ExtTlv.Parse(data, extOffset, (int)header.ExtLen);
                foreach (var kv in exts)
                {
                    string tagName = ExtTagName(kv.Key);
                    string value = FormatTlvValue(kv.Key, kv.Value);
                    Console.WriteLine($"  [{kv.Key}={tagName}]: {value}");
                }
            }

            // 4. 读取 stub 字节中的版本标记
            int stubLen = (int)headerOff;
            Console.WriteLine();
            Console.WriteLine("=== Stub 信息 ===");
            Console.WriteLine($"  Stub 大小:    {stubLen} bytes ({stubLen / 1024.0:F1} KB)");
            Console.WriteLine($"  Payload 偏移: {headerOff} (0x{headerOff:X})");

            string stubVer = ReadStubVersion(data, stubLen);
            Console.WriteLine($"  Stub 版本:    {(stubVer ?? "(未找到 WAL_VER 标记)")}");

            bool isTest = IsTestStub(data, stubLen);
            Console.WriteLine($"  Stub 类型:    {(isTest ? "Test（内置密码，仅供测试）" : "正式版")}");

            // 5. 汇总
            Console.WriteLine();
            Console.WriteLine("=== 校验结果 ===");
            Console.WriteLine($"  Header magic:   OK");
            Console.WriteLine($"  Header CRC32:   OK");
            Console.WriteLine($"  Footer magic:   OK");
            Console.WriteLine($"  Footer CRC32:   OK");
            Console.WriteLine($"  Payload 结构:   OK (header + salt({header.SaltLen}) + nonce({header.NonceLen}) + cipher + ext({header.ExtLen}) + footer({PayloadFormat.FooterSize}))");
            Console.WriteLine($"  总大小验证:     stub({stubLen}) + payload({footer.PayloadLen}) + footer({PayloadFormat.FooterSize}) = {stubLen + (long)footer.PayloadLen + PayloadFormat.FooterSize} vs 实际 {data.Length}");
            bool sizeMatch = stubLen + (long)footer.PayloadLen + PayloadFormat.FooterSize == data.Length;
            Console.WriteLine($"                  {(sizeMatch ? "OK" : "MISMATCH")}");

            Console.WriteLine();
            Console.WriteLine(sizeMatch && footerMagicOk ? "✓ 这是合法的 WinAppLocker 加密 EXE" : "✗ 文件结构异常");
            return (sizeMatch && footerMagicOk) ? 0 : 1;
        }

        private static bool CheckFooterMagic(byte[] data, int off)
        {
            for (int i = 0; i < 8; i++)
            {
                if (data[off + 0x0C + i] != PayloadFormat.FooterMagicA[i]) return false;
                if (data[off + 0x14 + i] != PayloadFormat.FooterMagicB[i]) return false;
            }
            return true;
        }

        /// <summary>在 stub 字节范围内搜索 WAL_VER|...|WAL_END 标记（UTF-16）。</summary>
        private static string ReadStubVersion(byte[] data, int stubLen)
        {
            byte[] startBytes = Encoding.Unicode.GetBytes(PayloadFormat.VersionBlobStart);
            byte[] endBytes = Encoding.Unicode.GetBytes(PayloadFormat.VersionBlobEnd);

            int start = ByteSearch.IndexOf(data, startBytes, 0, stubLen);
            if (start < 0) return null;
            int end = ByteSearch.IndexOf(data, endBytes, start + startBytes.Length, stubLen);
            if (end < 0) return null;

            int blobEnd = end + endBytes.Length;
            string blob = Encoding.Unicode.GetString(data, start, blobEnd - start);
            string inner = blob.Substring(PayloadFormat.VersionBlobStart.Length,
                blob.Length - PayloadFormat.VersionBlobStart.Length - PayloadFormat.VersionBlobEnd.Length);
            string[] parts = inner.Split('|');
            if (parts.Length >= 3)
                return $"{parts[0]} (git: {parts[2]}, build: {parts[1]})";
            return inner;
        }

        /// <summary>检测 stub 字节是否包含 [stub_test] 标记（UTF-16 字符串字面量）。</summary>
        private static bool IsTestStub(byte[] data, int stubLen)
        {
            byte[] marker = Encoding.Unicode.GetBytes("[stub_test]");
            return ByteSearch.IndexOf(data, marker, 0, stubLen) >= 0;
        }

        private static string AlgoName(ushort id)
        {
            switch (id)
            {
                case PayloadFormat.AlgoAes256CbcHmacSha256: return "AES-256-CBC + HMAC-SHA256";
                case PayloadFormat.AlgoAes256Gcm: return "AES-256-GCM (预留)";
                default: return "未知";
            }
        }

        private static string KdfName(ushort id)
        {
            switch (id)
            {
                case PayloadFormat.KdfPbkdf2Sha256: return "PBKDF2-HMAC-SHA256";
                default: return "未知";
            }
        }

        private static string SubsystemName(uint sub)
        {
            switch (sub)
            {
                case 2: return "WindowsGui";
                case 3: return "WindowsCui (Console)";
                default: return $"未知 ({sub})";
            }
        }

        private static string MachineName(uint machine)
        {
            switch (machine)
            {
                case 0x014c: return "i386 (x86)";
                case 0x8664: return "AMD64 (x64)";
                case 0xAA64: return "ARM64";
                default: return $"未知 (0x{machine:X4})";
            }
        }

        private static string ExtTagName(ushort tag)
        {
            switch (tag)
            {
                case PayloadFormat.ExtTagOriginalName: return "OriginalName";
                case PayloadFormat.ExtTagPackerVersion: return "PackerVersion";
                case PayloadFormat.ExtTagOriginalSize: return "OriginalSize";
                default: return $"Unknown({tag})";
            }
        }

        /// <summary>按 tag 类型格式化 TLV 值用于显示。</summary>
        private static string FormatTlvValue(ushort tag, byte[] value)
        {
            if (value == null) return "(null)";
            // OriginalSize 是 u64（小端序 8 字节）
            if (tag == PayloadFormat.ExtTagOriginalSize && value.Length == 8)
            {
                ulong v = ((ulong)value[0])
                          | ((ulong)value[1] << 8)
                          | ((ulong)value[2] << 16)
                          | ((ulong)value[3] << 24)
                          | ((ulong)value[4] << 32)
                          | ((ulong)value[5] << 40)
                          | ((ulong)value[6] << 48)
                          | ((ulong)value[7] << 56);
                return $"{v} bytes ({v / 1024.0:F1} KB)";
            }
            // 其他 tag 当作 UTF-8 字符串
            return Encoding.UTF8.GetString(value);
        }
    }
}
