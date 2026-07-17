using System;
using System.Collections.Generic;
// stub 内嵌的 payload 格式定义。
// 按设计文档 §1：stub 与 packer 完全独立，互不引用，
// 仅通过 payload 字节格式约定。本文件是 stub 侧的独立拷贝。
namespace WinAppLocker.Stub
{
    /// <summary>
    /// payload 头部 + 尾部 + 算法 ID 等常量。
    /// stub 侧独立定义，必须与 packer 侧保持字节级一致。
    /// </summary>
    internal static class PayloadFormat
    {
        // ---- Magic ----
        public static readonly byte[] HeaderMagic = new byte[]
        {
            (byte)'W', (byte)'A', (byte)'L', (byte)'O',
            (byte)'C', (byte)'K', 0x01, 0x00
        };

        public static readonly byte[] FooterMagicA = new byte[]
        {
            (byte)'W', (byte)'A', (byte)'L', (byte)'E',
            (byte)'N', (byte)'D', 0xAA, 0xAA
        };

        public static readonly byte[] FooterMagicB = new byte[]
        {
            (byte)'W', (byte)'A', (byte)'L', (byte)'E',
            (byte)'N', (byte)'D', 0xBB, 0xBB
        };

        // ---- Sizes ----
        public const int HeaderSize = 64;
        public const int FooterSize = 32;

        // ---- Versions ----
        public const ushort PayloadVersion = 1;

        // ---- Algorithm IDs ----
        public const ushort AlgoAes256CbcHmacSha256 = 2;

        // ---- KDF IDs ----
        public const ushort KdfPbkdf2Sha256 = 1;

        // ---- Flags ----
        public const uint FlagHasExtensions = 0x04;

        // ---- Extension TLV Tags ----
        public const ushort ExtTagOriginalName = 1;
        public const ushort ExtTagPackerVersion = 2;
        public const ushort ExtTagOriginalSize = 3;

        // ---- 默认参数 ----
        public const int AesCbcIvLen = 16;
        public const int HmacSha256TagLen = 32;
        public const int AesKeyLen = 32;
    }

    /// <summary>
    /// Extension TLV 区域解析工具（stub 侧独立拷贝）。
    /// 格式：连续的 [tag:2][len:2][value:len] 条目。
    /// </summary>
    internal static class ExtTlv
    {
        public static List<KeyValuePair<ushort, byte[]>> Parse(byte[] buf, int offset, int length)
        {
            var list = new List<KeyValuePair<ushort, byte[]>>();
            int end = offset + length;
            while (offset + 4 <= end)
            {
                ushort tag = LE.ReadU16(buf, offset);
                ushort len = LE.ReadU16(buf, offset + 2);
                if (offset + 4 + len > end) break;
                var value = new byte[len];
                Buffer.BlockCopy(buf, offset + 4, value, 0, len);
                list.Add(new KeyValuePair<ushort, byte[]>(tag, value));
                offset += 4 + len;
            }
            return list;
        }

        public static string FindString(List<KeyValuePair<ushort, byte[]>> list, ushort tag)
        {
            foreach (var kv in list)
            {
                if (kv.Key == tag && kv.Value != null)
                    return System.Text.Encoding.UTF8.GetString(kv.Value);
            }
            return null;
        }
    }

    /// <summary>CRC32 (IEEE 802.3 多项式 0xEDB88320)。</summary>
    internal static class Crc32
    {
        private static readonly uint[] Table = BuildTable();

        private static uint[] BuildTable()
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++)
                {
                    c = (c & 1) != 0 ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                }
                t[i] = c;
            }
            return t;
        }

        public static uint Compute(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            return Compute(data, 0, data.Length);
        }

        public static uint Compute(byte[] data, int offset, int length)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            uint crc = 0xFFFFFFFFu;
            for (int i = 0; i < length; i++)
            {
                crc = Table[(crc ^ data[offset + i]) & 0xFF] ^ (crc >> 8);
            }
            return crc ^ 0xFFFFFFFFu;
        }
    }

    /// <summary>小端序读写辅助。</summary>
    internal static class LE
    {
        public static void WriteU16(byte[] buf, int off, ushort v)
        {
            buf[off] = (byte)v;
            buf[off + 1] = (byte)(v >> 8);
        }

        public static void WriteU32(byte[] buf, int off, uint v)
        {
            buf[off] = (byte)v;
            buf[off + 1] = (byte)(v >> 8);
            buf[off + 2] = (byte)(v >> 16);
            buf[off + 3] = (byte)(v >> 24);
        }

        public static void WriteU64(byte[] buf, int off, ulong v)
        {
            for (int i = 0; i < 8; i++)
                buf[off + i] = (byte)(v >> (8 * i));
        }

        public static ushort ReadU16(byte[] buf, int off)
        {
            return (ushort)(buf[off] | (buf[off + 1] << 8));
        }

        public static uint ReadU32(byte[] buf, int off)
        {
            return (uint)(buf[off]
                | (buf[off + 1] << 8)
                | (buf[off + 2] << 16)
                | (buf[off + 3] << 24));
        }

        public static ulong ReadU64(byte[] buf, int off)
        {
            ulong v = 0;
            for (int i = 0; i < 8; i++)
                v |= ((ulong)buf[off + i]) << (8 * i);
            return v;
        }
    }

    /// <summary>
    /// Payload 头部字段（64 字节，按小端序编码）。
    /// 0x00  magic         [8]
    /// 0x08  version       [2]
    /// 0x0A  header_size   [2]
    /// 0x0C  header_crc32  [4]   (对 offset 0x10..0x3F 共 48 字节计算)
    /// 0x10  algorithm_id  [2]
    /// 0x12  kdf_id        [2]
    /// 0x14  kdf_iterations [4]
    /// 0x18  flags         [4]
    /// 0x1C  salt_len      [2]
    /// 0x1E  nonce_len     [2]
    /// 0x20  plaintext_len [8]
    /// 0x28  plaintext_crc32 [4]
    /// 0x2C  subsystem     [4]
    /// 0x30  machine       [4]
    /// 0x34  timestamp     [8]
    /// 0x3C  ext_len       [4]  (Extension TLV 区域总字节数，0 = 无扩展)
    /// </summary>
    internal sealed class PayloadHeader
    {
        public const int HeaderCrcCoverOffset = 0x10;
        public const int HeaderCrcCoverLen = PayloadFormat.HeaderSize - HeaderCrcCoverOffset; // 48

        public ushort Version;
        public ushort HeaderSize;
        public uint HeaderCrc32;
        public ushort AlgorithmId;
        public ushort KdfId;
        public uint KdfIterations;
        public uint Flags;
        public ushort SaltLen;
        public ushort NonceLen;
        public ulong PlaintextLen;
        public uint PlaintextCrc32;
        public uint Subsystem;
        public uint Machine;
        public ulong Timestamp;
        public uint ExtLen;        // Extension TLV 区域总字节数（原 Reserved 字段）

        public static PayloadHeader FromBytes(byte[] buf, int offset)
        {
            if (buf == null) throw new ArgumentNullException(nameof(buf));
            if (offset + PayloadFormat.HeaderSize > buf.Length)
                throw new ArgumentException("buffer too small for header");

            // 校验 magic
            for (int i = 0; i < 8; i++)
                if (buf[offset + i] != PayloadFormat.HeaderMagic[i])
                    throw new InvalidOperationException("header magic mismatch");

            var h = new PayloadHeader
            {
                Version = LE.ReadU16(buf, offset + 0x08),
                HeaderSize = LE.ReadU16(buf, offset + 0x0A),
                HeaderCrc32 = LE.ReadU32(buf, offset + 0x0C),
                AlgorithmId = LE.ReadU16(buf, offset + 0x10),
                KdfId = LE.ReadU16(buf, offset + 0x12),
                KdfIterations = LE.ReadU32(buf, offset + 0x14),
                Flags = LE.ReadU32(buf, offset + 0x18),
                SaltLen = LE.ReadU16(buf, offset + 0x1C),
                NonceLen = LE.ReadU16(buf, offset + 0x1E),
                PlaintextLen = LE.ReadU64(buf, offset + 0x20),
                PlaintextCrc32 = LE.ReadU32(buf, offset + 0x28),
                Subsystem = LE.ReadU32(buf, offset + 0x2C),
                Machine = LE.ReadU32(buf, offset + 0x30),
                Timestamp = LE.ReadU64(buf, offset + 0x34),
                ExtLen = LE.ReadU32(buf, offset + 0x3C)
            };

            if (h.HeaderSize != PayloadFormat.HeaderSize)
                throw new InvalidOperationException($"unexpected header_size {h.HeaderSize}");

            // 校验 CRC
            uint expected = Crc32.Compute(buf, offset + HeaderCrcCoverOffset, HeaderCrcCoverLen);
            if (expected != h.HeaderCrc32)
                throw new InvalidOperationException("header crc mismatch");

            return h;
        }
    }

    /// <summary>
    /// Payload 尾部字段（32 字节，按小端序编码）。
    /// 0x00  payload_len   [8]   (header 起到 footer 前的总长度)
    /// 0x08  footer_crc32  [4]   (对 0x00..0x07 + 0x0C..0x1F 共 28 字节计算)
    /// 0x0C  magic_a        [8]
    /// 0x14  magic_b        [8]
    /// 0x1C  footer_pad     [4]
    /// </summary>
    internal sealed class PayloadFooter
    {
        public const int FooterCrcCoverLen = PayloadFormat.FooterSize - 4; // 28 字节

        public ulong PayloadLen;
        public uint FooterCrc32;

        public static PayloadFooter FromBytes(byte[] buf, int offset)
        {
            if (buf == null) throw new ArgumentNullException(nameof(buf));
            if (offset + PayloadFormat.FooterSize > buf.Length)
                throw new ArgumentException("buffer too small for footer");

            for (int i = 0; i < 8; i++)
            {
                if (buf[offset + 0x0C + i] != PayloadFormat.FooterMagicA[i])
                    throw new InvalidOperationException("footer magic_a mismatch");
                if (buf[offset + 0x14 + i] != PayloadFormat.FooterMagicB[i])
                    throw new InvalidOperationException("footer magic_b mismatch");
            }

            var f = new PayloadFooter
            {
                PayloadLen = LE.ReadU64(buf, offset + 0x00),
                FooterCrc32 = LE.ReadU32(buf, offset + 0x08)
            };

            var crcBuf = new byte[FooterCrcCoverLen];
            Buffer.BlockCopy(buf, offset + 0x00, crcBuf, 0, 8);
            Buffer.BlockCopy(buf, offset + 0x0C, crcBuf, 8, 20);
            uint expected = Crc32.Compute(crcBuf);
            if (expected != f.FooterCrc32)
                throw new InvalidOperationException("footer crc mismatch");

            return f;
        }
    }
}
