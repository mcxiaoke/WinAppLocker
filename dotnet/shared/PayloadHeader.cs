using System;
// stub 与 packer 共享的 Payload 头部/尾部结构定义
namespace WinAppLocker.Shared
{
    /// <summary>
    /// Payload 头部字段（64 字节，按小端序编码）。
    /// 字段顺序对应文件偏移：
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
    public sealed class PayloadHeader
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

        public byte[] ToBytes()
        {
            var buf = new byte[PayloadFormat.HeaderSize];
            Buffer.BlockCopy(PayloadFormat.HeaderMagic, 0, buf, 0x00, 8);
            LE.WriteU16(buf, 0x08, Version);
            LE.WriteU16(buf, 0x0A, HeaderSize);
            LE.WriteU32(buf, 0x0C, HeaderCrc32);
            LE.WriteU16(buf, 0x10, AlgorithmId);
            LE.WriteU16(buf, 0x12, KdfId);
            LE.WriteU32(buf, 0x14, KdfIterations);
            LE.WriteU32(buf, 0x18, Flags);
            LE.WriteU16(buf, 0x1C, SaltLen);
            LE.WriteU16(buf, 0x1E, NonceLen);
            LE.WriteU64(buf, 0x20, PlaintextLen);
            LE.WriteU32(buf, 0x28, PlaintextCrc32);
            LE.WriteU32(buf, 0x2C, Subsystem);
            LE.WriteU32(buf, 0x30, Machine);
            LE.WriteU64(buf, 0x34, Timestamp);
            LE.WriteU32(buf, 0x3C, ExtLen);

            // 计算 CRC：覆盖 0x10..0x3F 共 48 字节
            uint crc = Crc32.Compute(buf, HeaderCrcCoverOffset, HeaderCrcCoverLen);
            LE.WriteU32(buf, 0x0C, crc);
            HeaderCrc32 = crc;
            return buf;
        }

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
    public sealed class PayloadFooter
    {
        public const int FooterCrcCoverLen = PayloadFormat.FooterSize - 4; // 28 字节

        public ulong PayloadLen;
        public uint FooterCrc32;

        public byte[] ToBytes()
        {
            var buf = new byte[PayloadFormat.FooterSize];
            LE.WriteU64(buf, 0x00, PayloadLen);
            LE.WriteU32(buf, 0x08, FooterCrc32);
            Buffer.BlockCopy(PayloadFormat.FooterMagicA, 0, buf, 0x0C, 8);
            Buffer.BlockCopy(PayloadFormat.FooterMagicB, 0, buf, 0x14, 8);
            LE.WriteU32(buf, 0x1C, 0);

            // 计算 CRC：覆盖除 crc32 字段以外的所有字节
            // 即 0x00..0x07 (payload_len) + 0x0C..0x1F (magic_a + magic_b + pad)
            var crcBuf = new byte[FooterCrcCoverLen];
            Buffer.BlockCopy(buf, 0x00, crcBuf, 0, 8);
            Buffer.BlockCopy(buf, 0x0C, crcBuf, 8, 20);
            uint crc = Crc32.Compute(crcBuf);
            LE.WriteU32(buf, 0x08, crc);
            FooterCrc32 = crc;
            return buf;
        }

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
