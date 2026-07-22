using System;
using WinAppLocker.Shared;
using Xunit;

namespace WinAppLocker.Shared.Tests
{
    public class PayloadHeaderTests
    {
        private static PayloadHeader MakeSample()
        {
            return new PayloadHeader
            {
                Version = PayloadFormat.PayloadVersion,
                HeaderSize = PayloadFormat.HeaderSize,
                AlgorithmId = PayloadFormat.AlgoAes256CbcHmacSha256,
                KdfId = PayloadFormat.KdfPbkdf2Sha256,
                KdfIterations = 100_000,
                Flags = PayloadFormat.FlagHasExtensions,
                SaltLen = 16,
                NonceLen = 16,
                PlaintextLen = 4096,
                PlaintextCrc32 = 0xDEADBEEFu,
                Subsystem = 2,
                Machine = 0x8664,
                Timestamp = 1700000000,
                ExtLen = 12
            };
        }

        [Fact]
        public void ToBytes_LengthIs64()
        {
            var h = MakeSample();
            byte[] buf = h.ToBytes();
            Assert.Equal(64, buf.Length);
        }

        [Fact]
        public void RoundTrip_AllFieldsPreserved()
        {
            var h = MakeSample();
            byte[] buf = h.ToBytes();
            var h2 = PayloadHeader.FromBytes(buf, 0);

            Assert.Equal(h.Version, h2.Version);
            Assert.Equal(h.HeaderSize, h2.HeaderSize);
            Assert.Equal(h.AlgorithmId, h2.AlgorithmId);
            Assert.Equal(h.KdfId, h2.KdfId);
            Assert.Equal(h.KdfIterations, h2.KdfIterations);
            Assert.Equal(h.Flags, h2.Flags);
            Assert.Equal(h.SaltLen, h2.SaltLen);
            Assert.Equal(h.NonceLen, h2.NonceLen);
            Assert.Equal(h.PlaintextLen, h2.PlaintextLen);
            Assert.Equal(h.PlaintextCrc32, h2.PlaintextCrc32);
            Assert.Equal(h.Subsystem, h2.Subsystem);
            Assert.Equal(h.Machine, h2.Machine);
            Assert.Equal(h.Timestamp, h2.Timestamp);
            Assert.Equal(h.ExtLen, h2.ExtLen);
        }

        [Fact]
        public void ToBytes_CrcIsFilled()
        {
            var h = MakeSample();
            h.HeaderCrc32 = 0;  // 故意置 0
            byte[] buf = h.ToBytes();
            // ToBytes 应该计算并填入 CRC
            Assert.NotEqual(0u, h.HeaderCrc32);
            // 头部 CRC 字段在偏移 0x0C
            uint crcInBuf = LE.ReadU32(buf, 0x0C);
            Assert.Equal(h.HeaderCrc32, crcInBuf);
        }

        [Fact]
        public void Crc_CoversOffset0x10To0x3F()
        {
            var h = MakeSample();
            byte[] buf = h.ToBytes();
            // CRC 应该覆盖 0x10..0x3F 共 48 字节
            uint expected = Crc32.Compute(buf, PayloadHeader.HeaderCrcCoverOffset, PayloadHeader.HeaderCrcCoverLen);
            Assert.Equal(expected, h.HeaderCrc32);
        }

        [Fact]
        public void FromBytes_MagicMismatch_Throws()
        {
            var h = MakeSample();
            byte[] buf = h.ToBytes();
            buf[0] = 0xFF;  // 破坏 magic
            Assert.Throws<InvalidOperationException>(() => PayloadHeader.FromBytes(buf, 0));
        }

        [Fact]
        public void FromBytes_CrcMismatch_Throws()
        {
            var h = MakeSample();
            byte[] buf = h.ToBytes();
            buf[0x10] ^= 0x01;  // 篡改 CRC 覆盖范围内的字段
            Assert.Throws<InvalidOperationException>(() => PayloadHeader.FromBytes(buf, 0));
        }

        [Fact]
        public void FromBytes_UnexpectedHeaderSize_Throws()
        {
            var h = MakeSample();
            byte[] buf = h.ToBytes();
            // 改 HeaderSize 字段（偏移 0x0A），同时重算 CRC 以通过 CRC 检查
            LE.WriteU16(buf, 0x0A, 32);
            uint crc = Crc32.Compute(buf, PayloadHeader.HeaderCrcCoverOffset, PayloadHeader.HeaderCrcCoverLen);
            LE.WriteU32(buf, 0x0C, crc);
            Assert.Throws<InvalidOperationException>(() => PayloadHeader.FromBytes(buf, 0));
        }

        [Fact]
        public void FromBytes_BufferTooSmall_Throws()
        {
            var buf = new byte[63];
            Assert.Throws<ArgumentException>(() => PayloadHeader.FromBytes(buf, 0));
        }

        [Fact]
        public void FromBytes_WithOffset_Works()
        {
            var h = MakeSample();
            byte[] buf = h.ToBytes();
            // 包在一个更大的 buffer 里，offset=10
            var big = new byte[10 + 64 + 10];
            Buffer.BlockCopy(buf, 0, big, 10, buf.Length);
            var h2 = PayloadHeader.FromBytes(big, 10);
            Assert.Equal(h.PlaintextLen, h2.PlaintextLen);
        }

        [Fact]
        public void NullBuffer_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => PayloadHeader.FromBytes(null, 0));
        }
    }

    public class PayloadFooterTests
    {
        [Fact]
        public void ToBytes_LengthIs32()
        {
            var f = new PayloadFooter { PayloadLen = 1000 };
            Assert.Equal(32, f.ToBytes().Length);
        }

        [Fact]
        public void RoundTrip()
        {
            var f = new PayloadFooter { PayloadLen = 0x123456789A };
            byte[] buf = f.ToBytes();
            var f2 = PayloadFooter.FromBytes(buf, 0);
            Assert.Equal(f.PayloadLen, f2.PayloadLen);
            Assert.Equal(f.FooterCrc32, f2.FooterCrc32);
        }

        [Fact]
        public void FromBytes_MagicAMismatch_Throws()
        {
            var f = new PayloadFooter { PayloadLen = 100 };
            byte[] buf = f.ToBytes();
            buf[0x0C] = 0xFF;  // 破坏 magic_a
            Assert.Throws<InvalidOperationException>(() => PayloadFooter.FromBytes(buf, 0));
        }

        [Fact]
        public void FromBytes_MagicBMismatch_Throws()
        {
            var f = new PayloadFooter { PayloadLen = 100 };
            byte[] buf = f.ToBytes();
            buf[0x14] = 0xFF;  // 破坏 magic_b
            Assert.Throws<InvalidOperationException>(() => PayloadFooter.FromBytes(buf, 0));
        }

        [Fact]
        public void FromBytes_CrcMismatch_Throws()
        {
            var f = new PayloadFooter { PayloadLen = 100 };
            byte[] buf = f.ToBytes();
            buf[0] ^= 0x01;  // 篡改 PayloadLen 字段
            Assert.Throws<InvalidOperationException>(() => PayloadFooter.FromBytes(buf, 0));
        }

        [Fact]
        public void BufferTooSmall_Throws()
        {
            Assert.Throws<ArgumentException>(() => PayloadFooter.FromBytes(new byte[31], 0));
        }

        [Fact]
        public void NullBuffer_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => PayloadFooter.FromBytes(null, 0));
        }
    }

    public class PayloadFormatTests
    {
        [Fact]
        public void HeaderMagic_Length8()
        {
            Assert.Equal(8, PayloadFormat.HeaderMagic.Length);
        }

        [Fact]
        public void HeaderMagic_Value()
        {
            byte[] expected = { (byte)'W', (byte)'A', (byte)'L', (byte)'O', (byte)'C', (byte)'K', 0x01, 0x00 };
            Assert.Equal(expected, PayloadFormat.HeaderMagic);
        }

        [Fact]
        public void FooterMagic_Length8()
        {
            Assert.Equal(8, PayloadFormat.FooterMagicA.Length);
            Assert.Equal(8, PayloadFormat.FooterMagicB.Length);
        }

        [Fact]
        public void Sizes()
        {
            Assert.Equal(64, PayloadFormat.HeaderSize);
            Assert.Equal(32, PayloadFormat.FooterSize);
        }

        [Fact]
        public void VersionBlobMarkers()
        {
            Assert.Equal("WAL_VER|", PayloadFormat.VersionBlobStart);
            Assert.Equal("|WAL_END", PayloadFormat.VersionBlobEnd);
        }
    }
}
