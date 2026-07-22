using System;
using WinAppLocker.Shared;
using Xunit;

namespace WinAppLocker.Shared.Tests
{
    public class Crc32Tests
    {
        [Fact]
        public void Empty_ReturnsZero()
        {
            Assert.Equal(0u, Crc32.Compute(new byte[0]));
        }

        [Fact]
        public void StandardVector_123456789_Returns0xCBF43926()
        {
            // IEEE 802.3 标准测试向量 "123456789"
            byte[] data = System.Text.Encoding.ASCII.GetBytes("123456789");
            Assert.Equal(0xCBF43926u, Crc32.Compute(data));
        }

        [Fact]
        public void StandardVector_AsciiA_Returns0xE8B7BE43()
        {
            // "a" → CRC32 = 0xE8B7BE43
            byte[] data = System.Text.Encoding.ASCII.GetBytes("a");
            Assert.Equal(0xE8B7BE43u, Crc32.Compute(data));
        }

        [Fact]
        public void Slice_EqualsSubstring()
        {
            // Compute(data, offset, length) 应等于子数组 Compute
            byte[] data = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
            byte[] slice = { 0x30, 0x40, 0x50 };
            Assert.Equal(Crc32.Compute(slice), Crc32.Compute(data, 2, 3));
        }

        [Fact]
        public void NullData_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => Crc32.Compute(null));
            Assert.Throws<ArgumentNullException>(() => Crc32.Compute(null, 0, 0));
        }

        [Fact]
        public void SingleByte_RoundTrip()
        {
            byte[] data = { 0xAB };
            uint expected = Crc32.Compute(data);
            Assert.Equal(expected, Crc32.Compute(data, 0, 1));
        }
    }

    public class LeTests
    {
        [Fact]
        public void U16_RoundTrip()
        {
            var buf = new byte[2];
            LE.WriteU16(buf, 0, 0xCAFE);
            Assert.Equal(0xCAFE, LE.ReadU16(buf, 0));
        }

        [Fact]
        public void U16_LittleEndian()
        {
            var buf = new byte[2];
            LE.WriteU16(buf, 0, 0x0102);
            // 小端：低字节在前
            Assert.Equal(0x02, buf[0]);
            Assert.Equal(0x01, buf[1]);
        }

        [Fact]
        public void U32_RoundTrip()
        {
            var buf = new byte[4];
            LE.WriteU32(buf, 0, 0xDEADBEEFu);
            Assert.Equal(0xDEADBEEFu, LE.ReadU32(buf, 0));
        }

        [Fact]
        public void U32_LittleEndian()
        {
            var buf = new byte[4];
            LE.WriteU32(buf, 0, 0x01020304);
            Assert.Equal(0x04, buf[0]);
            Assert.Equal(0x03, buf[1]);
            Assert.Equal(0x02, buf[2]);
            Assert.Equal(0x01, buf[3]);
        }

        [Fact]
        public void U64_RoundTrip()
        {
            var buf = new byte[8];
            ulong val = 0x0123456789ABCDEFu;
            LE.WriteU64(buf, 0, val);
            Assert.Equal(val, LE.ReadU64(buf, 0));
        }

        [Fact]
        public void U64_AllZero()
        {
            var buf = new byte[8];
            LE.WriteU64(buf, 0, 0);
            Assert.Equal(0uL, LE.ReadU64(buf, 0));
            for (int i = 0; i < 8; i++) Assert.Equal(0, buf[i]);
        }

        [Fact]
        public void U64_AllOnes()
        {
            var buf = new byte[8];
            LE.WriteU64(buf, 0, 0xFFFFFFFFFFFFFFFFuL);
            Assert.Equal(0xFFFFFFFFFFFFFFFFuL, LE.ReadU64(buf, 0));
            for (int i = 0; i < 8; i++) Assert.Equal(0xFF, buf[i]);
        }

        [Fact]
        public void OffsetReadWrite()
        {
            var buf = new byte[32];
            LE.WriteU16(buf, 4, 0x1111);
            LE.WriteU32(buf, 8, 0x22222222);
            LE.WriteU64(buf, 16, 0x3333333333333333);
            Assert.Equal(0x1111, LE.ReadU16(buf, 4));
            Assert.Equal(0x22222222u, LE.ReadU32(buf, 8));
            Assert.Equal(0x3333333333333333uL, LE.ReadU64(buf, 16));
        }
    }
}
