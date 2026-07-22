using System;
using System.Collections.Generic;
using WinAppLocker.Shared;
using Xunit;

namespace WinAppLocker.Shared.Tests
{
    public class ExtTlvTests
    {
        [Fact]
        public void EncodeEntry_LengthIs4PlusValue()
        {
            byte[] value = { 0x01, 0x02, 0x03 };
            byte[] entry = ExtTlv.EncodeEntry(5, value);
            Assert.Equal(7, entry.Length);
        }

        [Fact]
        public void EncodeEntry_TagAndLenCorrect()
        {
            byte[] value = { 0xAA, 0xBB };
            byte[] entry = ExtTlv.EncodeEntry(0x1234, value);
            Assert.Equal(0x1234, LE.ReadU16(entry, 0));
            Assert.Equal(2, LE.ReadU16(entry, 2));
        }

        [Fact]
        public void EncodeEntry_NullValueTreatedAsEmpty()
        {
            byte[] entry = ExtTlv.EncodeEntry(1, null);
            Assert.Equal(4, entry.Length);
            Assert.Equal(0, LE.ReadU16(entry, 2));
        }

        [Fact]
        public void EncodeString_Utf8()
        {
            byte[] entry = ExtTlv.EncodeString(1, "hello");
            Assert.Equal(4 + 5, entry.Length);
            // UTF-8 "hello" 就是 ASCII 字节
            Assert.Equal((byte)'h', entry[4]);
            Assert.Equal((byte)'o', entry[8]);
        }

        [Fact]
        public void EncodeString_Chinese()
        {
            // "中" 的 UTF-8 是 3 字节
            byte[] entry = ExtTlv.EncodeString(1, "中");
            Assert.Equal(4 + 3, entry.Length);
            byte[] expectedUtf8 = System.Text.Encoding.UTF8.GetBytes("中");
            Assert.Equal(expectedUtf8[0], entry[4]);
            Assert.Equal(expectedUtf8[1], entry[5]);
            Assert.Equal(expectedUtf8[2], entry[6]);
        }

        [Fact]
        public void EncodeU64_8BytesLittleEndian()
        {
            byte[] entry = ExtTlv.EncodeU64(3, 0x0123456789ABCDEFuL);
            Assert.Equal(4 + 8, entry.Length);
            // 小端低字节在前
            Assert.Equal(0xEF, entry[4]);
            Assert.Equal(0xCD, entry[5]);
            Assert.Equal(0x01, entry[11]);
        }

        [Fact]
        public void Parse_SingleEntry()
        {
            byte[] value = { 0xAA, 0xBB };
            byte[] buf = ExtTlv.EncodeEntry(5, value);
            var list = ExtTlv.Parse(buf, 0, buf.Length);
            Assert.Single(list);
            Assert.Equal(5, list[0].Key);
            Assert.Equal(value, list[0].Value);
        }

        [Fact]
        public void Parse_MultipleEntries()
        {
            byte[] a = ExtTlv.EncodeString(1, "name");
            byte[] b = ExtTlv.EncodeU64(3, 100);
            byte[] buf = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, buf, 0, a.Length);
            Buffer.BlockCopy(b, 0, buf, a.Length, b.Length);
            var list = ExtTlv.Parse(buf, 0, buf.Length);
            Assert.Equal(2, list.Count);
            Assert.Equal(1, list[0].Key);
            Assert.Equal(3, list[1].Key);
        }

        [Fact]
        public void Parse_EmptyBuffer_ReturnsEmptyList()
        {
            var list = ExtTlv.Parse(new byte[0], 0, 0);
            Assert.Empty(list);
        }

        [Fact]
        public void Parse_TruncatedEntry_StopsGracefully()
        {
            // 只有 4 字节头但声明 len=10，总长不足
            byte[] buf = new byte[4];
            LE.WriteU16(buf, 0, 1);
            LE.WriteU16(buf, 2, 10);
            var list = ExtTlv.Parse(buf, 0, buf.Length);
            Assert.Empty(list);
        }

        [Fact]
        public void FindString_HitAndMiss()
        {
            var list = new List<KeyValuePair<ushort, byte[]>>
            {
                new KeyValuePair<ushort, byte[]>(1, System.Text.Encoding.UTF8.GetBytes("hello")),
                new KeyValuePair<ushort, byte[]>(3, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 })
            };
            Assert.Equal("hello", ExtTlv.FindString(list, 1));
            Assert.Null(ExtTlv.FindString(list, 99));
        }

        [Fact]
        public void FindU64_HitAndMiss()
        {
            var list = new List<KeyValuePair<ushort, byte[]>>
            {
                new KeyValuePair<ushort, byte[]>(3, new byte[] { 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01 })
            };
            Assert.Equal(0x0123456789ABCDEFuL, ExtTlv.FindU64(list, 3));
            Assert.Null(ExtTlv.FindU64(list, 99));
        }

        [Fact]
        public void FindU64_WrongLength_ReturnsNull()
        {
            var list = new List<KeyValuePair<ushort, byte[]>>
            {
                new KeyValuePair<ushort, byte[]>(3, new byte[] { 1, 2, 3 })  // 长度不是 8
            };
            Assert.Null(ExtTlv.FindU64(list, 3));
        }

        [Fact]
        public void FindString_ReturnsFirstMatch_WhenDuplicate()
        {
            var list = new List<KeyValuePair<ushort, byte[]>>
            {
                new KeyValuePair<ushort, byte[]>(1, System.Text.Encoding.UTF8.GetBytes("first")),
                new KeyValuePair<ushort, byte[]>(1, System.Text.Encoding.UTF8.GetBytes("second"))
            };
            Assert.Equal("first", ExtTlv.FindString(list, 1));
        }
    }

    public class ByteSearchTests
    {
        [Fact]
        public void NormalMatch()
        {
            byte[] buf = { 0x01, 0x02, 0x03, 0x04, 0x05 };
            byte[] sub = { 0x03, 0x04 };
            Assert.Equal(2, ByteSearch.IndexOf(buf, sub));
        }

        [Fact]
        public void NotFound_ReturnsMinus1()
        {
            byte[] buf = { 0x01, 0x02, 0x03 };
            byte[] sub = { 0x05 };
            Assert.Equal(-1, ByteSearch.IndexOf(buf, sub));
        }

        [Fact]
        public void MultipleOccurrences_ReturnsFirst()
        {
            byte[] buf = { 0x10, 0x20, 0x10, 0x20, 0x10 };
            byte[] sub = { 0x10 };
            Assert.Equal(0, ByteSearch.IndexOf(buf, sub));
        }

        [Fact]
        public void EmptySub_ReturnsMinus1()
        {
            byte[] buf = { 0x01 };
            Assert.Equal(-1, ByteSearch.IndexOf(buf, new byte[0]));
            Assert.Equal(-1, ByteSearch.IndexOf(buf, null));
        }

        [Fact]
        public void BufferShorterThanSub_ReturnsMinus1()
        {
            byte[] buf = { 0x01 };
            byte[] sub = { 0x01, 0x02 };
            Assert.Equal(-1, ByteSearch.IndexOf(buf, sub));
        }

        [Fact]
        public void StartBeyondBuffer_ReturnsMinus1()
        {
            byte[] buf = { 0x01, 0x02, 0x03 };
            byte[] sub = { 0x01 };
            Assert.Equal(-1, ByteSearch.IndexOf(buf, sub, 100));
        }

        [Fact]
        public void WithStart_FindsAfterStart()
        {
            byte[] buf = { 0xAA, 0xBB, 0xAA, 0xCC };
            byte[] sub = { 0xAA, 0xCC };
            Assert.Equal(2, ByteSearch.IndexOf(buf, sub, 1));
        }

        [Fact]
        public void WithLength_LimitsRange()
        {
            // buf[0..4) 包含 sub，但 length=2 时找不到
            byte[] buf = { 0x10, 0x20, 0x30, 0x40 };
            byte[] sub = { 0x30, 0x40 };
            Assert.Equal(2, ByteSearch.IndexOf(buf, sub, 0, 4));
            Assert.Equal(-1, ByteSearch.IndexOf(buf, sub, 0, 2));
        }

        [Fact]
        public void SingleByteMatch()
        {
            byte[] buf = { 0x01, 0x02, 0x03 };
            Assert.Equal(1, ByteSearch.IndexOf(buf, new byte[] { 0x02 }));
        }

        [Fact]
        public void FullMatch_AtBufferEnd()
        {
            byte[] buf = { 0x01, 0x02, 0x03 };
            byte[] sub = { 0x02, 0x03 };
            Assert.Equal(1, ByteSearch.IndexOf(buf, sub));
        }

        [Fact]
        public void FullMatch_WholeBuffer()
        {
            byte[] buf = { 0x01, 0x02, 0x03 };
            byte[] sub = { 0x01, 0x02, 0x03 };
            Assert.Equal(0, ByteSearch.IndexOf(buf, sub));
        }
    }
}
