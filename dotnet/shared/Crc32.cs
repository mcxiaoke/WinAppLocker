using System;
// CRC32 (IEEE 802.3 多项式 0xEDB88320)
// 用于 header / footer / plaintext 完整性校验
namespace WinAppLocker.Shared
{
    public static class Crc32
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

        public static uint Compute(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            return Compute(data, 0, data.Length);
        }
    }

    /// <summary>小端序读写辅助。</summary>
    public static class LE
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
}
