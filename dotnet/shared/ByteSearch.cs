using System;
// 字节模式查找 - packer 用于在 stub 字节中搜索 WAL_VER 标记
namespace WinAppLocker.Shared
{
    public static class ByteSearch
    {
        /// <summary>在 buf 中查找 sub 的第一次出现位置，找不到返回 -1。</summary>
        public static int IndexOf(byte[] buf, byte[] sub, int start = 0)
        {
            if (sub == null || sub.Length == 0) return -1;
            if (buf == null || buf.Length < sub.Length) return -1;

            int limit = buf.Length - sub.Length;
            for (int i = start; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < sub.Length; j++)
                {
                    if (buf[i + j] != sub[j]) { match = false; break; }
                }
                if (match) return i;
            }
            return -1;
        }

        /// <summary>在 buf[0..length) 范围内查找 sub 的第一次出现位置，找不到返回 -1。</summary>
        public static int IndexOf(byte[] buf, byte[] sub, int start, int length)
        {
            if (sub == null || sub.Length == 0) return -1;
            if (buf == null || length < sub.Length) return -1;

            int limit = Math.Min(buf.Length, length) - sub.Length;
            for (int i = start; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < sub.Length; j++)
                {
                    if (buf[i + j] != sub[j]) { match = false; break; }
                }
                if (match) return i;
            }
            return -1;
        }
    }
}
