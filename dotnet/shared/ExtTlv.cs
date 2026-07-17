using System;
using System.Collections.Generic;

namespace WinAppLocker.Shared
{
    /// <summary>
    /// Extension TLV 区域读写工具。
    /// 格式：连续的 [tag:2][len:2][value:len] 条目。
    /// 放在 Ciphertext 之后、Footer 之前。
    /// </summary>
    public static class ExtTlv
    {
        /// <summary>编码一个 TLV 条目。</summary>
        public static byte[] EncodeEntry(ushort tag, byte[] value)
        {
            if (value == null) value = new byte[0];
            var buf = new byte[4 + value.Length];
            LE.WriteU16(buf, 0, tag);
            LE.WriteU16(buf, 2, (ushort)value.Length);
            Buffer.BlockCopy(value, 0, buf, 4, value.Length);
            return buf;
        }

        /// <summary>编码一个字符串 TLV 条目（UTF-8）。</summary>
        public static byte[] EncodeString(ushort tag, string value)
        {
            return EncodeEntry(tag, System.Text.Encoding.UTF8.GetBytes(value ?? ""));
        }

        /// <summary>编码一个 u64 TLV 条目（小端序 8 字节）。</summary>
        public static byte[] EncodeU64(ushort tag, ulong value)
        {
            var buf = new byte[8];
            LE.WriteU64(buf, 0, value);
            return EncodeEntry(tag, buf);
        }

        /// <summary>从 TLV 列表中查找第一个匹配 tag 的 u64 值。</summary>
        public static ulong? FindU64(List<KeyValuePair<ushort, byte[]>> list, ushort tag)
        {
            foreach (var kv in list)
            {
                if (kv.Key == tag && kv.Value != null && kv.Value.Length == 8)
                    return LE.ReadU64(kv.Value, 0);
            }
            return null;
        }

        /// <summary>解析 TLV 区域，返回 (tag, value) 列表。</summary>
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

        /// <summary>从 TLV 列表中查找第一个匹配 tag 的字符串值。</summary>
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
}
