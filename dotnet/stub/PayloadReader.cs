using System;
using System.Collections.Generic;

namespace WinAppLocker.Stub
{
    /// <summary>
    /// 从自身 exe 末尾解析 payload。
    /// payload 结构：
    ///   [Header 64] [Salt] [Nonce] [Ciphertext + MAC] [Extension TLV] [Footer 32]
    /// stub 从文件末尾读 footer 反向定位 header 起点。
    /// </summary>
    internal sealed class PayloadReader
    {
        public PayloadHeader Header;
        public byte[] Salt;
        public byte[] Nonce;        // AES-CBC IV
        public byte[] CipherWithMac; // [AES_CBC ciphertext (padded)] + [HMAC tag (32 bytes)]
        public List<KeyValuePair<ushort, byte[]>> Extensions; // Extension TLV 条目

        /// <summary>从 exe 字节中解析 payload。失败抛异常。</summary>
        public static PayloadReader Parse(byte[] selfBytes)
        {
            if (selfBytes == null) throw new ArgumentNullException(nameof(selfBytes));
            if (selfBytes.Length < PayloadFormat.HeaderSize + PayloadFormat.FooterSize)
                throw new InvalidOperationException("file too small to contain payload");

            // 1. 从末尾读 footer
            int footerOff = selfBytes.Length - PayloadFormat.FooterSize;
            var footer = PayloadFooter.FromBytes(selfBytes, footerOff);

            // 2. 反向定位 header 起点
            long headerOff = (long)selfBytes.Length - PayloadFormat.FooterSize - (long)footer.PayloadLen;
            if (headerOff < 0 || headerOff > selfBytes.Length)
                throw new InvalidOperationException("invalid payload_len");

            // 3. 解析 header
            var header = PayloadHeader.FromBytes(selfBytes, (int)headerOff);
            if (header.Version != PayloadFormat.PayloadVersion)
                throw new InvalidOperationException($"unsupported payload version {header.Version}");
            if (header.AlgorithmId != PayloadFormat.AlgoAes256CbcHmacSha256)
                throw new InvalidOperationException($"unsupported algorithm {header.AlgorithmId}");
            if (header.KdfId != PayloadFormat.KdfPbkdf2Sha256)
                throw new InvalidOperationException($"unsupported kdf {header.KdfId}");

            // 4. 读取 salt / nonce / ciphertext / extensions
            int cursor = (int)headerOff + PayloadFormat.HeaderSize;
            int saltLen = header.SaltLen;
            int nonceLen = header.NonceLen;
            if (nonceLen != PayloadFormat.AesCbcIvLen)
                throw new InvalidOperationException("unexpected nonce_len");

            int extLen = (int)header.ExtLen;
            if (cursor + saltLen + nonceLen + extLen > footerOff)
                throw new InvalidOperationException("payload truncated");

            byte[] salt = new byte[saltLen];
            Buffer.BlockCopy(selfBytes, cursor, salt, 0, saltLen);
            cursor += saltLen;

            byte[] nonce = new byte[nonceLen];
            Buffer.BlockCopy(selfBytes, cursor, nonce, 0, nonceLen);
            cursor += nonceLen;

            // ciphertext = footerOff - extLen - cursor
            int cipherLen = footerOff - extLen - cursor;
            if (cipherLen < PayloadFormat.HmacSha256TagLen)
                throw new InvalidOperationException("ciphertext too small");
            byte[] cipherWithMac = new byte[cipherLen];
            Buffer.BlockCopy(selfBytes, cursor, cipherWithMac, 0, cipherLen);
            cursor += cipherLen;

            // Extension TLV
            List<KeyValuePair<ushort, byte[]>> extensions = null;
            if (extLen > 0)
            {
                extensions = ExtTlv.Parse(selfBytes, cursor, extLen);
            }

            return new PayloadReader
            {
                Header = header,
                Salt = salt,
                Nonce = nonce,
                CipherWithMac = cipherWithMac,
                Extensions = extensions
            };
        }

        /// <summary>从 Extension TLV 中获取原始文件名，找不到返回 null。</summary>
        public string GetOriginalName()
        {
            if (Extensions == null) return null;
            return ExtTlv.FindString(Extensions, PayloadFormat.ExtTagOriginalName);
        }
    }
}
