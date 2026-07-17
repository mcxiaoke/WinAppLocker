using System;
using System.IO;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// 组装 payload 二进制：
    ///   [Header 64] [Salt] [Nonce] [Ciphertext + MAC] [Extension TLV] [Footer 32]
    /// </summary>
    internal static class PayloadBuilder
    {
        public class BuildInput
        {
            public byte[] Salt;
            public byte[] Nonce;            // AES-CBC IV (16)
            public byte[] CipherWithMac;     // [AES_CBC ciphertext (padded)] + [HMAC tag (32)]
            public int KdfIterations;
            public ulong PlaintextLen;       // 原 EXE 字节长度
            public uint PlaintextCrc32;      // 原 EXE CRC32
            public uint Subsystem;           // 原 EXE 子系统
            public uint Machine;             // 原 EXE 机器类型
            public ulong Timestamp;          // 打包时间（unix epoch 秒）
            public string OriginalName;      // 原 EXE 文件名（不含路径）
            public string PackerVersion;     // 打包器版本签名
            public ulong OriginalSize;       // 原始文件大小（冗余校验，与 PlaintextLen 一致）
        }

        /// <summary>组装 payload 字节。</summary>
        public static byte[] Build(BuildInput input)
        {
            if (input.Salt == null) throw new ArgumentException("Salt required");
            if (input.Nonce == null || input.Nonce.Length != PayloadFormat.AesCbcIvLen)
                throw new ArgumentException("invalid nonce");
            if (input.CipherWithMac == null) throw new ArgumentException("ciphertext required");

            // 构建 Extension TLV 区域
            byte[] extBytes = BuildExtensions(input);
            uint extLen = (uint)extBytes.Length;

            int payloadLen = PayloadFormat.HeaderSize
                            + input.Salt.Length
                            + input.Nonce.Length
                            + input.CipherWithMac.Length
                            + extBytes.Length;

            var result = new byte[payloadLen + PayloadFormat.FooterSize];

            // 1. Header
            uint flags = extLen > 0 ? PayloadFormat.FlagHasExtensions : 0;
            var header = new PayloadHeader
            {
                Version = PayloadFormat.PayloadVersion,
                HeaderSize = PayloadFormat.HeaderSize,
                AlgorithmId = PayloadFormat.AlgoAes256CbcHmacSha256,
                KdfId = PayloadFormat.KdfPbkdf2Sha256,
                KdfIterations = (uint)input.KdfIterations,
                Flags = flags,
                SaltLen = (ushort)input.Salt.Length,
                NonceLen = (ushort)input.Nonce.Length,
                PlaintextLen = input.PlaintextLen,
                PlaintextCrc32 = input.PlaintextCrc32,
                Subsystem = input.Subsystem,
                Machine = input.Machine,
                Timestamp = input.Timestamp,
                ExtLen = extLen
            };
            byte[] headerBytes = header.ToBytes();
            Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);

            // 2. Salt
            int cursor = PayloadFormat.HeaderSize;
            Buffer.BlockCopy(input.Salt, 0, result, cursor, input.Salt.Length);
            cursor += input.Salt.Length;

            // 3. Nonce
            Buffer.BlockCopy(input.Nonce, 0, result, cursor, input.Nonce.Length);
            cursor += input.Nonce.Length;

            // 4. Ciphertext + MAC
            Buffer.BlockCopy(input.CipherWithMac, 0, result, cursor, input.CipherWithMac.Length);
            cursor += input.CipherWithMac.Length;

            // 5. Extension TLV
            if (extBytes.Length > 0)
            {
                Buffer.BlockCopy(extBytes, 0, result, cursor, extBytes.Length);
                cursor += extBytes.Length;
            }

            // 6. Footer
            var footer = new PayloadFooter
            {
                PayloadLen = (ulong)payloadLen
            };
            byte[] footerBytes = footer.ToBytes();
            Buffer.BlockCopy(footerBytes, 0, result, cursor, footerBytes.Length);

            return result;
        }

        /// <summary>构建 Extension TLV 字节流。</summary>
        private static byte[] BuildExtensions(BuildInput input)
        {
            using (var ms = new MemoryStream())
            {
                // Tag 1: 原始文件名（UTF-8，不含路径）
                if (!string.IsNullOrEmpty(input.OriginalName))
                {
                    byte[] entry = ExtTlv.EncodeString(PayloadFormat.ExtTagOriginalName, input.OriginalName);
                    ms.Write(entry, 0, entry.Length);
                }

                // Tag 2: 打包器版本签名（UTF-8，如 "WinAppLocker v0.1.0"）
                if (!string.IsNullOrEmpty(input.PackerVersion))
                {
                    byte[] entry = ExtTlv.EncodeString(PayloadFormat.ExtTagPackerVersion, input.PackerVersion);
                    ms.Write(entry, 0, entry.Length);
                }

                // Tag 3: 原始文件大小（u64，与 PlaintextLen 冗余但可用于独立校验）
                if (input.OriginalSize > 0)
                {
                    byte[] entry = ExtTlv.EncodeU64(PayloadFormat.ExtTagOriginalSize, input.OriginalSize);
                    ms.Write(entry, 0, entry.Length);
                }

                return ms.ToArray();
            }
        }
    }
}
