using System;
using System.Security.Cryptography;
using System.Text;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// packer 端加密：PBKDF2-HMAC-SHA256 + AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)。
    /// 与 stub CryptoUtil 完全一致的字节格式，但代码独立（设计文档要求 stub 与 packer 不共享代码）。
    /// </summary>
    internal static class CryptoUtil
    {
        // ---- PBKDF2-HMAC-SHA256 ----
        public static byte[] DeriveKey(string password, byte[] salt, int iterations)
        {
            byte[] pwBytes = Encoding.UTF8.GetBytes(password);
            byte[] key = PBKDF2_SHA256(pwBytes, salt, iterations, PayloadFormat.AesKeyLen);
            for (int i = 0; i < pwBytes.Length; i++) pwBytes[i] = 0;
            return key;
        }

        private static byte[] PBKDF2_SHA256(byte[] password, byte[] salt, int iterations, int dkLen)
        {
            const int hashLen = 32;
            int blocks = (dkLen + hashLen - 1) / hashLen;
            var dk = new byte[blocks * hashLen];
            var saltBlock = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltBlock, 0, salt.Length);

            using (var hmac = new HMACSHA256(password))
            {
                // 复用 t 缓冲区避免每次迭代 alloc（600K 次 * 32B = 大量 GC 压力）
                byte[] t = new byte[hashLen];
                for (int i = 1; i <= blocks; i++)
                {
                    saltBlock[salt.Length + 0] = (byte)(i >> 24);
                    saltBlock[salt.Length + 1] = (byte)(i >> 16);
                    saltBlock[salt.Length + 2] = (byte)(i >> 8);
                    saltBlock[salt.Length + 3] = (byte)i;

                    byte[] u = hmac.ComputeHash(saltBlock);
                    Buffer.BlockCopy(u, 0, t, 0, hashLen);
                    for (int j = 1; j < iterations; j++)
                    {
                        u = hmac.ComputeHash(u);
                        for (int k = 0; k < hashLen; k++) t[k] ^= u[k];
                    }
                    Buffer.BlockCopy(t, 0, dk, (i - 1) * hashLen, hashLen);
                }
            }
            var result = new byte[dkLen];
            Buffer.BlockCopy(dk, 0, result, 0, dkLen);
            return result;
        }

        // ---- AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) ----
        // 输出格式：[IV (16)] [AES_CBC ciphertext (padded to 16)] [HMAC tag (32)]
        // HMAC 覆盖：IV + AES_CBC ciphertext

        public static byte[] EncryptAesCbcHmac(byte[] key, byte[] iv, byte[] plaintext)
        {
            if (key == null || key.Length != PayloadFormat.AesKeyLen)
                throw new ArgumentException("invalid key length");
            if (iv == null || iv.Length != PayloadFormat.AesCbcIvLen)
                throw new ArgumentException("invalid iv length");

            byte[] encKey, macKey;
            SplitKey(key, out encKey, out macKey);

            // 加密 AES-CBC
            byte[] cipher;
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = encKey;
                aes.IV = iv;
                using (var enc = aes.CreateEncryptor())
                {
                    cipher = enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
                }
            }

            // HMAC over iv + ciphertext
            byte[] macInput = new byte[iv.Length + cipher.Length];
            Buffer.BlockCopy(iv, 0, macInput, 0, iv.Length);
            Buffer.BlockCopy(cipher, 0, macInput, iv.Length, cipher.Length);
            byte[] mac;
            using (var hmac = new HMACSHA256(macKey))
            {
                mac = hmac.ComputeHash(macInput);
            }

            // 拼接: cipher || mac
            var result = new byte[cipher.Length + mac.Length];
            Buffer.BlockCopy(cipher, 0, result, 0, cipher.Length);
            Buffer.BlockCopy(mac, 0, result, cipher.Length, mac.Length);
            return result;
        }

        /// <summary>
        /// 生成密码学安全的随机字节。使用 RNGCryptoServiceProvider (.NET 4.7.2 原生)。
        /// </summary>
        public static byte[] RandomBytes(int len)
        {
            var buf = new byte[len];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(buf);
            }
            return buf;
        }

        private static void SplitKey(byte[] key, out byte[] encKey, out byte[] macKey)
        {
            using (var sha = SHA256.Create())
            {
                var buf1 = new byte[key.Length + 1];
                Buffer.BlockCopy(key, 0, buf1, 0, key.Length);
                buf1[key.Length] = 0x01;
                encKey = sha.ComputeHash(buf1);

                var buf2 = new byte[key.Length + 1];
                Buffer.BlockCopy(key, 0, buf2, 0, key.Length);
                buf2[key.Length] = 0x02;
                macKey = sha.ComputeHash(buf2);
            }
        }
    }
}
