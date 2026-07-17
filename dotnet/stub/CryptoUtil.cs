using System;
using System.Security.Cryptography;
using System.Text;

namespace WinAppLocker.Stub
{
    /// <summary>
    /// 加密原语：PBKDF2-HMAC-SHA256 + AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)。
    /// 完全使用 .NET Framework 4.7.2 原生 API，不依赖任何第三方库。
    /// </summary>
    internal static class CryptoUtil
    {
        // ---- PBKDF2-HMAC-SHA256 (手动实现，原生 .NET 4.7.2 的 Rfc2898DeriveBytes 默认 HMACSHA1) ----

        /// <summary>派生 AES-256 密钥 (32 字节)。</summary>
        public static byte[] DeriveKey(string password, byte[] salt, int iterations)
        {
            byte[] pwBytes = Encoding.UTF8.GetBytes(password);
            byte[] encKey = PBKDF2_SHA256(pwBytes, salt, iterations, PayloadFormat.AesKeyLen);
            // 清零密码字节
            for (int i = 0; i < pwBytes.Length; i++) pwBytes[i] = 0;
            return encKey;
        }

        /// <summary>
        /// 手动实现的 PBKDF2-HMAC-SHA256。
        /// .NET Framework 4.7.2 的 Rfc2898DeriveBytes 默认使用 HMACSHA1，无法切换到 SHA256；
        /// 这里直接实现 RFC 2898，使用 HMACSHA256。
        /// 优化：复用缓冲区避免每次迭代 alloc 新字节数组（600K 次 * 32B = 大量 GC 压力）。
        /// </summary>
        private static byte[] PBKDF2_SHA256(byte[] password, byte[] salt, int iterations, int dkLen)
        {
            const int hashLen = 32; // SHA-256 输出
            int blocks = (dkLen + hashLen - 1) / hashLen;
            var dk = new byte[blocks * hashLen];
            var saltBlock = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltBlock, 0, salt.Length);

            using (var hmac = new HMACSHA256(password))
            {
                // 复用 u / t 缓冲区，避免每次 ComputeHash 返回新数组
                // 但 HMACSHA256.ComputeHash 总是返回新数组，无法避免；
                // 关键优化：t 数组只 alloc 一次，把 u 直接 XOR 到 t 上
                byte[] t = new byte[hashLen];
                for (int i = 1; i <= blocks; i++)
                {
                    saltBlock[salt.Length + 0] = (byte)(i >> 24);
                    saltBlock[salt.Length + 1] = (byte)(i >> 16);
                    saltBlock[salt.Length + 2] = (byte)(i >> 8);
                    saltBlock[salt.Length + 3] = (byte)i;

                    // U_1 = HMAC(password, salt || INT(i))
                    byte[] u = hmac.ComputeHash(saltBlock);
                    Buffer.BlockCopy(u, 0, t, 0, hashLen);

                    // U_2 .. U_c: t ^= U_j
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
        // 密文格式：[IV (16 bytes)] [AES_CBC ciphertext (padded to 16)] [HMAC tag (32 bytes)]
        // HMAC 覆盖：IV + AES_CBC ciphertext (不包含 MAC 自身)

        /// <summary>
        /// 解密 payload 字段。返回 null 表示 MAC 校验失败（密码错误或数据被篡改）。
        /// </summary>
        public static byte[] DecryptAesCbcHmac(byte[] key, byte[] iv, byte[] cipherWithMac)
        {
            if (key == null || key.Length != PayloadFormat.AesKeyLen)
                throw new ArgumentException("invalid key length");
            if (iv == null || iv.Length != PayloadFormat.AesCbcIvLen)
                throw new ArgumentException("invalid iv length");
            if (cipherWithMac == null || cipherWithMac.Length < PayloadFormat.HmacSha256TagLen)
                return null;

            int macLen = PayloadFormat.HmacSha256TagLen;
            int cipherLen = cipherWithMac.Length - macLen;
            byte[] mac = new byte[macLen];
            Buffer.BlockCopy(cipherWithMac, cipherLen, mac, 0, macLen);

            // 计算 HMAC: key 派生为 encKey + macKey
            byte[] encKey, macKey;
            SplitKey(key, out encKey, out macKey);

            // HMAC 覆盖 IV + ciphertext
            using (var hmac = new HMACSHA256(macKey))
            {
                // 构造待认证数据：iv || ciphertext
                var macInput = new byte[iv.Length + cipherLen];
                Buffer.BlockCopy(iv, 0, macInput, 0, iv.Length);
                Buffer.BlockCopy(cipherWithMac, 0, macInput, iv.Length, cipherLen);
                byte[] expectedMac = hmac.ComputeHash(macInput);

                if (!ConstantTimeEquals(mac, expectedMac))
                    return null;
            }

            // 解密 AES-CBC
            byte[] cipher = new byte[cipherLen];
            Buffer.BlockCopy(cipherWithMac, 0, cipher, 0, cipherLen);

            try
            {
                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = encKey;
                    aes.IV = iv;
                    using (var dec = aes.CreateDecryptor())
                    {
                        return dec.TransformFinalBlock(cipher, 0, cipher.Length);
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        /// <summary>把 32 字节密钥拆成 encKey (32) 和 macKey (32)。
        /// 使用 HKDF-Expand 思路：把原 32 字节做 PBKDF2 派生 64 字节，前 32 作 encKey，后 32 作 macKey。
        /// 但为避免引入额外依赖，这里用 SHA256 双 hash 简单派生。</summary>
        private static void SplitKey(byte[] key, out byte[] encKey, out byte[] macKey)
        {
            // encKey = SHA256(key || 0x01)
            // macKey = SHA256(key || 0x02)
            // 这是简化版 KDF；对掩耳盗铃用途足够。
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

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
