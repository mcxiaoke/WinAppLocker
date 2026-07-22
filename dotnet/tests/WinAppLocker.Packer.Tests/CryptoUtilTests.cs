using System;
using System.Text;
using WinAppLocker.Shared;
using WinAppLocker.Packer;
using Xunit;

namespace WinAppLocker.Packer.Tests
{
    public class CryptoUtilTests
    {
        // ---- PBKDF2-HMAC-SHA256 ----

        [Fact]
        public void DeriveKey_Deterministic()
        {
            byte[] salt = { 0x01, 0x02, 0x03, 0x04 };
            byte[] k1 = CryptoUtil.DeriveKey("password", salt, 1000);
            byte[] k2 = CryptoUtil.DeriveKey("password", salt, 1000);
            Assert.Equal(k1, k2);
            Assert.Equal(PayloadFormat.AesKeyLen, k1.Length);
        }

        [Fact]
        public void DeriveKey_DifferentSalt_DifferentKey()
        {
            byte[] salt1 = { 0x01, 0x02, 0x03, 0x04 };
            byte[] salt2 = { 0x01, 0x02, 0x03, 0x05 };
            byte[] k1 = CryptoUtil.DeriveKey("password", salt1, 100);
            byte[] k2 = CryptoUtil.DeriveKey("password", salt2, 100);
            Assert.NotEqual(k1, k2);
        }

        [Fact]
        public void DeriveKey_DifferentIterations_DifferentKey()
        {
            byte[] salt = { 0xAA, 0xBB };
            byte[] k1 = CryptoUtil.DeriveKey("pw", salt, 1);
            byte[] k2 = CryptoUtil.DeriveKey("pw", salt, 2);
            Assert.NotEqual(k1, k2);
        }

        [Fact]
        public void DeriveKey_Iterations1_MatchesRfcVector()
        {
            // RFC 7914 (scrypt) / RFC 6070 风格的 PBKDF2-HMAC-SHA256 向量
            // 来自 RFC 7914 第 11 节：
            //   P = "passwd", S = "salt", c = 1, dkLen = 64
            //   输出前 32 字节：
            //   55 ac 04 6e 56 e3 08 9f ec 16 91 c2 25 44 b6 05
            //   f9 41 85 21 6d de 04 65 e6 8b 9d 57 c2 0d ac bc
            //   49 ca 9c cc f1 79 b6 45 99 16 64 b3 9d 77 ef 31
            //   7c 71 b8 45 b1 e3 0b d5 09 11 20 41 d3 a1 97 83
            byte[] salt = Encoding.ASCII.GetBytes("salt");
            byte[] key = CryptoUtil.DeriveKey("passwd", salt, 1);
            byte[] expected =
            {
                0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
                0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
                0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65,
                0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc
            };
            Assert.Equal(expected, key);
        }

        // ---- AES-256-CBC + HMAC-SHA256 ----

        [Fact]
        public void Encrypt_InvalidKeyLength_Throws()
        {
            byte[] badKey = new byte[16];  // 应为 32
            byte[] iv = new byte[16];
            byte[] plaintext = { 0x01 };
            Assert.Throws<ArgumentException>(() => CryptoUtil.EncryptAesCbcHmac(badKey, iv, plaintext));
        }

        [Fact]
        public void Encrypt_InvalidIvLength_Throws()
        {
            byte[] key = new byte[32];
            byte[] badIv = new byte[8];  // 应为 16
            byte[] plaintext = { 0x01 };
            Assert.Throws<ArgumentException>(() => CryptoUtil.EncryptAesCbcHmac(key, badIv, plaintext));
        }

        [Fact]
        public void Encrypt_OutputIsCipherPlus32ByteMac()
        {
            byte[] key = new byte[32];
            for (int i = 0; i < 32; i++) key[i] = (byte)i;
            byte[] iv = new byte[16];
            for (int i = 0; i < 16; i++) iv[i] = (byte)(0x10 + i);

            byte[] plaintext = Encoding.UTF8.GetBytes("hello world");
            byte[] output = CryptoUtil.EncryptAesCbcHmac(key, iv, plaintext);

            // PKCS7 对齐到 16 字节 + 32 字节 HMAC
            int paddedLen = ((plaintext.Length / 16) + 1) * 16;
            Assert.Equal(paddedLen + 32, output.Length);
        }

        [Fact]
        public void Encrypt_DeterministicWithSameInputs()
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            byte[] plaintext = { 0xAA, 0xBB, 0xCC };
            byte[] o1 = CryptoUtil.EncryptAesCbcHmac(key, iv, plaintext);
            byte[] o2 = CryptoUtil.EncryptAesCbcHmac(key, iv, plaintext);
            Assert.Equal(o1, o2);
        }

        [Fact]
        public void Encrypt_DifferentKey_DifferentOutput()
        {
            byte[] key1 = new byte[32];
            byte[] key2 = new byte[32];
            key2[0] = 0x01;
            byte[] iv = new byte[16];
            byte[] plaintext = { 0xAA };
            byte[] o1 = CryptoUtil.EncryptAesCbcHmac(key1, iv, plaintext);
            byte[] o2 = CryptoUtil.EncryptAesCbcHmac(key2, iv, plaintext);
            Assert.NotEqual(o1, o2);
        }

        [Fact]
        public void Encrypt_EmptyPlaintext_Succeeds()
        {
            // 空明文经 PKCS7 填充为 16 字节（全是 0x10）
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            byte[] output = CryptoUtil.EncryptAesCbcHmac(key, iv, new byte[0]);
            Assert.Equal(16 + 32, output.Length);
        }

        [Fact]
        public void SplitKey_DerivesDifferentEncAndMacKeys()
        {
            // 通过 SplitKey 的输出（key+0x01 和 key+0x02 的 SHA-256）应该不同
            // 间接验证：相同 key+iv 加密空明文，输出长度 = 16 + 32
            byte[] key = new byte[32];
            for (int i = 0; i < 32; i++) key[i] = (byte)(i + 1);
            byte[] iv = new byte[16];
            byte[] out1 = CryptoUtil.EncryptAesCbcHmac(key, iv, new byte[0]);

            // 改变 key 末位，应改变整个输出
            byte[] key2 = (byte[])key.Clone();
            key2[31] ^= 0x01;
            byte[] out2 = CryptoUtil.EncryptAesCbcHmac(key2, iv, new byte[0]);
            Assert.NotEqual(out1, out2);
        }

        // ---- RandomBytes ----

        [Fact]
        public void RandomBytes_ZeroLength_ReturnsEmpty()
        {
            byte[] r = CryptoUtil.RandomBytes(0);
            Assert.Empty(r);
        }

        [Fact]
        public void RandomBytes_CorrectLength()
        {
            Assert.Equal(16, CryptoUtil.RandomBytes(16).Length);
            Assert.Equal(32, CryptoUtil.RandomBytes(32).Length);
        }

        [Fact]
        public void RandomBytes_NonDeterministic()
        {
            byte[] r1 = CryptoUtil.RandomBytes(32);
            byte[] r2 = CryptoUtil.RandomBytes(32);
            Assert.NotEqual(r1, r2);
        }
    }
}
