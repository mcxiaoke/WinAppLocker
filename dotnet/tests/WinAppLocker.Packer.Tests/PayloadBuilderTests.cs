using System;
using System.Text;
using WinAppLocker.Shared;
using WinAppLocker.Packer;
using Xunit;

namespace WinAppLocker.Packer.Tests
{
    public class PayloadBuilderTests
    {
        private static PayloadBuilder.BuildInput MakeInput(
            string originalName = "test.exe",
            string packerVersion = "v1.0.0",
            ulong originalSize = 4096)
        {
            return new PayloadBuilder.BuildInput
            {
                Salt = new byte[16],
                Nonce = new byte[16],
                CipherWithMac = new byte[48 + 32],  // 3 AES 块 + HMAC
                KdfIterations = 100_000,
                PlaintextLen = 4096,
                PlaintextCrc32 = 0xABCDEF01u,
                Subsystem = 2,
                Machine = 0x8664,
                Timestamp = 1700000000,
                OriginalName = originalName,
                PackerVersion = packerVersion,
                OriginalSize = originalSize
            };
        }

        [Fact]
        public void Build_TotalLength_Correct()
        {
            var input = MakeInput();
            byte[] result = PayloadBuilder.Build(input);

            int expected = PayloadFormat.HeaderSize          // 64
                         + input.Salt.Length                  // 16
                         + input.Nonce.Length                 // 16
                         + input.CipherWithMac.Length         // 80
                         + 0 /* ext 由 BuildExtensions 决定 */
                         + PayloadFormat.FooterSize;          // 32

            // ext 区域：Tag1("test.exe"=8B)+Tag2("v1.0.0"=6B)+Tag3(u64=8B) = (4+8)+(4+6)+(4+8) = 34
            int extLen = (4 + 8) + (4 + 6) + (4 + 8);
            expected += extLen;

            Assert.Equal(expected, result.Length);
        }

        [Fact]
        public void Build_HasFlagHasExtensions_WhenExtPresent()
        {
            var input = MakeInput();
            byte[] result = PayloadBuilder.Build(input);
            var header = PayloadHeader.FromBytes(result, 0);
            Assert.Equal(PayloadFormat.FlagHasExtensions, header.Flags & PayloadFormat.FlagHasExtensions);
            Assert.True(header.ExtLen > 0);
        }

        [Fact]
        public void Build_NoFlag_WhenNoExt()
        {
            // 不设 OriginalName / PackerVersion / OriginalSize → ext 为空
            var input = new PayloadBuilder.BuildInput
            {
                Salt = new byte[16],
                Nonce = new byte[16],
                CipherWithMac = new byte[32],
                KdfIterations = 100,
                PlaintextLen = 10,
                PlaintextCrc32 = 0,
                Subsystem = 3,
                Machine = 0x014c,
                Timestamp = 0,
                OriginalName = null,
                PackerVersion = null,
                OriginalSize = 0
            };
            byte[] result = PayloadBuilder.Build(input);
            var header = PayloadHeader.FromBytes(result, 0);
            Assert.Equal(0u, header.Flags);
            Assert.Equal(0u, header.ExtLen);
        }

        [Fact]
        public void Build_HeaderFields_Preserved()
        {
            var input = MakeInput();
            byte[] result = PayloadBuilder.Build(input);
            var header = PayloadHeader.FromBytes(result, 0);

            Assert.Equal(PayloadFormat.PayloadVersion, header.Version);
            Assert.Equal(PayloadFormat.AlgoAes256CbcHmacSha256, header.AlgorithmId);
            Assert.Equal(PayloadFormat.KdfPbkdf2Sha256, header.KdfId);
            Assert.Equal(100_000u, header.KdfIterations);
            Assert.Equal(16, header.SaltLen);
            Assert.Equal(16, header.NonceLen);
            Assert.Equal(4096uL, header.PlaintextLen);
            Assert.Equal(0xABCDEF01u, header.PlaintextCrc32);
            Assert.Equal(2u, header.Subsystem);
            Assert.Equal(0x8664u, header.Machine);
        }

        [Fact]
        public void Build_FooterPayloadLen_Correct()
        {
            var input = MakeInput();
            byte[] result = PayloadBuilder.Build(input);

            int footerOffset = result.Length - PayloadFormat.FooterSize;
            var footer = PayloadFooter.FromBytes(result, footerOffset);

            // PayloadLen = Header + Salt + Nonce + Cipher + Ext（不含 Footer）
            int expectedPayloadLen = result.Length - PayloadFormat.FooterSize;
            Assert.Equal((ulong)expectedPayloadLen, footer.PayloadLen);
        }

        [Fact]
        public void Build_HeaderMagic_AtOffset0()
        {
            var input = MakeInput();
            byte[] result = PayloadBuilder.Build(input);

            for (int i = 0; i < 8; i++)
                Assert.Equal(PayloadFormat.HeaderMagic[i], result[i]);
        }

        [Fact]
        public void Build_FooterMagic_AtEnd()
        {
            var input = MakeInput();
            byte[] result = PayloadBuilder.Build(input);

            int footerOffset = result.Length - PayloadFormat.FooterSize;
            for (int i = 0; i < 8; i++)
            {
                Assert.Equal(PayloadFormat.FooterMagicA[i], result[footerOffset + 0x0C + i]);
                Assert.Equal(PayloadFormat.FooterMagicB[i], result[footerOffset + 0x14 + i]);
            }
        }

        [Fact]
        public void Build_SaltAndNonce_PlacedCorrectly()
        {
            var input = MakeInput();
            // 填入可识别的 salt/nonce
            for (int i = 0; i < 16; i++) input.Salt[i] = (byte)(0xA0 + i);
            for (int i = 0; i < 16; i++) input.Nonce[i] = (byte)(0xB0 + i);

            byte[] result = PayloadBuilder.Build(input);

            // Salt 紧跟 Header
            int saltOff = PayloadFormat.HeaderSize;
            for (int i = 0; i < 16; i++)
                Assert.Equal(input.Salt[i], result[saltOff + i]);

            // Nonce 紧跟 Salt
            int nonceOff = saltOff + input.Salt.Length;
            for (int i = 0; i < 16; i++)
                Assert.Equal(input.Nonce[i], result[nonceOff + i]);
        }

        [Fact]
        public void Build_Cipher_PlacedCorrectly()
        {
            var input = MakeInput();
            // 填入可识别的密文
            for (int i = 0; i < input.CipherWithMac.Length; i++)
                input.CipherWithMac[i] = (byte)(0xC0 + (i & 0x3F));

            byte[] result = PayloadBuilder.Build(input);

            int cipherOff = PayloadFormat.HeaderSize + input.Salt.Length + input.Nonce.Length;
            for (int i = 0; i < input.CipherWithMac.Length; i++)
                Assert.Equal(input.CipherWithMac[i], result[cipherOff + i]);
        }

        [Fact]
        public void Build_ExtTlv_Parseable()
        {
            var input = MakeInput(originalName: "myapp.exe", packerVersion: "v2.0", originalSize: 1024);
            byte[] result = PayloadBuilder.Build(input);
            var header = PayloadHeader.FromBytes(result, 0);

            // Ext 区域位置：Header + Salt + Nonce + Cipher
            int extOff = PayloadFormat.HeaderSize + input.Salt.Length + input.Nonce.Length + input.CipherWithMac.Length;
            var list = ExtTlv.Parse(result, extOff, (int)header.ExtLen);

            // 应该有 3 个 TLV
            Assert.Equal(3, list.Count);
            Assert.Equal("myapp.exe", ExtTlv.FindString(list, PayloadFormat.ExtTagOriginalName));
            Assert.Equal("v2.0", ExtTlv.FindString(list, PayloadFormat.ExtTagPackerVersion));
            Assert.Equal(1024uL, ExtTlv.FindU64(list, PayloadFormat.ExtTagOriginalSize));
        }

        [Fact]
        public void Build_NullSalt_Throws()
        {
            var input = MakeInput();
            input.Salt = null;
            Assert.Throws<ArgumentException>(() => PayloadBuilder.Build(input));
        }

        [Fact]
        public void Build_InvalidNonce_Throws()
        {
            var input = MakeInput();
            input.Nonce = new byte[8];  // 应为 16
            Assert.Throws<ArgumentException>(() => PayloadBuilder.Build(input));
        }

        [Fact]
        public void Build_NullCipher_Throws()
        {
            var input = MakeInput();
            input.CipherWithMac = null;
            Assert.Throws<ArgumentException>(() => PayloadBuilder.Build(input));
        }

        [Fact]
        public void Build_RoundTrip_HeaderAndFooterValid()
        {
            var input = MakeInput();
            byte[] result = PayloadBuilder.Build(input);

            // 头部能解析
            var header = PayloadHeader.FromBytes(result, 0);
            Assert.Equal(input.PlaintextLen, header.PlaintextLen);

            // 尾部能解析
            var footer = PayloadFooter.FromBytes(result, result.Length - PayloadFormat.FooterSize);
            Assert.Equal((ulong)(result.Length - PayloadFormat.FooterSize), footer.PayloadLen);
        }
    }
}
