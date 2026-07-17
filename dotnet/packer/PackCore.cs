using System;
using System.IO;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    public sealed class PackOptions
    {
        public string InputPath;
        public string OutputPath;
        public string Password;
        public StubKind StubPreference = StubKind.Auto;
        public int KdfIterations = PayloadFormat.DefaultKdfIterations;
    }

    public sealed class PackReport
    {
        public long InputSize;
        public long OutputSize;
        public string OutputPath;
    }

    /// <summary>
    /// packer 主流程：
    ///   1. 读取原 EXE
    ///   2. PE 解析
    ///   3. 选择 stub
    ///   4. 生成 salt / nonce
    ///   5. KDF 派生密钥
    ///   6. AES-CBC+HMAC 加密
    ///   7. 组装 payload
    ///   8. 写入 stub -> UpdateResource 复制图标 -> 追加 payload
    /// </summary>
    internal static class PackCore
    {
        public static PackReport Pack(PackOptions opts, IProgress<int> progress, Action<string> logger)
        {
            if (string.IsNullOrEmpty(opts.Password))
                throw new ArgumentException("密码不能为空");
            if (opts.Password.Length < 4)
                throw new ArgumentException("密码至少 4 个字符");
            if (!File.Exists(opts.InputPath))
                throw new FileNotFoundException($"输入文件不存在: {opts.InputPath}");

            // 1. 读取原 EXE
            byte[] original = File.ReadAllBytes(opts.InputPath);
            progress?.Report(15);

            // 2. PE 解析
            var peInfo = PeReader.Parse(original);
            // .NET EXE 也支持（payload 不区分），只是 stub 启动它作为子进程即可
            progress?.Report(25);

            // 3. 选择 stub
            byte[] stubBytes = StubLoader.SelectStub(peInfo.Subsystem, opts.StubPreference);
            progress?.Report(30);

            // 4. 生成 salt / nonce
            byte[] salt = CryptoUtil.RandomBytes(PayloadFormat.DefaultSaltLen);
            byte[] nonce = CryptoUtil.RandomBytes(PayloadFormat.AesCbcIvLen);
            progress?.Report(40);

            // 5. KDF 派生密钥
            byte[] key = CryptoUtil.DeriveKey(opts.Password, salt, opts.KdfIterations);
            progress?.Report(55);

            // 6. AES-CBC+HMAC 加密
            byte[] cipherWithMac = CryptoUtil.EncryptAesCbcHmac(key, nonce, original);
            // 清零密钥
            for (int i = 0; i < key.Length; i++) key[i] = 0;
            progress?.Report(80);

            // 7. 组装 payload（含 Extension TLV：原始文件名 + 打包器签名 + 原始大小）
            var payload = PayloadBuilder.Build(new PayloadBuilder.BuildInput
            {
                Salt = salt,
                Nonce = nonce,
                CipherWithMac = cipherWithMac,
                KdfIterations = opts.KdfIterations,
                PlaintextLen = (ulong)original.Length,
                PlaintextCrc32 = Crc32.Compute(original),
                Subsystem = peInfo.Subsystem,
                Machine = peInfo.Machine,
                Timestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                OriginalName = Path.GetFileName(opts.InputPath),
                PackerVersion = $"WinAppLocker {VersionInfo.Version}",
                OriginalSize = (ulong)original.Length
            });
            progress?.Report(90);

            // 8. 写入输出文件
            //    顺序非常重要：
            //    a. 先写 stub 字节
            //    b. UpdateResourceW 复制图标（会重写 PE 资源段，可能截断尾部）
            //    c. 最后追加 payload（在资源更新之后，避免被截断）
            string outDir = Path.GetDirectoryName(Path.GetFullPath(opts.OutputPath));
            if (!Directory.Exists(outDir)) Directory.CreateDirectory(outDir);

            using (var fs = new FileStream(opts.OutputPath, FileMode.Create, FileAccess.Write))
            {
                fs.Write(stubBytes, 0, stubBytes.Length);
            }
            progress?.Report(95);

            // 复制图标/版本资源（失败不影响主流程）
            IconCopier.CopyIconAndVersion(opts.InputPath, opts.OutputPath, logger);

            // 追加 payload
            using (var fs = new FileStream(opts.OutputPath, FileMode.Append, FileAccess.Write))
            {
                fs.Write(payload, 0, payload.Length);
            }
            progress?.Report(100);

            return new PackReport
            {
                InputSize = original.Length,
                OutputSize = new FileInfo(opts.OutputPath).Length,
                OutputPath = opts.OutputPath
            };
        }
    }
}
