using System;

namespace WinAppLocker.Stub
{
    /// <summary>
    /// stub 主流程：
    /// 1. 读取自身 exe 字节
    /// 2. 从末尾解析 payload（含 Extension TLV 元数据）
    /// 3. 弹密码框
    /// 4. KDF 派生密钥
    /// 5. AES-CBC+HMAC 解密
    /// 6. 校验明文 CRC32
    /// 7. 在原目录创建隐藏临时文件（用原始 exe 名字）
    /// 8. CreateProcessW 启动子进程
    /// 9. 等待退出，删除临时文件
    /// </summary>
    internal static class StubEntry
    {
        // 退出码定义
        public const int ExitPayloadCorrupt = 1;
        public const int ExitUserCancel = 2;
        public const int ExitDecryptFail = 3;
        public const int ExitTempFileFail = 4;
        public const int ExitChildFail = 5;

        // 临时文件扩展名：用 .exe（CreateProcessW 支持任意扩展，但 .exe 兼容性最好）
        // 之前测试 .bin/.tmp 也能启动，但某些安全软件对非 .exe 的可执行文件更敏感
        private const string TempFileExt = ".exe";

        public static int Run()
        {
            // 1. 读取自身 exe 字节
            string selfPath = GetSelfPath();
            byte[] selfBytes;
            try
            {
                selfBytes = System.IO.File.ReadAllBytes(selfPath);
            }
            catch (Exception)
            {
                ErrorReporter.Show("无法读取自身 EXE");
                return ExitPayloadCorrupt;
            }

            // 2. 从末尾解析 payload
            PayloadReader payload;
            try
            {
                payload = PayloadReader.Parse(selfBytes);
            }
            catch (Exception ex)
            {
                ErrorReporter.Show("EXE 文件已损坏", ex.Message);
                return ExitPayloadCorrupt;
            }

            // 3. 弹密码框
            //    标题用原 exe 名字（从 Extension TLV 读取），让用户知道在为哪个程序输入密码
            string originalName = payload.GetOriginalName();
            if (string.IsNullOrEmpty(originalName))
            {
                // TLV 没有原始名，fallback 到 packed exe 名字
                originalName = System.IO.Path.GetFileName(selfPath);
            }
            string promptTitle = $"{originalName} - 请输入密码";
            string password = PasswordReader.Ask(promptTitle);
            if (string.IsNullOrEmpty(password))
                return ExitUserCancel;

            // 4. KDF 派生密钥
            byte[] key = CryptoUtil.DeriveKey(password, payload.Salt, (int)payload.Header.KdfIterations);

            // 5. AES-CBC+HMAC 解密
            byte[] plaintext;
            try
            {
                plaintext = CryptoUtil.DecryptAesCbcHmac(key, payload.Nonce, payload.CipherWithMac);
            }
            catch (Exception)
            {
                plaintext = null;
            }

            if (plaintext == null)
            {
                ErrorReporter.Show("密码错误");
                return ExitDecryptFail;
            }

            // 6. 校验明文长度与 CRC32
            if ((ulong)plaintext.Length != payload.Header.PlaintextLen)
            {
                ErrorReporter.Show("解密失败：长度不匹配");
                return ExitDecryptFail;
            }
            uint crc = Crc32.Compute(plaintext);
            if (crc != payload.Header.PlaintextCrc32)
            {
                ErrorReporter.Show("解密失败：校验失败");
                return ExitDecryptFail;
            }

            // 7 + 8 + 9. 临时文件 + 子进程 + 删除
            // 临时文件名优先用 Extension TLV 中记录的原始 exe 名字：
            //   chrome_locked.exe 打包了 chrome.exe → 临时文件 _chrome_ori.exe
            // 这样用户和 AV 能从文件名识别原程序
            string originalDir = System.IO.Path.GetDirectoryName(selfPath);
            string tempName = BuildTempFileName(originalName);
            string tempPath = System.IO.Path.Combine(originalDir, tempName);

            try
            {
                return ProcessLauncher.LaunchAndWait(plaintext, originalDir, tempPath);
            }
            catch (Exception ex)
            {
                ErrorReporter.Show("无法启动原程序", ex.Message);
                return ExitChildFail;
            }
        }

        /// <summary>从原始 exe 名字构造临时文件名：xxx.exe → _xxx_ori.exe</summary>
        private static string BuildTempFileName(string originalName)
        {
            string name = System.IO.Path.GetFileNameWithoutExtension(originalName);
            return "_" + name + "_ori" + TempFileExt;
        }

        /// <summary>获取自身 exe 路径。</summary>
        private static string GetSelfPath()
        {
            string[] argv = Environment.GetCommandLineArgs();
            if (argv.Length > 0 && !string.IsNullOrEmpty(argv[0]))
                return System.IO.Path.GetFullPath(argv[0]);
            return System.Reflection.Assembly.GetExecutingAssembly().Location;
        }
    }
}
