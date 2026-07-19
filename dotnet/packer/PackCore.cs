using System;
using System.Collections.Generic;
using System.IO;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    public sealed class PackOptions
    {
        public string InputPath;
        public string OutputPath;
        public string Password;
        /// <summary>旧字段：子系统偏好（Auto/Gui/Console/Test），保留向后兼容</summary>
        public StubPreference StubPreference = StubPreference.Auto;
        /// <summary>新字段：指定 stub manifest name（如 "winlock"、"applocker-gui"）。优先级高于 StubPreference</summary>
        public string PreferStubName = null;
        public int KdfIterations = PayloadFormat.DefaultKdfIterations;
        /// <summary>
        /// WinLock 测试模式：传给 builder 的 -t 参数，stub 跳过密码弹框，用硬编码 "test123" 解密。
        /// 用于 CI/自动化测试（auto_test.ps1 -WinLock）。密码 -p 会被 builder 忽略。
        /// </summary>
        public bool WinLockTestMode = false;
    }

    public sealed class PackReport
    {
        public long InputSize;
        public long OutputSize;
        public string OutputPath;
        /// <summary>实际使用的 stub 名称（用于日志）</summary>
        public string UsedStubName;
        /// <summary>实际使用的加壳方案</summary>
        public StubKind UsedKind;
    }

    /// <summary>
    /// packer 主流程：
    ///   1. 读取原 EXE
    ///   2. PE 解析
    ///   3. 扫描 stub 目录，按偏好选 stub
    ///   4a. tempfile 模式：生成 salt/nonce → KDF → AES-CBC+HMAC → 组装 payload → 写入 stub + 追加 payload
    ///   4b. WinLock 模式：调用 winlock_builder.exe 做 in-place 加壳 → 复制图标
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

            // 3. 扫描 stub 目录，选 stub
            string stubDir = StubLoader.FindStubDir();
            var allStubs = StubRegistry.LoadAll(stubDir);
            var originalSubsystem = MapSubsystem(peInfo.Subsystem);

            // 选 stub：优先用户指定的 PreferStubName
            StubManifest selected = null;
            if (!string.IsNullOrEmpty(opts.PreferStubName))
            {
                selected = StubRegistry.Select(allStubs, originalSubsystem, peInfo.Machine, opts.PreferStubName);
                if (selected == null)
                {
                    throw new InvalidOperationException(
                        $"找不到指定的 stub: {opts.PreferStubName}（可能缺失文件或不支持该架构）");
                }
            }

            // 如果没有指定 PreferStubName，按旧的 StubPreference 走（向后兼容）
            if (selected == null)
            {
                selected = SelectByLegacyPreference(allStubs, opts.StubPreference, originalSubsystem, peInfo.Machine);
            }

            // 兜底：按子系统自动选
            if (selected == null)
            {
                selected = StubRegistry.Select(allStubs, originalSubsystem, peInfo.Machine);
            }

            if (selected == null || !selected.IsAvailable)
            {
                throw new InvalidOperationException(
                    $"没有可用的 stub。请检查 stub/ 目录: {stubDir}\n" +
                    $"可用 stub 数量: {allStubs.Count}");
            }

            logger?.Invoke($"[packer] 使用 stub: {selected.Name} ({selected.Kind}/{selected.Subsystem})");
            progress?.Report(30);

            // 4. 分支：按 stub kind 走不同路径
            PackReport report;
            if (selected.Kind == StubKind.InplaceBuilder)
            {
                // WinLock 模式：不能加壳 .NET CLR 托管 PE
                if (peInfo.IsDotNet)
                    throw new InvalidOperationException("WinLock 模式不支持 .NET CLR 托管 PE，请改用临时文件模式");
                // WinLock 模式：当前仅支持 GUI 程序
                if (originalSubsystem != StubSubsystem.Gui)
                    throw new InvalidOperationException(
                        "WinLock 模式当前仅支持 GUI 程序（Console 程序请改用 AppLocker Console 模式）");

                report = PackWithWinLock(selected, opts, progress, logger);
            }
            else if (selected.Kind == StubKind.ReflectiveBuilder)
            {
                // Reflective 模式：支持 x86/x64 native PE + 简单 .NET 程序
                // MVP v1 明文模式（无密码），原 PE 完整保留在 .payload 节
                // 不限制子系统（GUI/Console 都支持，stub 继承原 PE subsystem）
                report = PackWithReflective(selected, opts, peInfo, progress, logger);
            }
            else
            {
                report = PackWithTempfile(selected, original, peInfo, opts, progress, logger);
            }
            return report;
        }

        /// <summary>WinLock 加壳分支：调用 builder.exe 做 in-place 加壳</summary>
        private static PackReport PackWithWinLock(
            StubManifest stub,
            PackOptions opts,
            IProgress<int> progress,
            Action<string> logger)
        {
            logger?.Invoke($"[WinLock] 使用 {stub.Name} 加壳...");

            // WinLock builder 不能原地覆盖输入文件，需要先复制到临时文件
            string tempInput = Path.Combine(Path.GetTempPath(),
                $"winlock_in_{Guid.NewGuid():N}.exe");
            string tempOutput = Path.Combine(Path.GetTempPath(),
                $"winlock_out_{Guid.NewGuid():N}.exe");
            try
            {
                File.Copy(opts.InputPath, tempInput, true);

                string builderExe = stub.MainFilePath;
                string stubDir = stub.StubDir;

                // WinLock 测试模式：由 PackOptions.WinLockTestMode 显式控制（CLI --test 开关）
                // 启用后 builder 用 -t 参数，stub 跳过密码弹框，用硬编码 "test123" 解密
                var result = WinLockPacker.Pack(
                    builderExe, stubDir, tempInput, tempOutput, opts.Password, opts.WinLockTestMode);

                // 输出 builder 日志（每行加前缀）
                if (!string.IsNullOrEmpty(result.Stdout))
                    foreach (var line in result.Stdout.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                        if (!string.IsNullOrWhiteSpace(line))
                            logger?.Invoke($"[WinLock] {line}");
                if (!string.IsNullOrEmpty(result.Stderr))
                    foreach (var line in result.Stderr.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                        if (!string.IsNullOrWhiteSpace(line))
                            logger?.Invoke($"[WinLock] [stderr] {line}");

                if (!result.Success)
                    throw new Exception(
                        $"WinLock builder 失败 (exit={result.ExitCode})\n" +
                        $"stdout: {result.Stdout}\nstderr: {result.Stderr}");

                // 把输出复制到目标路径
                string outDir = Path.GetDirectoryName(Path.GetFullPath(opts.OutputPath));
                if (!Directory.Exists(outDir)) Directory.CreateDirectory(outDir);
                File.Copy(tempOutput, opts.OutputPath, true);

                // 注意：WinLock 模式下不调用 IconCopier！
                // WinLock 加壳时原 PE 的 .rsrc 节被完整保留（图标已在），
                // 此时再调用 UpdateResourceW 会重新布局资源段，可能改变 .lock 节的
                // RawOffset 或破坏 stub 内的绝对地址引用，导致 stub 运行时崩溃。
                // tempfile 模式才需要 IconCopier（因为 stub 是另一个 exe，没原 PE 图标）。

                progress?.Report(100);
                return new PackReport
                {
                    InputSize = new FileInfo(opts.InputPath).Length,
                    OutputSize = new FileInfo(opts.OutputPath).Length,
                    OutputPath = opts.OutputPath,
                    UsedStubName = stub.Name,
                    UsedKind = StubKind.InplaceBuilder,
                };
            }
            finally
            {
                try { File.Delete(tempInput); } catch { }
                try { File.Delete(tempOutput); } catch { }
            }
        }

        /// <summary>Reflective 加壳分支：调用 builder_reflective.exe 做反射式加壳</summary>
        private static PackReport PackWithReflective(
            StubManifest stub,
            PackOptions opts,
            PeInfo peInfo,
            IProgress<int> progress,
            Action<string> logger)
        {
            logger?.Invoke($"[Reflective] 使用 {stub.Name} 加壳（MVP v1 明文模式）...");

            // builder 不能原地覆盖输入文件，复制到临时文件
            string tempInput = Path.Combine(Path.GetTempPath(),
                $"refl_in_{Guid.NewGuid():N}.exe");
            string tempOutput = Path.Combine(Path.GetTempPath(),
                $"refl_out_{Guid.NewGuid():N}.exe");
            try
            {
                File.Copy(opts.InputPath, tempInput, true);

                string builderExe = stub.MainFilePath;
                string stubDir = stub.StubDir;

                // 调用 builder_reflective.exe
                // 命令行：builder_reflective.exe <input> <output> --stub <stub_path>
                // builder 按 PE 架构自动选 stub（x64→loader_x64.exe，x86→loader_x86.exe）
                var result = ReflectivePacker.Pack(
                    builderExe, stubDir, tempInput, tempOutput, peInfo.Machine);

                // 输出 builder 日志
                if (!string.IsNullOrEmpty(result.Stdout))
                    foreach (var line in result.Stdout.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                        if (!string.IsNullOrWhiteSpace(line))
                            logger?.Invoke($"[Reflective] {line}");
                if (!string.IsNullOrEmpty(result.Stderr))
                    foreach (var line in result.Stderr.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
                        if (!string.IsNullOrWhiteSpace(line))
                            logger?.Invoke($"[Reflective] [stderr] {line}");

                if (!result.Success)
                    throw new Exception(
                        $"Reflective builder 失败 (exit={result.ExitCode})\n" +
                        $"stdout: {result.Stdout}\nstderr: {result.Stderr}");

                // 把输出复制到目标路径
                string outDir = Path.GetDirectoryName(Path.GetFullPath(opts.OutputPath));
                if (!Directory.Exists(outDir)) Directory.CreateDirectory(outDir);
                File.Copy(tempOutput, opts.OutputPath, true);

                // Reflective 模式不调用 IconCopier（原 PE 的 .rsrc 节已完整保留在 .payload 中，
                // stub 加载原 PE 后通过 PEB.Ldr 覆写让 OS 找到原 PE 的资源；再调 UpdateResourceW
                // 会改 stub 自己的资源段，与原 PE 资源无关，反而可能干扰）

                progress?.Report(100);
                return new PackReport
                {
                    InputSize = new FileInfo(opts.InputPath).Length,
                    OutputSize = new FileInfo(opts.OutputPath).Length,
                    OutputPath = opts.OutputPath,
                    UsedStubName = stub.Name,
                    UsedKind = StubKind.ReflectiveBuilder,
                };
            }
            finally
            {
                try { File.Delete(tempInput); } catch { }
                try { File.Delete(tempOutput); } catch { }
            }
        }

        /// <summary>临时文件加壳分支：原 PackCore.Pack 逻辑</summary>
        private static PackReport PackWithTempfile(
            StubManifest stub,
            byte[] original,
            PeInfo peInfo,
            PackOptions opts,
            IProgress<int> progress,
            Action<string> logger)
        {
            // 从 stub/ 目录或嵌入资源读 stub 字节
            byte[] stubBytes;
            if (stub.StubDir != null && File.Exists(stub.MainFilePath))
            {
                stubBytes = File.ReadAllBytes(stub.MainFilePath);
            }
            else
            {
                // 兜底：用旧的 StubLoader（嵌入资源）
                stubBytes = StubLoader.SelectStub(peInfo.Subsystem, opts.StubPreference);
            }
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
                OutputPath = opts.OutputPath,
                UsedStubName = stub.Name,
                UsedKind = StubKind.Tempfile,
            };
        }

        /// <summary>PE 子系统数值映射到 StubSubsystem 枚举</summary>
        private static StubSubsystem MapSubsystem(ushort raw)
        {
            // IMAGE_SUBSYSTEM_WINDOWS_GUI = 2, IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
            return raw == 2 ? StubSubsystem.Gui : StubSubsystem.Console;
        }

        /// <summary>
        /// 旧的 StubPreference（Auto/Gui/Console/Test）映射到 stub manifest。
        /// 优先 tempfile 模式（兼容性更好）。
        /// </summary>
        private static StubManifest SelectByLegacyPreference(
            List<StubManifest> all,
            StubPreference pref,
            StubSubsystem originalSubsystem,
            ushort machine)
        {
            if (all == null || all.Count == 0) return null;

            // Auto：按子系统自动选（tempfile 优先）
            if (pref == StubPreference.Auto)
            {
                var wantSubsystem = originalSubsystem == StubSubsystem.Console
                    ? StubSubsystem.Console
                    : StubSubsystem.Gui;
                return all.Find(m =>
                    m.IsAvailable &&
                    m.Kind == StubKind.Tempfile &&
                    m.Subsystem == wantSubsystem &&
                    m.SupportsMachine(machine));
            }

            // Gui/Console/Test：按对应子系统选
            StubSubsystem wantSub = pref == StubPreference.Gui ? StubSubsystem.Gui
                : pref == StubPreference.Console ? StubSubsystem.Console
                : StubSubsystem.Test;
            return all.Find(m =>
                m.IsAvailable &&
                m.Kind == StubKind.Tempfile &&
                m.Subsystem == wantSub &&
                m.SupportsMachine(machine));
        }
    }
}
