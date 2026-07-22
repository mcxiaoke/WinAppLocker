using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    internal static class Program
    {
        // WinExe 没有控制台，CLI 模式时需 AttachConsole 接管父进程控制台才能输出
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(uint dwProcessId);

        private const uint ATTACH_PARENT_PROCESS = 0xFFFFFFFF;

        [STAThread]
        private static int Main(string[] args)
        {
            // 任何 CLI 命令：--info / --pack / --version / --help 都需要先接管父控制台才能输出
            bool cliMode = args.Length > 0;
            if (cliMode)
            {
                AttachConsole(ATTACH_PARENT_PROCESS);
                // 让 stdout 立即写入已接管控制台，避免缓冲
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
                AppLogger.Info($"CLI 调用: {string.Join(" ", args)}");
            }

            // --info <packed.exe>: 读取已加密 EXE 的元信息，验证打包是否正确
            if (args.Length > 0 && (args[0] == "--info" || args[0] == "-info"))
            {
                if (args.Length < 2)
                {
                    Console.Error.WriteLine("用法: WinAppLocker.exe --info <packed.exe>");
                    return 2;
                }
                return PackInfo.Inspect(args[1]);
            }

            // --pe-info <exe>: 显示 PE 关键信息（架构/子系统/ASLR/DEP/TLS/签名等），用于诊断
            if (args.Length > 0 && (args[0] == "--pe-info" || args[0] == "-pe-info"))
            {
                if (args.Length < 2)
                {
                    Console.Error.WriteLine("用法: WinAppLocker.exe --pe-info <exe>");
                    return 2;
                }
                return PrintPeInfo(args[1]);
            }

            // --list-stubs: 列出 stub/ 目录下所有 stub manifest
            if (args.Length > 0 && (args[0] == "--list-stubs" || args[0] == "-list-stubs"))
            {
                return ListStubs();
            }

            // CLI 模式：dotnet WinAppLocker.exe --pack -i input.exe -o output.exe -p password [--stub auto|gui|console|test] [--iterations N]
            if (args.Length > 0 && (args[0] == "--pack" || args[0] == "-pack"))
            {
                return RunCliPack(args);
            }

            // --version: 显示版本信息
            if (args.Length > 0 && (args[0] == "--version" || args[0] == "-v" || args[0] == "version"))
            {
                Console.WriteLine($"WinAppLocker {VersionInfo.Version}");
                Console.WriteLine($"  git: {VersionInfo.GitHash}");
                Console.WriteLine($"  build: {VersionInfo.BuildTime}");
                return 0;
            }

            // --help / -h
            if (args.Length > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help"))
            {
                PrintHelp();
                return 0;
            }

            // 无参数：启动 GUI
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            try
            {
                using (var form = new MainForm())
                {
                    Application.Run(form);
                }
                return 0;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "WinAppLocker", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("WinAppLocker - EXE 密码保护工具");
            Console.WriteLine();
            Console.WriteLine("用法:");
            Console.WriteLine("  WinAppLocker.exe                              启动 GUI 界面");
            Console.WriteLine("  WinAppLocker.exe --pack -i <input> -o <output> -p <password> [options]");
            Console.WriteLine("  WinAppLocker.exe --info <packed.exe>          检查已加密 EXE 的信息");
            Console.WriteLine("  WinAppLocker.exe --pe-info <exe>              显示 PE 关键信息（架构/ASLR/DEP/TLS/签名等）");
            Console.WriteLine("  WinAppLocker.exe --version                    显示版本信息");
            Console.WriteLine();
            Console.WriteLine("pack 选项:");
            Console.WriteLine("  -i, --input <path>        输入 EXE 路径");
            Console.WriteLine("  -o, --output <path>       输出 EXE 路径");
            Console.WriteLine("  -p, --password <pass>     密码（至少 4 字符）");
            Console.WriteLine("      --stub <Auto|Gui|Console|Test>");
            Console.WriteLine("                            旧 stub 偏好（按子系统选 tempfile 模式）");
            Console.WriteLine("      --stub-name <name>    指定 stub manifest 名称（优先级高于 --stub）");
            Console.WriteLine("                            如 gui / cli / test / inplace / reflective 等");
            Console.WriteLine("                            用 --list-stubs 查看可用 stub");
            Console.WriteLine("      --list-stubs          列出 stub/ 目录下所有可用 stub");
            Console.WriteLine("      --iterations <N>      PBKDF2 迭代次数（默认 200000）");
            Console.WriteLine("      --test                WinLock 测试模式：builder 用 -t，stub 跳过密码弹框");
            Console.WriteLine("                            用硬编码密码 test123 解密（仅 --stub-name inplace 有效）");
        }

        private static int RunCliPack(string[] args)
        {
            string inputPath = null;
            string outputPath = null;
            string password = null;
            var stubPref = StubPreference.Auto;
            string stubName = null;
            int iterations = PayloadFormat.DefaultKdfIterations;
            // WinLock 测试模式：--test 传给 builder -t，stub 跳过弹框用硬编码 test123 解密
            bool winLockTestMode = false;

            // --list-stubs 提前处理：列出 stub/ 目录所有可用 stub 后退出
            bool listStubs = false;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--list-stubs")
                {
                    listStubs = true;
                    break;
                }
            }
            if (listStubs)
            {
                return ListStubs();
            }

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-i":
                    case "--input":
                        inputPath = args[++i];
                        break;
                    case "-o":
                    case "--output":
                        outputPath = args[++i];
                        break;
                    case "-p":
                    case "--password":
                        password = args[++i];
                        break;
                    case "--stub":
                        Enum.TryParse(args[++i], true, out stubPref);
                        break;
                    case "--stub-name":
                        stubName = args[++i];
                        break;
                    case "--iterations":
                        int.TryParse(args[++i], out iterations);
                        break;
                    case "--test":
                        // WinLock 测试模式：builder 用 -t，stub 跳过弹框，密码硬编码为 test123
                        winLockTestMode = true;
                        break;
                    case "-h":
                    case "--help":
                        PrintHelp();
                        return 0;
                }
            }

            if (string.IsNullOrEmpty(inputPath) || string.IsNullOrEmpty(outputPath) || string.IsNullOrEmpty(password))
            {
                Console.Error.WriteLine("用法: WinAppLocker.exe --pack -i input.exe -o output.exe -p password [--stub Auto|Gui|Console|Test] [--stub-name <name>] [--test]");
                return 2;
            }

            // --stub Test 警告：测试 stub 内置密码 test1234，必须用相同密码打包
            if (stubPref == StubPreference.Test && string.IsNullOrEmpty(stubName) && password != "test1234")
            {
                Console.Error.WriteLine("[警告] --stub Test 使用内置密码 test1234，但你提供了不同的密码。");
                Console.Error.WriteLine("[警告] 加密后的 EXE 将无法解密。请使用 -p test1234 配合 --stub Test。");
                Console.Error.WriteLine("[警告] 继续加密（按 Ctrl+C 中止）...");
            }

            // --test 警告：WinLock 测试模式密码硬编码为 test123，-p 会被 builder 忽略
            if (winLockTestMode && password != "test123")
            {
                Console.Error.WriteLine($"[警告] --test 模式 WinLock builder 用硬编码密码 test123，你提供的 -p {password} 会被忽略。");
                Console.Error.WriteLine($"[警告] 加密后的 EXE 仅能用密码 test123 解密。");
                Console.Error.WriteLine("[警告] 继续加密（按 Ctrl+C 中止）...");
            }

            var opts = new PackOptions
            {
                InputPath = inputPath,
                OutputPath = outputPath,
                Password = password,
                StubPreference = stubPref,
                PreferStubName = stubName,
                KdfIterations = iterations,
                WinLockTestMode = winLockTestMode
            };

            try
            {
                // 读 PE 信息后写入"CLI 加密开始"日志，方便事后排查
                string peSummary = "(PE 读取失败)";
                try
                {
                    byte[] pe = File.ReadAllBytes(inputPath);
                    var peInfo = PeReader.Parse(pe);
                    peSummary = $"{peInfo.MachineName}/{peInfo.SubsystemName} " +
                                $"ASLR={peInfo.IsAslr} DEP={peInfo.IsDep} CFG={peInfo.IsCfg} HEVA={peInfo.IsHighEntropyVA} " +
                                $"TLS={peInfo.HasTls} Signed={peInfo.IsSigned} Reloc={peInfo.HasReloc} " +
                                $".NET={peInfo.IsDotNet} size={peInfo.FileSize}";
                }
                catch (Exception ex) { peSummary = $"(PE 读取失败: {ex.Message})"; }

                AppLogger.Info($"CLI 加密开始: input={inputPath} output={outputPath} stub-name={stubName ?? "(null)"} stub-pref={stubPref} iterations={iterations} PE=[{peSummary}]");
                var report = PackCore.Pack(opts, new Progress<int>(p =>
                {
                    Console.Write($"\r进度: {p,3}%");
                }), msg => {
                    Console.Error.WriteLine($"[log] {msg}");
                    // 按消息前缀区分级别
                    if (msg.Contains("WARN:") || msg.Contains("ERROR:") || msg.Contains("[stderr]"))
                        AppLogger.Warn(msg);
                    else
                        AppLogger.Info(msg);
                });
                Console.WriteLine();
                Console.WriteLine($"✓ 加密成功: {report.InputSize} bytes → {report.OutputSize} bytes");
                Console.WriteLine($"  输出: {report.OutputPath}");
                Console.WriteLine($"  使用 stub: {report.UsedStubName} ({report.UsedKind})");
                AppLogger.Info($"CLI 加密成功: {report.InputSize} → {report.OutputSize} bytes, stub={report.UsedStubName} ({report.UsedKind})");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"✗ 失败: {ex.Message}");
                AppLogger.Error($"CLI 加密失败: input={inputPath} output={outputPath}", ex);
                return 3;
            }
        }

        /// <summary>--list-stubs：扫描 stub/ 目录并列出所有 stub manifest</summary>
        private static int ListStubs()
        {
            string stubDir = StubLoader.FindStubDir();
            Console.WriteLine($"stub 目录: {stubDir}");
            var stubs = StubRegistry.LoadAll(stubDir);
            if (stubs.Count == 0)
            {
                Console.WriteLine("  (无可用 stub，请先运行 build.ps1 生成 stub/)");
                return 0;
            }
            Console.WriteLine($"共 {stubs.Count} 个 stub:");
            foreach (var s in stubs)
            {
                string status = s.IsAvailable ? "OK" : $"缺失({string.Join(",", s.MissingComponents)})";
                Console.WriteLine($"  - {s.Name,-20} kind={s.KindStr,-15} subsystem={s.SubsystemStr,-8} version={s.Version ?? "?"} [{status}]");
                Console.WriteLine($"    desc: {s.Description}");
                if (s.SupportedMachines != null && s.SupportedMachines.Count > 0)
                    Console.WriteLine($"    arch: {string.Join(", ", s.SupportedMachines)}");
            }
            return 0;
        }

        /// <summary>--pe-info：打印 PE 关键信息，用于诊断原 EXE 属性</summary>
        private static int PrintPeInfo(string exePath)
        {
            if (!File.Exists(exePath))
            {
                Console.Error.WriteLine($"文件不存在: {exePath}");
                return 2;
            }

            try
            {
                byte[] bytes = File.ReadAllBytes(exePath);
                var info = PeReader.Parse(bytes);

                Console.WriteLine($"文件: {exePath}");
                Console.WriteLine($"  架构 (Machine):  0x{info.Machine:X4}  ({info.MachineName})");
                Console.WriteLine($"  子系统 (Subsystem): {info.Subsystem}  ({info.SubsystemName})");
                Console.WriteLine($"  .NET CLR 托管:    {info.IsDotNet}");
                Console.WriteLine($"  ASLR (DynamicBase):    {info.IsAslr}");
                Console.WriteLine($"  DEP (NxCompat):        {info.IsDep}");
                Console.WriteLine($"  HighEntropyVA:         {info.IsHighEntropyVA}");
                Console.WriteLine($"  CFG (GuardCf):         {info.IsCfg}");
                Console.WriteLine($"  TLS 目录:              {info.HasTls}");
                Console.WriteLine($"  Authenticode 签名:     {info.IsSigned}");
                Console.WriteLine($"  重定位表 (.reloc):     {info.HasReloc}");
                Console.WriteLine($"  Chromium 系浏览器:     {info.IsChromiumLike}");
                Console.WriteLine($"  文件大小:              {info.FileSize:N0} bytes ({info.FileSize / 1024.0:F1} KB)");

                AppLogger.Info($"--pe-info {exePath}: machine={info.MachineName} subsystem={info.SubsystemName} dotnet={info.IsDotNet} chromium={info.IsChromiumLike} aslr={info.IsAslr} dep={info.IsDep} tls={info.HasTls} signed={info.IsSigned} size={info.FileSize}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"PE 解析失败: {ex.Message}");
                AppLogger.Error($"--pe-info 失败: {exePath}", ex);
                return 3;
            }
        }
    }
}
