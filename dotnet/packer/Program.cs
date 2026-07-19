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
            // 任何 CLI 命令：--info / --pack / --version / --help 都需要先接管父控制台
            bool cliMode = args.Length > 0;
            if (cliMode)
            {
                AttachConsole(ATTACH_PARENT_PROCESS);
                // 让 stdout 立即写入已接管控制台，避免缓冲
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
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
            Console.WriteLine("  WinAppLocker.exe --version                    显示版本信息");
            Console.WriteLine();
            Console.WriteLine("pack 选项:");
            Console.WriteLine("  -i, --input <path>        输入 EXE 路径");
            Console.WriteLine("  -o, --output <path>       输出 EXE 路径");
            Console.WriteLine("  -p, --password <pass>     密码（至少 4 字符）");
            Console.WriteLine("      --stub <Auto|Gui|Console|Test>");
            Console.WriteLine("                            旧 stub 偏好（按子系统选 tempfile 模式）");
            Console.WriteLine("      --stub-name <name>    指定 stub manifest 名称（优先级高于 --stub）");
            Console.WriteLine("                            如 applocker-gui / applocker-console / winlock 等");
            Console.WriteLine("                            用 --list-stubs 查看可用 stub");
            Console.WriteLine("      --list-stubs          列出 stub/ 目录下所有可用 stub");
            Console.WriteLine("      --iterations <N>      PBKDF2 迭代次数（默认 200000）");
        }

        private static int RunCliPack(string[] args)
        {
            string inputPath = null;
            string outputPath = null;
            string password = null;
            var stubPref = StubPreference.Auto;
            string stubName = null;
            int iterations = PayloadFormat.DefaultKdfIterations;

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
                    case "-h":
                    case "--help":
                        PrintHelp();
                        return 0;
                }
            }

            if (string.IsNullOrEmpty(inputPath) || string.IsNullOrEmpty(outputPath) || string.IsNullOrEmpty(password))
            {
                Console.Error.WriteLine("用法: WinAppLocker.exe --pack -i input.exe -o output.exe -p password [--stub Auto|Gui|Console|Test] [--stub-name <name>]");
                return 2;
            }

            // --stub Test 警告：测试 stub 内置密码 test1234，必须用相同密码打包
            if (stubPref == StubPreference.Test && string.IsNullOrEmpty(stubName) && password != "test1234")
            {
                Console.Error.WriteLine("[警告] --stub Test 使用内置密码 test1234，但你提供了不同的密码。");
                Console.Error.WriteLine("[警告] 加密后的 EXE 将无法解密。请使用 -p test1234 配合 --stub Test。");
                Console.Error.WriteLine("[警告] 继续加密（按 Ctrl+C 中止）...");
            }

            var opts = new PackOptions
            {
                InputPath = inputPath,
                OutputPath = outputPath,
                Password = password,
                StubPreference = stubPref,
                PreferStubName = stubName,
                KdfIterations = iterations
            };

            try
            {
                var report = PackCore.Pack(opts, new Progress<int>(p =>
                {
                    Console.Write($"\r进度: {p,3}%");
                }), msg => Console.Error.WriteLine($"[log] {msg}"));
                Console.WriteLine();
                Console.WriteLine($"✓ 加密成功: {report.InputSize} bytes → {report.OutputSize} bytes");
                Console.WriteLine($"  输出: {report.OutputPath}");
                Console.WriteLine($"  使用 stub: {report.UsedStubName} ({report.UsedKind})");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"✗ 失败: {ex.Message}");
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
    }
}
