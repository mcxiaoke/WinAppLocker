using System;
using System.Diagnostics;
using System.IO;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// Reflective 加壳分支：调用 builder_reflective.exe 把原 PE 作为 .payload 节
    /// 嵌入 stub EXE，运行时反射式加载原 PE 并跳到其 OEP。
    ///
    /// 与 WinLockPacker（in-place）的区别：
    ///   - in-place：XTEA 加密 .text 前 N 字节，原 PE 被原地修改
    ///   - reflective：原 PE 完整保留在 .payload 节，stub 通过反射式 loader
    ///                 在内存中 VirtualAlloc + 复制 PE + 处理 IAT/reloc/延迟导入
    ///                 + PEB.Ldr 覆写 → 跳 OEP
    ///
    /// 当前为 MVP v1 明文模式（无加密），后续可加 AES + 密码弹框。
    /// 支持 x86/x64 native PE，简单 .NET 程序可能成功（不保证）。
    /// </summary>
    public static class ReflectivePacker
    {
        /// <summary>Reflective builder 调用结果</summary>
        public sealed class ReflectiveResult
        {
            /// <summary>是否成功（exit code = 0 且输出文件存在）</summary>
            public bool Success;
            /// <summary>输出 EXE 路径（成功时）</summary>
            public string OutputPath;
            /// <summary>builder stdout 内容（用于日志）</summary>
            public string Stdout;
            /// <summary>builder stderr 内容（用于日志）</summary>
            public string Stderr;
            /// <summary>builder 进程退出码</summary>
            public int ExitCode;
        }

        /// <summary>
        /// 调用 builder_reflective.exe 加壳。
        ///
        /// 调用形式：builder_reflective.exe input.exe output.exe --stub loader_xXX.exe
        /// builder 按输入 PE 架构自动选 stub（x64→loader_x64.exe，x86→loader_x86.exe）。
        /// 用 --stub 显式指定可覆盖自动选择（用于 components 路径解析）。
        ///
        /// 命令行格式与 WinLockPacker 不同：
        ///   - 无密码参数（MVP v1 明文模式）
        ///   - 无 -i/-o 前缀，用位置参数
        ///   - 用 --stub 指定单个 stub（不是 --stub-dir）
        /// </summary>
        /// <param name="builderExe">builder_reflective.exe 完整路径</param>
        /// <param name="stubDir">stub/ 目录路径（builder_reflective.exe 所在目录，用于相对路径解析）</param>
        /// <param name="inputExe">原 EXE 路径</param>
        /// <param name="outputExe">输出 EXE 路径</param>
        /// <param name="machine">原 PE 的 Machine 字段（IMAGE_FILE_MACHINE_AMD64=0x8664 / I386=0x14c），用于选 stub</param>
        public static ReflectiveResult Pack(
            string builderExe,
            string stubDir,
            string inputExe,
            string outputExe,
            ushort machine)
        {
            var result = new ReflectiveResult();

            // 根据原 PE 架构选 stub 文件名
            // builder 默认 stub 路径是相对路径 ../reflective/loader_xXX.exe，
            // 但 dotnet/packer/stub/ 目录布局不同，需要用 --stub 显式指定
            string stubFile = machine == 0x8664 ? "loader_x64.exe"
                           : machine == 0x14c ? "loader_x86.exe"
                           : null;
            if (stubFile == null)
            {
                result.Success = false;
                result.Stderr = $"不支持的 PE 架构: Machine=0x{machine:x4}（仅支持 x86/x64）";
                return result;
            }
            string stubPath = Path.Combine(stubDir, stubFile);
            if (!File.Exists(stubPath))
            {
                result.Success = false;
                result.Stderr = $"找不到 reflective stub: {stubPath}";
                return result;
            }

            // 命令行：builder_reflective.exe <input> <output> --stub <stub_path>
            // 注意：builder_reflective 用位置参数（不是 -i/-o）
            var args = $"\"{inputExe}\" \"{outputExe}\" --stub \"{stubPath}\"";

            var psi = new ProcessStartInfo
            {
                FileName = builderExe,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                // WorkingDirectory 设为 builder 所在目录，
                // 让 builder 内部相对路径（如默认 ../reflective/loader_xXX.exe）能正确解析
                WorkingDirectory = Path.GetDirectoryName(builderExe) ?? "",
            };

            using (var proc = Process.Start(psi))
            {
                if (proc == null)
                {
                    result.Success = false;
                    result.Stderr = "无法启动 builder_reflective.exe";
                    return result;
                }
                // 异步读 stdout/stderr 避免死锁
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                result.ExitCode = proc.ExitCode;
                result.Stdout = stdout;
                result.Stderr = stderr;
                result.Success = proc.ExitCode == 0 && File.Exists(outputExe);
                result.OutputPath = result.Success ? outputExe : null;
            }
            return result;
        }
    }
}
