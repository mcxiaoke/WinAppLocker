using System;
using System.Diagnostics;
using System.IO;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// WinLock 加壳分支：调用 winlock_builder.exe 对原 EXE 做 in-place 加壳。
    /// builder 是 C 程序，独立进程调用，避免 P/Invoke 复杂度。
    /// </summary>
    public static class WinLockPacker
    {
        /// <summary>WinLock builder 调用结果</summary>
        public sealed class WinLockResult
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
        /// 调用 winlock_builder.exe 加壳。
        ///
        /// 调用形式：builder.exe -i input.exe -o output.exe -p password --stub-dir stubDir
        /// builder 会自动检测输入 PE 架构（x64/x86）选用对应 stub_xXX.bin。
        /// </summary>
        /// <param name="builderExe">winlock_builder.exe 完整路径</param>
        /// <param name="stubDir">stub/ 目录路径（builder 找 stub_x64/x86.bin 用）</param>
        /// <param name="inputExe">原 EXE 路径</param>
        /// <param name="outputExe">输出 EXE 路径</param>
        /// <param name="password">密码</param>
        /// <param name="testMode">true=测试模式（硬编码密码 test123，跳过弹框）</param>
        public static WinLockResult Pack(
            string builderExe,
            string stubDir,
            string inputExe,
            string outputExe,
            string password,
            bool testMode = false)
        {
            var result = new WinLockResult();

            // 构造命令行参数（路径用引号包裹，避免空格问题）
            var args = $"-i \"{inputExe}\" -o \"{outputExe}\" -p \"{password}\" --stub-dir \"{stubDir}\"";
            if (testMode)
            {
                // 测试模式：builder 用硬编码密码 test123，忽略 -p
                args = $"-i \"{inputExe}\" -o \"{outputExe}\" -t --stub-dir \"{stubDir}\"";
            }

            var psi = new ProcessStartInfo
            {
                FileName = builderExe,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(builderExe) ?? "",
            };

            using (var proc = Process.Start(psi))
            {
                if (proc == null)
                {
                    result.Success = false;
                    result.Stderr = "无法启动 winlock_builder.exe";
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
