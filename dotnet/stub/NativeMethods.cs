using System;
using System.Runtime.InteropServices;

namespace WinAppLocker.Stub
{
    internal static class NativeMethods
    {
        // ---- CreateFileW 用于创建带 HIDDEN 属性的临时文件 ----
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint GENERIC_READ = 0x80000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint FILE_SHARE_DELETE = 0x00000004;
        public const uint CREATE_ALWAYS = 2;
        public const uint FILE_ATTRIBUTE_HIDDEN = 0x00000002;
        // FILE_ATTRIBUTE_TEMPORARY：提示系统文件将很快被删除，
        // 尽量不刷盘也尽量不触发 AV 的"持久化文件"扫描路径
        public const uint FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        // ---- CreateProcessW 用于启动子进程 ----
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const uint CREATE_NO_WINDOW = 0x08000000;
        public static readonly uint INFINITE = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize;
            public uint dwXCountChars, dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessW(
            string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetCurrentDirectoryW(string lpPathName);

        // ---- DPI awareness（Win10 1703+ 优先，旧系统 fallback）----
        // stub 运行时没有 exe.config 文件在旁边（payload 追加在 stub exe 末尾，
        // 用户拿到的是单个 exe），所以不能用 App.config 方式声明 PerMonitorV2。
        // 改用 API 在 Main 最早处主动声明，等价于 config 的 DpiAwareness=PerMonitorV2。
        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        private static readonly IntPtr PER_MONITOR_AWARE_V2 = new IntPtr(-4);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessDpiAwarenessContext(IntPtr value);

        [DllImport("shcore.dll", SetLastError = true)]
        private static extern int SetProcessDpiAwareness(int value);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessDPIAware();

        /// <summary>
        /// 声明进程 DPI awareness：PerMonitorV2 → PerMonitor → System → 失败。
        /// 必须在任何 WinForms 代码执行前调用（CLR 初始化后即可）。
        /// </summary>
        public static void EnableDpiAwareness()
        {
            // 1. Win10 1703+：PerMonitorV2（推荐）
            try
            {
                if (SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2))
                    return;
            }
            catch { } // 旧系统没有这个 API（EntryPointNotFoundException）

            // 2. Win8.1+：PerMonitor
            try
            {
                if (SetProcessDpiAwareness(2 /*PROCESS_PER_MONITOR_DPI_AWARE*/) == 0 /*S_OK*/)
                    return;
            }
            catch { }

            // 3. Vista+：System DPI Aware（最后兜底，总比模糊好）
            try
            {
                SetProcessDPIAware();
            }
            catch { }
        }
    }
}
