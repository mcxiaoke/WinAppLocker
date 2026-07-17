using System;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace WinAppLocker.Stub
{
    /// <summary>
    /// 创建隐藏临时文件 + CreateProcessW 启动子进程 + 等待退出 + 删除。
    /// 临时文件名由调用方决定（用 _{原名}_ori.exe 而非 el_{pid}.exe，
    /// 让用户和 AV 从文件名能识别原程序）。
    /// </summary>
    internal static class ProcessLauncher
    {
        /// <summary>
        /// 在 originalDir/tempPath 写入 PE 字节，启动子进程，等待退出，删除临时文件。
        /// 返回子进程退出码。
        /// </summary>
        public static int LaunchAndWait(byte[] peBytes, string originalDir, string tempPath)
        {
            // 0. 如果上一次运行的临时文件残留（异常退出未清理），先删除
            TryDeleteIfExists(tempPath);

            // 1. 创建隐藏文件并写入 PE
            WriteHiddenFile(tempPath, peBytes);

            try
            {
                // 2. 启动子进程
                var si = new NativeMethods.STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(NativeMethods.STARTUPINFO));
                var pi = new NativeMethods.PROCESS_INFORMATION();

                bool ok = NativeMethods.CreateProcessW(
                    tempPath,
                    null,
                    IntPtr.Zero, IntPtr.Zero,
                    false,
                    NativeMethods.CREATE_UNICODE_ENVIRONMENT,
                    IntPtr.Zero,
                    originalDir,
                    ref si,
                    out pi);

                if (!ok)
                {
                    int err = Marshal.GetLastWin32Error();
                    throw new System.ComponentModel.Win32Exception(err);
                }

                NativeMethods.CloseHandle(pi.hThread);

                // 3. 等待子进程退出
                NativeMethods.WaitForSingleObject(pi.hProcess, NativeMethods.INFINITE);

                NativeMethods.GetExitCodeProcess(pi.hProcess, out uint exitCode);
                NativeMethods.CloseHandle(pi.hProcess);
                return (int)exitCode;
            }
            finally
            {
                // 4. 删除临时文件（带重试，应对 OS 异步释放 / 杀软扫描占用）
                TryDeleteWithRetry(tempPath);
            }
        }

        /// <summary>CreateFileW + FILE_ATTRIBUTE_HIDDEN，文件从创建起就隐藏。</summary>
        private static void WriteHiddenFile(string path, byte[] data)
        {
            IntPtr handle = NativeMethods.CreateFileW(
                path,
                NativeMethods.GENERIC_WRITE,
                NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE | NativeMethods.FILE_SHARE_DELETE,
                IntPtr.Zero,
                NativeMethods.CREATE_ALWAYS,
                NativeMethods.FILE_ATTRIBUTE_HIDDEN | NativeMethods.FILE_ATTRIBUTE_TEMPORARY,
                IntPtr.Zero);

            if (handle == NativeMethods.INVALID_HANDLE_VALUE)
            {
                int err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(err);
            }

            try
            {
                // 使用 SafeFileHandle 避免 CS0618 (FileStream(IntPtr, FileAccess) 已过时)
                var safeHandle = new SafeFileHandle(handle, true);
                using (var fs = new System.IO.FileStream(safeHandle, System.IO.FileAccess.Write))
                {
                    fs.Write(data, 0, data.Length);
                    fs.Flush();
                }
            }
            finally
            {
                // SafeFileHandle 会接管 Close，这里不再调 NativeMethods.CloseHandle
            }
        }

        private static void TryDeleteIfExists(string path)
        {
            try
            {
                if (System.IO.File.Exists(path))
                    System.IO.File.Delete(path);
            }
            catch (System.IO.IOException) { }
            catch (System.UnauthorizedAccessException) { }
        }

        /// <summary>5 次 × 50ms 重试删除，失败只静默忽略。</summary>
        private static void TryDeleteWithRetry(string path)
        {
            for (int i = 0; i < 5; i++)
            {
                try
                {
                    if (!System.IO.File.Exists(path)) return;
                    System.IO.File.Delete(path);
                    return;
                }
                catch (System.IO.IOException) { Thread.Sleep(50); }
                catch (System.UnauthorizedAccessException) { Thread.Sleep(50); }
            }
            // 删除失败不抛异常，残留可手动清理
        }
    }
}
