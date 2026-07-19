using System;
using System.IO;
using System.Reflection;
using System.Threading;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// 应用操作日志器：把关键操作记录到日志文件，便于事后排查问题。
    ///
    /// 日志目录选择策略（首次写入时确定，之后缓存）：
    ///   1. 优先：packer exe 同目录下的 logs/ 子目录
    ///      （例如 X:\path\WinAppLocker.exe → X:\path\logs\）
    ///   2. 回退：%LOCALAPPDATA%\WinAppLocker\logs\
    ///      （exe 同目录不可写时，例如装在 Program Files）
    ///
    /// 日志文件按天滚动：packer_YYYYMMDD.log，追加模式。
    /// 所有 IO 异常都被吞掉（日志不能让主流程崩溃）。
    /// 线程安全：通过 lock 保护文件写入。
    /// </summary>
    internal static class AppLogger
    {
        private static readonly object _lock = new object();
        private static string _logDir;
        private static string _logFilePath;

        // 日志级别标签
        private const string TagInfo = "INFO";
        private const string TagWarn = "WARN";
        private const string TagError = "ERROR";

        /// <summary>当前使用的日志目录（已缓存）。仅供诊断/显示用。</summary>
        public static string LogDirectory
        {
            get
            {
                if (_logDir == null) EnsureLogDirectory();
                return _logDir;
            }
        }

        /// <summary>INFO 级日志</summary>
        public static void Info(string message)
        {
            Write(TagInfo, message, null);
        }

        /// <summary>WARN 级日志</summary>
        public static void Warn(string message)
        {
            Write(TagWarn, message, null);
        }

        /// <summary>ERROR 级日志（带异常）</summary>
        public static void Error(string message, Exception ex)
        {
            Write(TagError, ex == null ? message : $"{message}\n  异常: {ex.GetType().Name}: {ex.Message}\n  堆栈:\n{ex.StackTrace}", null);
        }

        /// <summary>ERROR 级日志（仅消息）</summary>
        public static void Error(string message)
        {
            Write(TagError, message, null);
        }

        /// <summary>确定日志目录：优先 exe 同目录 logs/，失败回退 LocalAppData</summary>
        private static void EnsureLogDirectory()
        {
            if (_logDir != null) return;
            lock (_lock)
            {
                if (_logDir != null) return;

                string exeDir = null;
                try
                {
                    string exePath = Assembly.GetExecutingAssembly().Location;
                    if (!string.IsNullOrEmpty(exePath))
                        exeDir = Path.GetDirectoryName(exePath);
                }
                catch { /* 忽略，走 fallback */ }

                // 1. 试 exe 同目录下的 logs/
                string primaryDir = null;
                if (!string.IsNullOrEmpty(exeDir))
                    primaryDir = Path.Combine(exeDir, "logs");

                if (primaryDir != null && TryEnsureWritable(primaryDir))
                {
                    _logDir = primaryDir;
                }
                else
                {
                    // 2. 回退到 %LOCALAPPDATA%\WinAppLocker\logs\
                    string fallbackDir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "WinAppLocker", "logs");
                    try
                    {
                        Directory.CreateDirectory(fallbackDir);
                        _logDir = fallbackDir;
                    }
                    catch
                    {
                        // 实在没办法，禁用日志
                        _logDir = null;
                    }
                }

                // 日志文件名按天滚动
                if (_logDir != null)
                    _logFilePath = Path.Combine(_logDir, $"packer_{DateTime.Now:yyyyMMdd}.log");
            }
        }

        /// <summary>尝试创建目录并验证可写：写一个测试字节再删除</summary>
        private static bool TryEnsureWritable(string dir)
        {
            try
            {
                if (!Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                // 用一个临时文件测试可写
                string testFile = Path.Combine(dir, $".write_test_{Guid.NewGuid():N}");
                File.WriteAllText(testFile, "t");
                File.Delete(testFile);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>实际写入日志行</summary>
        private static void Write(string level, string message, string extra)
        {
            try
            {
                EnsureLogDirectory();
                if (_logFilePath == null) return;

                // 跨天时切换到当天的日志文件
                string todayPath = Path.Combine(_logDir, $"packer_{DateTime.Now:yyyyMMdd}.log");
                if (!string.Equals(todayPath, _logFilePath, StringComparison.OrdinalIgnoreCase))
                {
                    Interlocked.Exchange(ref _logFilePath, todayPath);
                }

                string line = $"{DateTime.Now:HH:mm:ss.fff} [{level}] {message}";
                if (extra != null) line += "\n" + extra;

                lock (_lock)
                {
                    File.AppendAllText(_logFilePath, line + Environment.NewLine);
                }
            }
            catch
            {
                // 日志失败不能影响主流程
            }
        }
    }
}
