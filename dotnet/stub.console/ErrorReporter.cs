using System;

namespace WinAppLocker.Stub
{
    /// <summary>
    /// Console stub 错误显示：写到 stderr。
    /// </summary>
    internal static class ErrorReporter
    {
        public static void Show(string message, string detail = null)
        {
            string text = string.IsNullOrEmpty(detail) ? message : $"{message}: {detail}";
            Console.Error.WriteLine($"[ERROR] {text}");
        }
    }
}
