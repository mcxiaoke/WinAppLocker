using System;

namespace WinAppLocker.Stub
{
    /// <summary>
    /// Test stub 错误显示：写到 stderr，便于自动化测试观察。
    /// </summary>
    internal static class ErrorReporter
    {
        public static void Show(string message, string detail = null)
        {
            string text = string.IsNullOrEmpty(detail) ? message : $"{message}: {detail}";
            Console.Error.WriteLine($"[stub_test ERROR] {text}");
        }
    }
}
