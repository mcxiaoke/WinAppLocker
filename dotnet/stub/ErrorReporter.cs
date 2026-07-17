namespace WinAppLocker.Stub
{
    /// <summary>
    /// 错误显示抽象。每个 stub 项目提供自己的实现（GUI=MessageBox，Console=stderr）。
    /// StubEntry 通过此类解耦 UI。
    /// </summary>
    internal static class ErrorReporter
    {
        public static void Show(string message, string detail = null)
        {
            string text = string.IsNullOrEmpty(detail) ? message : $"{message}\n\n{detail}";
            System.Windows.Forms.MessageBox.Show(text, "WinAppLocker",
                System.Windows.Forms.MessageBoxButtons.OK,
                System.Windows.Forms.MessageBoxIcon.Error);
        }
    }
}
