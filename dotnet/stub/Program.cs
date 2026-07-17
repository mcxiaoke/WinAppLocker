using System;

namespace WinAppLocker.Stub
{
    internal static class Program
    {
        [STAThread]
        private static int Main()
        {
            // stub 运行时没有 exe.config 旁边（payload 追加在 stub exe 末尾），
            // 无法用 App.config 声明 PerMonitorV2。改用 Win32 API 在 Main 最早处声明。
            // 必须在任何 WinForms 代码执行前调用，否则 PerMonitorV2 不会生效。
            NativeMethods.EnableDpiAwareness();

            try
            {
                return StubEntry.Run();
            }
            catch (Exception ex)
            {
                System.Windows.Forms.MessageBox.Show(ex.Message, "WinAppLocker", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Error);
                return 99;
            }
        }
    }
}
