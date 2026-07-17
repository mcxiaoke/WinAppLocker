using System;

namespace WinAppLocker.Stub
{
    internal static class Program
    {
        [STAThread]
        private static int Main()
        {
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
