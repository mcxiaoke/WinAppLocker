using System;

namespace WinAppLocker.Stub
{
    internal static class Program
    {
        private static int Main()
        {
            // 声明 DPI awareness（console stub 无 GUI，但统一调用无害，保持一致性）
            NativeMethods.EnableDpiAwareness();

            try
            {
                return StubEntry.Run();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[FATAL] {ex.Message}");
                return 99;
            }
        }
    }
}
