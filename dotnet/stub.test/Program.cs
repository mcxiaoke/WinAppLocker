using System;

namespace WinAppLocker.Stub
{
    internal static class Program
    {
        private static int Main()
        {
            // 声明 DPI awareness（统一调用，保持三个 stub 一致）
            NativeMethods.EnableDpiAwareness();

            Console.Error.WriteLine($"[stub_test] WinAppLocker stub v{VersionInfo.Version} (git: {VersionInfo.GitHash})");
            Console.Error.WriteLine($"[stub_test] 警告：此 stub 内置密码，仅用于自动化测试，请勿用于实际加密");
            try
            {
                return StubEntry.Run();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[stub_test FATAL] {ex.Message}");
                Console.Error.WriteLine($"[stub_test FATAL] {ex.StackTrace}");
                return 99;
            }
        }
    }
}
