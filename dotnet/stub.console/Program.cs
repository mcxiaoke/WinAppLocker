using System;

namespace WinAppLocker.Stub
{
    internal static class Program
    {
        private static int Main()
        {
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
