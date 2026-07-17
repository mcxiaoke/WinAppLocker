using System;

namespace WinAppLocker.Stub
{
    /// <summary>
    /// Test stub 密码输入：返回内置固定密码 "test1234"，跳过任何 UI（自动化测试用）。
    /// packer 用 --stub Test 时必须配合 -p test1234 打包。
    /// </summary>
    internal static class PasswordReader
    {
        public const string TestPassword = "test1234";

        public static string Ask(string title)
        {
            Console.Error.WriteLine($"[stub_test] 使用内置密码（长度 {TestPassword.Length}），跳过密码输入 UI");
            return TestPassword;
        }
    }
}
