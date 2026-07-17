using System;
using System.Text;

namespace WinAppLocker.Stub
{
    /// <summary>
    /// Console stub 密码输入：用 Console.ReadKey 隐藏输入。
    /// 取消返回 null。
    /// </summary>
    internal static class PasswordReader
    {
        public static string Ask(string title)
        {
            Console.WriteLine(title);
            return ReadConsole();
        }

        private static string ReadConsole()
        {
            Console.Write("请输入密码: ");
            // 若输入被重定向（管道/脚本），ReadKey 会抛异常；fallback 到 ReadLine
            if (Console.IsInputRedirected)
            {
                string line = Console.ReadLine();
                return line;
            }

            var sb = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                    {
                        sb.Remove(sb.Length - 1, 1);
                        Console.Write("\b \b");
                    }
                }
                else if (key.Key == ConsoleKey.Escape)
                {
                    Console.WriteLine();
                    return null;
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    sb.Append(key.KeyChar);
                    Console.Write("*");
                }
            }
            Console.WriteLine();
            return sb.ToString();
        }
    }
}
