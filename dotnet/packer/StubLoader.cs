using System;
using System.IO;
using System.Reflection;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// 从 packer 的嵌入资源中加载 stub 字节，并提供基于 PE 子系统的自动选择。
    /// </summary>
    internal static class StubLoader
    {
        /// <summary>选择 stub 字节。</summary>
        public static byte[] SelectStub(ushort subsystem, StubKind pref)
        {
            string name;
            switch (pref)
            {
                case StubKind.Gui:
                    name = "stub_gui.exe";
                    break;
                case StubKind.Console:
                    name = "stub_console.exe";
                    break;
                case StubKind.Test:
                    name = "stub_test.exe";
                    break;
                case StubKind.Auto:
                    name = subsystem == (ushort)2 /* WindowsGui */
                        ? "stub_gui.exe"
                        : "stub_console.exe";
                    break;
                default:
                    throw new ArgumentException($"unknown stub preference {pref}");
            }
            return LoadEmbedded(name);
        }

        private static byte[] LoadEmbedded(string name)
        {
            var asm = Assembly.GetExecutingAssembly();
            // SDK-style csproj 的 EmbeddedResource 默认会用项目默认命名空间 + 文件相对路径
            // 这里 packer 默认命名空间是 WinAppLocker.Packer，资源在 Resources/ 目录下
            string[] candidates = new[]
            {
                $"WinAppLocker.Packer.Resources.{name}",
                $"WinAppLocker.Packer.{name}",
                name
            };

            foreach (var rid in candidates)
            {
                using (var s = asm.GetManifestResourceStream(rid))
                {
                    if (s == null) continue;
                    using (var ms = new MemoryStream())
                    {
                        s.CopyTo(ms);
                        return ms.ToArray();
                    }
                }
            }
            throw new InvalidOperationException($"嵌入资源 {name} 未找到。请先构建 stub。");
        }

        /// <summary>
        /// 在 stub 字节中搜索 WAL_VER|...|WAL_END 标记（UTF-16 编码），
        /// 返回 "version (git, build_time)" 或 null。
        /// </summary>
        public static string ReadStubVersion(byte[] stubBytes)
        {
            // stub 把版本信息存为 const string，C# 编译器把字符串字面量存到 metadata #US 堆
            // 因此 stub 字节中存在 UTF-16 编码的 WAL_VER|...|WAL_END
            byte[] startBytes = System.Text.Encoding.Unicode.GetBytes(PayloadFormat.VersionBlobStart);
            byte[] endBytes = System.Text.Encoding.Unicode.GetBytes(PayloadFormat.VersionBlobEnd);

            int start = ByteSearch.IndexOf(stubBytes, startBytes);
            if (start < 0) return null;
            int end = ByteSearch.IndexOf(stubBytes, endBytes, start + startBytes.Length);
            if (end < 0) return null;

            int blobEnd = end + endBytes.Length;
            string blob = System.Text.Encoding.Unicode.GetString(stubBytes, start, blobEnd - start);
            // WAL_VER|version|build_time|git_hash|WAL_END
            string inner = blob.Substring(PayloadFormat.VersionBlobStart.Length,
                blob.Length - PayloadFormat.VersionBlobStart.Length - PayloadFormat.VersionBlobEnd.Length);
            string[] parts = inner.Split('|');
            if (parts.Length >= 3)
                return $"{parts[0]} (git: {parts[2]}, build: {parts[1]})";
            return null;
        }
    }
}
