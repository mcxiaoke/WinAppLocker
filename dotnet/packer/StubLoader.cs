using System;
using System.IO;
using System.Reflection;
using WinAppLocker.Shared;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// stub 字节加载器：支持两种来源
    ///   1. 嵌入资源（兼容旧发布模式：单文件 exe）
    ///   2. stub/ 目录（新发布模式：exe + stub/ 目录，支持 WinLock）
    /// 优先用 stub/ 目录，找不到则退回嵌入资源。
    /// </summary>
    internal static class StubLoader
    {
        /// <summary>选择 stub 字节。</summary>
        public static byte[] SelectStub(ushort subsystem, StubPreference pref)
        {
            string name;
            switch (pref)
            {
                case StubPreference.Gui:
                    name = "stub_gui.exe";
                    break;
                case StubPreference.Console:
                    name = "stub_console.exe";
                    break;
                case StubPreference.Test:
                    name = "stub_test.exe";
                    break;
                case StubPreference.Auto:
                    name = subsystem == (ushort)2 /* WindowsGui */
                        ? "stub_gui.exe"
                        : "stub_console.exe";
                    break;
                default:
                    throw new ArgumentException($"unknown stub preference {pref}");
            }
            // 优先从 stub/ 目录读
            string stubDir = FindStubDir();
            string stubPath = Path.Combine(stubDir, name);
            if (File.Exists(stubPath))
            {
                return File.ReadAllBytes(stubPath);
            }
            // 退回嵌入资源
            return LoadEmbedded(name);
        }

        /// <summary>从 stub/ 目录加载指定文件名的 stub 字节。不存在则抛异常。</summary>
        public static byte[] LoadFromStubDir(string stubDir, string fileName)
        {
            string path = Path.Combine(stubDir, fileName);
            if (!File.Exists(path))
                throw new FileNotFoundException($"stub 文件不存在: {path}");
            return File.ReadAllBytes(path);
        }

        /// <summary>
        /// 定位 stub/ 目录：
        ///   1. packer exe 同目录的 stub/
        ///   2. （fallback）当前工作目录的 stub/
        /// </summary>
        public static string FindStubDir()
        {
            string exeDir = Path.GetDirectoryName(
                Assembly.GetExecutingAssembly().Location);
            string stubDir = Path.Combine(exeDir, "stub");
            if (Directory.Exists(stubDir)) return stubDir;
            // fallback
            string cwdStub = Path.Combine(Directory.GetCurrentDirectory(), "stub");
            return cwdStub;
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
            throw new InvalidOperationException(
                $"找不到 stub：既不在 stub/ 目录，也不在嵌入资源。请先构建 stub 或检查 stub/ 目录。\n" +
                $"期望文件: {name}");
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
