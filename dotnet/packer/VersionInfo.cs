using System.Reflection;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// Packer 版本信息。从编译期注入的 AssemblyMetadata 读取（参考 vault 项目）。
    /// Directory.Build.props 的 GenerateCustomVersion Target 注入：
    ///   - InformationalVersion（如 "0.1.0-20260717-abc1234"）
    ///   - AssemblyMetadata("GitCommit")
    ///   - AssemblyMetadata("BuildTime")
    /// </summary>
    public static class VersionInfo
    {
        /// <summary>版本字符串（如 "0.1.0-20260717-abc1234" 或 "0.1.0-debug"）</summary>
        public static string Version { get; } = ReadVersion();

        /// <summary>Git short commit hash</summary>
        public static string GitHash { get; } = ReadMetadata("GitCommit") ?? "unknown";

        /// <summary>构建时间（本地时区字符串）</summary>
        public static string BuildTime { get; } = ReadMetadata("BuildTime") ?? "unknown";

        private static string ReadVersion()
        {
            var asm = Assembly.GetExecutingAssembly();
            var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
            if (info != null && !string.IsNullOrEmpty(info.InformationalVersion))
            {
                var v = info.InformationalVersion;
                return v.StartsWith("v") ? v : "v" + v;
            }
            var av = asm.GetName().Version;
            return av != null ? "v" + av.ToString(3) : "v0.1.0";
        }

        private static string ReadMetadata(string key)
        {
            var asm = Assembly.GetExecutingAssembly();
            foreach (var attr in asm.GetCustomAttributes<AssemblyMetadataAttribute>())
            {
                if (string.Equals(attr.Key, key, System.StringComparison.Ordinal))
                    return attr.Value;
            }
            return null;
        }
    }
}
