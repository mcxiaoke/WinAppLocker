using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// stub 注册表：扫描 stub/ 目录，加载所有 *.meta.json，提供按偏好选 stub 的方法。
    /// </summary>
    public static class StubRegistry
    {
        /// <summary>JSON 反序列化选项：字段缺失不报错</summary>
        private static readonly JsonSerializerOptions JsonOpts = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            AllowTrailingCommas = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
        };

        /// <summary>扫描 stubDir 下所有 *.meta.json，返回 StubManifest 列表</summary>
        public static List<StubManifest> LoadAll(string stubDir)
        {
            var result = new List<StubManifest>();
            if (string.IsNullOrEmpty(stubDir) || !Directory.Exists(stubDir)) return result;

            foreach (var metaFile in Directory.EnumerateFiles(stubDir, "*.meta.json"))
            {
                try
                {
                    var json = File.ReadAllText(metaFile);
                    var manifest = JsonSerializer.Deserialize<StubManifest>(json, JsonOpts);
                    if (manifest == null) continue;

                    manifest.MetaFilePath = metaFile;
                    manifest.StubDir = stubDir;

                    // 验证主文件存在
                    if (!File.Exists(manifest.MainFilePath))
                    {
                        manifest.MissingComponents.Add(manifest.MainFile ?? "(unknown)");
                    }

                    // 验证 components 存在（inplace-builder 模式）
                    if (manifest.Components != null)
                    {
                        foreach (var kv in manifest.Components)
                        {
                            var compPath = Path.Combine(stubDir, kv.Value);
                            if (!File.Exists(compPath))
                            {
                                manifest.MissingComponents.Add(kv.Value);
                            }
                        }
                    }

                    result.Add(manifest);
                }
                catch
                {
                    /* 跳过损坏的 meta 文件 */
                }
            }
            return result;
        }

        /// <summary>
        /// 根据偏好选 stub。
        /// 选择优先级：
        ///   1. 用户指定 preferName，且该 stub 可用 → 直接用
        ///   2. 按 PE 子系统匹配：tempfile 模式 + 子系统一致（兼容性更好）
        ///   3. 退而求其次：任意可用的 stub
        /// </summary>
        /// <param name="all">所有已加载的 stub</param>
        /// <param name="originalSubsystem">原 EXE 的子系统</param>
        /// <param name="machine">原 EXE 的 Machine（IMAGE_FILE_MACHINE_*），用于 WinLock 架构检查</param>
        /// <param name="preferName">用户指定的 stub name（可选）</param>
        /// <returns>选中的 stub，或 null（没有可用 stub）</returns>
        public static StubManifest Select(
            List<StubManifest> all,
            StubSubsystem originalSubsystem,
            ushort machine,
            string preferName = null)
        {
            if (all == null || all.Count == 0) return null;

            // 1. 用户指定 name，直接用（如果可用 + 架构匹配）
            if (!string.IsNullOrEmpty(preferName))
            {
                var found = all.Find(m => m.Name == preferName && m.IsAvailable && m.SupportsMachine(machine));
                if (found != null) return found;
            }

            // 2. 按子系统自动选：先 tempfile 模式（兼容性更好）
            var wantSubsystem = originalSubsystem == StubSubsystem.Console
                ? StubSubsystem.Console
                : StubSubsystem.Gui;

            var tempfile = all.Find(m =>
                m.IsAvailable &&
                m.Kind == StubKind.Tempfile &&
                m.Subsystem == wantSubsystem &&
                m.SupportsMachine(machine));
            if (tempfile != null) return tempfile;

            // 3. 退而求其次：任意可用且架构匹配的 stub
            return all.Find(m => m.IsAvailable && m.SupportsMachine(machine));
        }

        /// <summary>根据 name 查找指定 stub（不检查可用性，调用方自行判断 IsAvailable）</summary>
        public static StubManifest FindByName(List<StubManifest> all, string name)
        {
            if (string.IsNullOrEmpty(name) || all == null) return null;
            return all.Find(m => m.Name == name);
        }
    }
}
