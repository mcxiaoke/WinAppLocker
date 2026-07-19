using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinAppLocker.Packer
{
    /// <summary>stub 加壳方案（区分 tempfile 与 in-place 加壳）</summary>
    public enum StubKind
    {
        /// <summary>临时文件模式：原 EXE 作为 payload 附加在 stub 后，运行时释放临时文件</summary>
        Tempfile,

        /// <summary>in-place 加壳模式：原 EXE 被原地修改，stub 嵌入 .lock 节（WinLock）</summary>
        InplaceBuilder,
    }

    /// <summary>stub 支持的子系统</summary>
    public enum StubSubsystem
    {
        /// <summary>GUI 程序：弹窗密码框</summary>
        Gui,

        /// <summary>Console 程序：命令行密码输入</summary>
        Console,

        /// <summary>测试：硬编码密码，跳过输入</summary>
        Test,
    }

    /// <summary>
    /// stub 元数据（从同名 .meta.json 反序列化）。
    /// 每个 stub exe/bin 旁边放一个 .meta.json 描述其属性。
    /// </summary>
    public class StubManifest
    {
        /// <summary>唯一标识，packer 内部引用用（如 "winlock"、"applocker-gui"）</summary>
        [JsonPropertyName("name")]
        public string Name { get; set; }

        /// <summary>加壳方案字符串："tempfile" 或 "inplace-builder"</summary>
        [JsonPropertyName("kind")]
        public string KindStr { get; set; }

        /// <summary>子系统字符串："gui" / "console" / "test"</summary>
        [JsonPropertyName("subsystem")]
        public string SubsystemStr { get; set; }

        /// <summary>人类可读说明</summary>
        [JsonPropertyName("description")]
        public string Description { get; set; }

        /// <summary>版本号</summary>
        [JsonPropertyName("version")]
        public string Version { get; set; }

        /// <summary>仅 inplace-builder 用：列出依赖的 stub 文件（key=逻辑名, value=文件名）</summary>
        [JsonPropertyName("components")]
        public Dictionary<string, string> Components { get; set; }

        /// <summary>仅 inplace-builder 用：支持的 PE 架构列表（"amd64" / "i386"）</summary>
        [JsonPropertyName("supported_machines")]
        public List<string> SupportedMachines { get; set; }

        /// <summary>可选：要求 packer 最低版本</summary>
        [JsonPropertyName("min_packer_version")]
        public string MinPackerVersion { get; set; }

        /// <summary>stub/ 目录绝对路径（运行时填入）</summary>
        [JsonIgnore]
        public string StubDir { get; set; }

        /// <summary>.meta.json 文件完整路径（运行时填入）</summary>
        [JsonIgnore]
        public string MetaFilePath { get; set; }

        /// <summary>缺失的主文件或 components 文件名列表（运行时填入）</summary>
        [JsonIgnore]
        public List<string> MissingComponents { get; set; } = new List<string>();

        /// <summary>解析后的加壳方案</summary>
        [JsonIgnore]
        public StubKind Kind => KindStr == "inplace-builder" ? StubKind.InplaceBuilder : StubKind.Tempfile;

        /// <summary>解析后的子系统</summary>
        [JsonIgnore]
        public StubSubsystem Subsystem => SubsystemStr switch
        {
            "console" => StubSubsystem.Console,
            "test" => StubSubsystem.Test,
            _ => StubSubsystem.Gui,
        };

        /// <summary>
        /// 主文件名（去掉 .meta.json 后缀）。
        /// 例：meta 文件 "stub_gui.exe.meta.json" → 主文件 "stub_gui.exe"
        /// </summary>
        [JsonIgnore]
        public string MainFile
        {
            get
            {
                if (string.IsNullOrEmpty(MetaFilePath)) return null;
                string fn = Path.GetFileName(MetaFilePath);
                // 去掉 ".meta.json" 后缀（11 字符）
                if (fn.EndsWith(".meta.json"))
                    return fn.Substring(0, fn.Length - ".meta.json".Length);
                return fn;
            }
        }

        /// <summary>主文件完整路径（stub/ 目录 + 主文件名）</summary>
        [JsonIgnore]
        public string MainFilePath => string.IsNullOrEmpty(MainFile) ? null : Path.Combine(StubDir ?? "", MainFile);

        /// <summary>是否完整可用（主文件 + 所有 components 都存在）</summary>
        [JsonIgnore]
        public bool IsAvailable => File.Exists(MainFilePath) && MissingComponents.Count == 0;

        /// <summary>仅 WinLock 模式：是否支持指定 PE 架构（IMAGE_FILE_MACHINE_AMD64=0x8664 / I386=0x14c）</summary>
        public bool SupportsMachine(ushort machine)
        {
            if (SupportedMachines == null || SupportedMachines.Count == 0) return true;
            string want = machine == 0x8664 ? "amd64" : (machine == 0x14c ? "i386" : null);
            if (want == null) return false;
            return SupportedMachines.Contains(want);
        }

        public override string ToString() => $"{Name} ({KindStr}/{SubsystemStr})";
    }
}
