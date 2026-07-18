# WinLock 集成到 AppLocker (.NET) 方案

> 创建日期：2026-07-18
> 目标：把 WinLock（in-place PE 加壳器）作为 AppLocker 的可选 stub 模式之一集成，
> 让用户在"临时文件模式"（现有）和"in-place 加壳模式"（WinLock）之间选择。

---

## 1. 背景与动机

### 1.1 两种方案对比

| 维度 | AppLocker 现方案（临时文件） | WinLock（in-place 加壳） |
|------|---------------------------|------------------------|
| **加密范围** | 整个原 EXE 文件字节 | 仅 `.text` 节的 RawData |
| **原 EXE 是否被修改** | 不修改，原 EXE 作为 payload 附加在 stub 后 | 原地修改：新增 `.lock` 节、改 EP、`.text` 改为密文 |
| **PE 加载方式** | Windows loader 加载 stub 释放的临时文件（干净环境） | Windows loader 加载加壳后的 PE（已注入 stub） |
| **运行时是否需要外部文件** | 需要：临时文件（运行期间存在明文 PE） | 不需要：完全单文件，内存中解密 |
| **磁盘明文残留风险** | 有：异常退出可能残留临时文件 | 无：解密在内存中进行 |
| **兼容性** | 极高（等同于原 EXE 直接运行） | 中（受 loader hook / 自校验限制） |
| **stub 实现** | C# / .NET（有 CRT，普通程序） | C + 内联汇编（PIC，无 CRT，PEB walk） |
| **架构支持** | 任意（stub AnyCPU，原 EXE 作为数据） | 必须按目标架构选 stub_x64 / stub_x86 |
| **加密算法** | AES-256-CBC + HMAC-SHA256 + PBKDF2 | XTEA + SHA-256 |

### 1.2 集成目标

- WinLock 作为**可选模式**，默认仍用临时文件方案
- 用户在 UI 上能选择"WinLock 模式"，明确知晓兼容性差异
- WinLock 模式生成的加壳 exe **运行时完全独立**，不需要任何外部文件
- WinLock 与 AppLocker 现方案**完全解耦**，可独立替换

### 1.3 WinLock 当前能力与限制

**能力**：
- x64 + x86 双架构支持
- ASLR 兼容（x64 PIC + x86 预 patch reloc）
- TLS callback 代理（原 PE 有 TLS callbacks 也能加壳）
- SHA-256 密码 hash + salt 防 dump 破解
- CFG 标志自动清除
- Authenticode 签名自动剥离

**限制**（已在 winlock README 详细说明）：
- ❌ Chrome：`chrome_elf.dll` 在 loader 阶段注册 UIA hook → loader lock 死锁
- ❌ QQ：`FirstLoad.dll` 调用 `WinVerifyTrust` 验证签名 → 加壳后签名失效
- ❌ 任何带自校验（hash / checksum / 签名）的程序
- ❌ 仅支持 GUI 程序（stub 用 `DialogBoxIndirectParamW` 弹密码框），不支持 console 密码输入
- ❌ 不支持 DLL（仅 EXE）
- ❌ 不支持 .NET CLR 托管 PE

---

## 2. 架构设计

### 2.1 整体架构

```
applocker/
├── applocker.exe                  # packer（C#），不嵌入任何 stub
├── stub/                          # 所有 stub 放这里
│   ├── stub_gui.exe               # AppLocker 现方案 stub（GUI）
│   ├── stub_gui.exe.meta.json
│   ├── stub_console.exe           # AppLocker 现方案 stub（Console）
│   ├── stub_console.exe.meta.json
│   ├── stub_test.exe              # AppLocker 现方案 stub（Test）
│   ├── stub_test.exe.meta.json
│   ├── winlock_builder.exe        # WinLock 加壳器（打包时用，x64 单文件）
│   ├── winlock_builder.exe.meta.json
│   ├── stub_x64.bin               # WinLock 运行时 stub（x64）
│   ├── stub_x64.bin.meta.json
│   ├── stub_x86.bin               # WinLock 运行时 stub（x86）
│   └── stub_x86.bin.meta.json
└── (运行加壳后的 exe 时，以上都不需要)
```

**关键点**：
- **不嵌入资源**：packer.exe 不再 `include_bytes!` 或 EmbeddedResource 任何 stub
- **运行时扫描**：packer 启动时扫 `stub/` 目录，读所有 `.meta.json` 建立可用 stub 列表
- **可独立替换**：替换 stub 文件 + meta.json 即可，不用重编 packer

### 2.2 三种角色

| 角色 | 何时用 | 文件 |
|------|--------|------|
| **AppLocker 临时 stub** | 用户运行加壳后 exe 时 | `stub_gui.exe` / `stub_console.exe` / `stub_test.exe` |
| **WinLock builder** | packer 加壳时（打包时） | `winlock_builder.exe` |
| **WinLock stub.bin** | packer 加壳时（builder 读取并嵌入目标 PE） | `stub_x64.bin` / `stub_x86.bin` |

**WinLock 模式运行时（用户运行加壳后 exe）完全不需要任何外部文件** — builder 把 stub.bin 嵌入到目标 PE 的 `.lock` 节，运行时 stub 在目标进程内执行。

### 2.3 两种 stub "kind" 概念

引入 `StubKind` 抽象区分加壳方案：

```csharp
public enum StubKind
{
    /// <summary>临时文件模式：原 EXE 作为 payload 附加在 stub 后，运行时释放临时文件</summary>
    Tempfile,

    /// <summary>in-place 加壳模式：原 EXE 被原地修改，stub 嵌入 .lock 节</summary>
    InplaceBuilder,
}
```

### 2.4 stub 子系统

```csharp
public enum StubSubsystem
{
    Gui,        // GUI 程序：弹窗密码框
    Console,    // Console 程序：命令行密码输入
    Test,       // 测试：硬编码密码，跳过输入
}
```

WinLock 当前**仅支持 Gui**。如果原 EXE 是 Console 子系统且用户选 WinLock，packer 应警告并建议改用 AppLocker Console 模式。

---

## 3. stub 元数据格式

### 3.1 meta.json schema

每个 stub（或 builder）旁边放一个同名 `.meta.json`：

```json
{
  "name": "<唯一标识>",
  "kind": "tempfile | inplace-builder",
  "subsystem": "gui | console | test",
  "description": "<人类可读说明>",
  "version": "<版本号>",
  "components": {
    "stub_x64": "stub_x64.bin",
    "stub_x86": "stub_x86.bin"
  },
  "supported_machines": ["amd64", "i386"],
  "min_packer_version": "<可选，要求 packer 最低版本>"
}
```

字段说明：
- `name`：唯一标识，packer 内部引用用（如 `winlock`、`applocker-gui`）
- `kind`：加壳方案，决定 packer 走哪条加密路径
- `subsystem`：stub 支持的子系统（WinLock 目前只有 `gui`）
- `components`：仅 `inplace-builder` 用，列出依赖的 stub.bin
- `supported_machines`：仅 `inplace-builder` 用，列出支持的 PE 架构
- `min_packer_version`：可选，packer 低于此版本不显示该 stub

### 3.2 各 stub 的 meta.json 实例

#### stub_gui.exe.meta.json（AppLocker 现方案 GUI）
```json
{
  "name": "applocker-gui",
  "kind": "tempfile",
  "subsystem": "gui",
  "description": "AppLocker GUI stub (tempfile mode)",
  "version": "1.0.0"
}
```

#### stub_console.exe.meta.json（AppLocker 现方案 Console）
```json
{
  "name": "applocker-console",
  "kind": "tempfile",
  "subsystem": "console",
  "description": "AppLocker Console stub (tempfile mode)",
  "version": "1.0.0"
}
```

#### stub_test.exe.meta.json（AppLocker 现方案 Test）
```json
{
  "name": "applocker-test",
  "kind": "tempfile",
  "subsystem": "test",
  "description": "AppLocker Test stub (hardcoded password test1234)",
  "version": "1.0.0"
}
```

#### winlock_builder.exe.meta.json（WinLock 加壳器）
```json
{
  "name": "winlock",
  "kind": "inplace-builder",
  "subsystem": "gui",
  "description": "WinLock in-place packer (GUI dialog, no plaintext tempfile)",
  "version": "2.0.0",
  "components": {
    "stub_x64": "stub_x64.bin",
    "stub_x86": "stub_x86.bin"
  },
  "supported_machines": ["amd64", "i386"]
}
```

#### stub_x64.bin.meta.json / stub_x86.bin.meta.json
**可以省略** — 这两个文件被 `winlock_builder.exe.meta.json` 的 `components` 字段引用，
packer 通过 builder 的 meta 间接知道它们的存在。在 builder 的 meta 找到 `components.stub_x64`
时，packer 验证 `stub_x64.bin` 文件存在即可。

### 3.3 packer 启动时扫描逻辑

```csharp
public static class StubRegistry
{
    /// <summary>扫描 stubDir 下所有 *.meta.json，加载为 StubManifest 列表。</summary>
    public static List<StubManifest> LoadAll(string stubDir)
    {
        var result = new List<StubManifest>();
        foreach (var metaFile in Directory.EnumerateFiles(stubDir, "*.meta.json"))
        {
            try
            {
                var json = File.ReadAllText(metaFile);
                var manifest = JsonSerializer.Deserialize<StubManifest>(json);
                // 验证主文件存在
                var mainFile = Path.Combine(stubDir, manifest.File);
                if (!File.Exists(mainFile)) continue;
                // 验证 components 存在（inplace-builder 模式）
                if (manifest.Components != null)
                {
                    foreach (var kv in manifest.Components)
                    {
                        var compFile = Path.Combine(stubDir, kv.Value);
                        if (!File.Exists(compFile))
                        {
                            manifest.MissingComponents.Add(kv.Key);
                        }
                    }
                }
                manifest.StubDir = stubDir;
                result.Add(manifest);
            }
            catch { /* 跳过损坏的 meta */ }
        }
        return result;
    }
}
```

---

## 4. WinLock 侧需要的改动

### 4.1 builder.c 加 `--stub-dir` 参数

**目的**：让 packer 调用 builder 时能指定 stub.bin 所在目录，避免硬编码 `stub/` 相对路径。

**改动位置**：`F:\Temp\pe\winlock\builder\builder.c` 第 437 行 `main()` 函数 + 第 782-806 行 stub.bin 搜索逻辑。

**当前行为**：builder 按 `stub/stub_x64.bin` → `stub_x64.bin` → `<argv0>/stub/stub_x64.bin` 顺序找。

**改后行为**：加 `--stub-dir <path>` 参数，优先从指定目录找 stub.bin。

伪代码：
```c
static const char* g_stub_dir = "stub";  /* 默认 */

/* 参数解析时 */
} else if (strcmp(argv[i], "--stub-dir") == 0) {
    if (i + 1 >= argc) { printf("[-] --stub-dir requires argument\n"); return 1; }
    g_stub_dir = argv[++i];
}

/* 找 stub.bin 时 */
char path[512];
snprintf(path, sizeof(path), "%s/stub_%s.bin", g_stub_dir, g_is_x64 ? "x64" : "x86");
stub = read_file(path, &stub_size);
```

**工作量**：约 30 行 C 代码改动。

### 4.2 builder 输出结构化结果（可选但推荐）

**目的**：让 packer 容易解析 builder 成功/失败，不靠解析 stdout 文本。

**当前行为**：builder 成功输出 `[+] Run        : <path>`，失败输出 `[-] <error>`，返回码 0/1。

**改进**：加 `--json` 参数，输出 JSON 结果：
```json
{"success": true, "output": "C:\\path\\to\\locked.exe", "arch": "x64"}
```
或
```json
{"success": false, "error": "Cannot read stub_x64.bin"}
```

**工作量**：约 20 行 C 代码（加个 `--json` flag，结尾根据 flag 输出 JSON 或人类可读文本）。

如果不实现 JSON，packer 也可以靠 return code 判断成功失败（0=成功，非 0=失败），靠 stdout 做日志。

### 4.3 WinLock 当前文件清单（要复制到 applocker/stub/）

| 源文件 | 目标文件 | 大小 | 说明 |
|--------|---------|------|------|
| `F:\Temp\pe\winlock\builder\builder.exe` | `stub/winlock_builder.exe` | ~105 KB | WinLock 加壳器 |
| `F:\Temp\pe\winlock\stub\stub_x64.bin` | `stub/stub_x64.bin` | ~6.5 KB | WinLock x64 stub |
| `F:\Temp\pe\winlock\stub\stub_x86.bin` | `stub/stub_x86.bin` | ~6.8 KB | WinLock x86 stub |

**注意**：不要复制 `stub_x64.exe` / `stub_x86.exe`（那只是 builder 用来读 .reloc 节的中间产物，
x64 stub 是 PIC 不需要 .reloc，x86 stub 的 .reloc 信息已经编进 builder.exe 里了 — 实际上
builder 还会从 stub_x86.exe 读 .reloc，所以**stub_x86.exe 也要复制**）。

修正文件清单：

| 源文件 | 目标文件 | 大小 | 说明 |
|--------|---------|------|------|
| `F:\Temp\pe\winlock\builder\builder.exe` | `stub/winlock_builder.exe` | ~105 KB | WinLock 加壳器 |
| `F:\Temp\pe\winlock\stub\stub_x64.bin` | `stub/stub_x64.bin` | ~6.5 KB | WinLock x64 stub（raw .lock 节） |
| `F:\Temp\pe\winlock\stub\stub_x86.bin` | `stub/stub_x86.bin` | ~6.8 KB | WinLock x86 stub（raw .lock 节） |
| `F:\Temp\pe\winlock\stub\stub_x86.exe` | `stub/stub_x86.exe` | ~50 KB | x86 stub 完整 PE（builder 读 .reloc 用） |

builder 找 stub_x86.exe 的逻辑同样需要支持 `--stub-dir`，参考 stub.bin 的改动。

---

## 5. AppLocker (.NET) 侧集成步骤

### 5.1 项目结构改动

```
applocker/dotnet/
├── packer/
│   ├── StubLoader.cs              # 改造：从 stub/ 目录读，不再从 EmbeddedResource
│   ├── StubRegistry.cs            # 新增：stub 清单管理
│   ├── StubManifest.cs           # 新增：stub 元数据模型
│   ├── WinLockPacker.cs          # 新增：WinLock 加壳分支
│   ├── PackCore.cs               # 改造：加 WinLock 分支
│   ├── MainForm.cs               # 改造：UI 动态列 stub
│   └── WinAppLocker.Packer.csproj # 改造：去掉 CopyStubs Target 和 EmbeddedResource
├── shared/
│   └── (无改动)
├── stub/                          # 新增：所有 stub 文件
│   ├── stub_gui.exe               # 从原 Resources/ 移过来
│   ├── stub_gui.exe.meta.json
│   ├── stub_console.exe
│   ├── stub_console.exe.meta.json
│   ├── stub_test.exe
│   ├── stub_test.exe.meta.json
│   ├── winlock_builder.exe        # 从 winlock 复制
│   ├── winlock_builder.exe.meta.json
│   ├── stub_x64.bin               # 从 winlock 复制
│   ├── stub_x64.bin.meta.json
│   ├── stub_x86.bin               # 从 winlock 复制
│   ├── stub_x86.bin.meta.json
│   └── stub_x86.exe               # 从 winlock 复制
└── (stub/ stub.console/ stub.test/ 子项目位置不变，仍生成 stub_*.exe)
```

### 5.2 新增文件清单

#### StubManifest.cs
```csharp
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace WinAppLocker.Packer
{
    /// <summary>stub 加壳方案</summary>
    public enum StubKind
    {
        Tempfile,          // 临时文件模式（AppLocker 现方案）
        InplaceBuilder,    // in-place 加壳（WinLock）
    }

    /// <summary>stub 支持的子系统</summary>
    public enum StubSubsystem
    {
        Gui,
        Console,
        Test,
    }

    /// <summary>stub 元数据（从 .meta.json 反序列化）</summary>
    public class StubManifest
    {
        [JsonPropertyName("name")] public string Name { get; set; }
        [JsonPropertyName("kind")] public string KindStr { get; set; }
        [JsonPropertyName("subsystem")] public string SubsystemStr { get; set; }
        [JsonPropertyName("description")] public string Description { get; set; }
        [JsonPropertyName("version")] public string Version { get; set; }
        [JsonPropertyName("components")] public Dictionary<string, string> Components { get; set; }
        [JsonPropertyName("supported_machines")] public List<string> SupportedMachines { get; set; }

        [JsonIgnore] public string StubDir { get; set; }
        [JsonIgnore] public string MetaFilePath { get; set; }
        [JsonIgnore] public List<string> MissingComponents { get; set; } = new List<string>();

        [JsonIgnore]
        public StubKind Kind => KindStr == "inplace-builder" ? StubKind.InplaceBuilder : StubKind.Tempfile;

        [JsonIgnore]
        public StubSubsystem Subsystem => SubsystemStr switch
        {
            "console" => StubSubsystem.Console,
            "test" => StubSubsystem.Test,
            _ => StubSubsystem.Gui,
        };

        [JsonIgnore]
        public string MainFile => System.IO.Path.GetFileNameWithoutExtension(MetaFilePath).Replace(".meta", "");

        [JsonIgnore]
        public string MainFilePath => System.IO.Path.Combine(StubDir, MainFile);

        /// <summary>是否完整可用（主文件 + 所有 components 都存在）</summary>
        [JsonIgnore]
        public bool IsAvailable => System.IO.File.Exists(MainFilePath) && MissingComponents.Count == 0;
    }
}
```

#### StubRegistry.cs
```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace WinAppLocker.Packer
{
    /// <summary>stub 注册表：扫描 stub/ 目录，加载所有 .meta.json</summary>
    public static class StubRegistry
    {
        /// <summary>扫描 stubDir 下所有 *.meta.json</summary>
        public static List<StubManifest> LoadAll(string stubDir)
        {
            var result = new List<StubManifest>();
            if (!Directory.Exists(stubDir)) return result;

            foreach (var metaFile in Directory.EnumerateFiles(stubDir, "*.meta.json"))
            {
                try
                {
                    var json = File.ReadAllText(metaFile);
                    var manifest = JsonSerializer.Deserialize<StubManifest>(json);
                    manifest.MetaFilePath = metaFile;
                    manifest.StubDir = stubDir;

                    // 验证主文件存在
                    if (!File.Exists(manifest.MainFilePath))
                    {
                        manifest.MissingComponents.Add(manifest.MainFile);
                    }

                    // 验证 components 存在
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
                    /* 跳过损坏的 meta */
                }
            }
            return result;
        }

        /// <summary>根据偏好选 stub</summary>
        public static StubManifest Select(
            List<StubManifest> all,
            StubSubsystem originalSubsystem,
            string preferName = null)
        {
            // 1. 用户指定 name，直接用（如果可用）
            if (!string.IsNullOrEmpty(preferName))
            {
                var found = all.Find(m => m.Name == preferName && m.IsAvailable);
                if (found != null) return found;
            }

            // 2. 按子系统自动选（默认 tempfile 模式优先）
            var wantGui = originalSubsystem == StubSubsystem.Gui;
            var wantSubsystem = wantGui ? StubSubsystem.Gui : StubSubsystem.Console;

            // 先找 tempfile 模式（兼容性更好）
            var tempfile = all.Find(m =>
                m.IsAvailable &&
                m.Kind == StubKind.Tempfile &&
                m.Subsystem == wantSubsystem);
            if (tempfile != null) return tempfile;

            // 退而求其次，任意可用 stub
            return all.Find(m => m.IsAvailable);
        }
    }
}
```

#### WinLockPacker.cs
```csharp
using System;
using System.Diagnostics;
using System.IO;

namespace WinAppLocker.Packer
{
    /// <summary>
    /// WinLock 加壳分支：调用 winlock_builder.exe 对原 EXE 做 in-place 加壳。
    /// </summary>
    public static class WinLockPacker
    {
        public class WinLockResult
        {
            public bool Success;
            public string OutputPath;
            public string Stdout;
            public string Stderr;
            public int ExitCode;
        }

        /// <summary>
        /// 调用 winlock_builder.exe 加壳。
        /// </summary>
        /// <param name="builderExe">winlock_builder.exe 完整路径</param>
        /// <param name="stubDir">stub/ 目录路径（builder 找 stub_x64/x86.bin 用）</param>
        /// <param name="inputExe">原 EXE 路径</param>
        /// <param name="outputExe">输出 EXE 路径</param>
        /// <param name="password">密码</param>
        public static WinLockResult Pack(
            string builderExe,
            string stubDir,
            string inputExe,
            string outputExe,
            string password)
        {
            var result = new WinLockResult();
            var args = $"-i \"{inputExe}\" -o \"{outputExe}\" -p \"{password}\" --stub-dir \"{stubDir}\"";

            var psi = new ProcessStartInfo
            {
                FileName = builderExe,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(builderExe),
            };

            using (var proc = Process.Start(psi))
            {
                var stdout = proc.StandardOutput.ReadToEnd();
                var stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                result.ExitCode = proc.ExitCode;
                result.Stdout = stdout;
                result.Stderr = stderr;
                result.Success = proc.ExitCode == 0 && File.Exists(outputExe);
                result.OutputPath = result.Success ? outputExe : null;
            }
            return result;
        }
    }
}
```

### 5.3 改造现有文件

#### PackCore.cs（加 WinLock 分支）

```csharp
public sealed class PackOptions
{
    public string InputPath;
    public string OutputPath;
    public string Password;
    public StubKind StubPreference = StubKind.Auto;     // 旧字段，保留向后兼容
    public string PreferStubName = null;                // 新字段：指定 stub manifest name
    public int KdfIterations = PayloadFormat.DefaultKdfIterations;
}

internal static class PackCore
{
    public static PackReport Pack(PackOptions opts, IProgress<int> progress, Action<string> logger)
    {
        // 1. 读取原 EXE
        byte[] original = File.ReadAllBytes(opts.InputPath);
        progress?.Report(15);

        // 2. PE 解析
        var peInfo = PeReader.Parse(original);
        progress?.Report(25);

        // 3. 扫描 stub 目录，选 stub
        string stubDir = FindStubDir();  // applocker.exe 同目录的 stub/
        var allStubs = StubRegistry.LoadAll(stubDir);
        var originalSubsystem = MapSubsystem(peInfo.Subsystem);
        var selected = StubRegistry.Select(allStubs, originalSubsystem, opts.PreferStubName);
        if (selected == null || !selected.IsAvailable)
            throw new InvalidOperationException("没有可用的 stub");
        progress?.Report(30);

        // 4. 分支：按 stub kind 走不同路径
        PackReport report;
        if (selected.Kind == StubKind.InplaceBuilder)
        {
            report = PackWithWinLock(selected, opts, progress, logger);
        }
        else
        {
            report = PackWithTempfile(selected, original, peInfo, opts, progress, logger);
        }
        return report;
    }

    private static PackReport PackWithWinLock(
        StubManifest stub,
        PackOptions opts,
        IProgress<int> progress,
        Action<string> logger)
    {
        logger?.Invoke($"[WinLock] 使用 {stub.Name} 加壳...");

        // WinLock builder 不能原地覆盖输入文件，需要先复制到临时文件
        string tempInput = Path.Combine(Path.GetTempPath(),
            $"winlock_in_{Guid.NewGuid():N}.exe");
        string tempOutput = Path.Combine(Path.GetTempPath(),
            $"winlock_out_{Guid.NewGuid():N}.exe");
        try
        {
            File.Copy(opts.InputPath, tempInput, true);

            string builderExe = stub.MainFilePath;
            string stubDir = stub.StubDir;

            var result = WinLockPacker.Pack(
                builderExe, stubDir, tempInput, tempOutput, opts.Password);

            logger?.Invoke($"[WinLock] stdout: {result.Stdout}");
            if (!string.IsNullOrEmpty(result.Stderr))
                logger?.Invoke($"[WinLock] stderr: {result.Stderr}");

            if (!result.Success)
                throw new Exception($"WinLock builder 失败 (exit={result.ExitCode})");

            // 把输出复制到目标路径
            string outDir = Path.GetDirectoryName(Path.GetFullPath(opts.OutputPath));
            if (!Directory.Exists(outDir)) Directory.CreateDirectory(outDir);

            // WinLock 加壳后的 exe 必须在原目录运行，所以直接复制到目标路径
            File.Copy(tempOutput, opts.OutputPath, true);

            // 复制图标（可选，失败不影响主流程）
            try { IconCopier.CopyIconAndVersion(opts.InputPath, opts.OutputPath, logger); }
            catch { /* 图标缺失不影响 */ }

            progress?.Report(100);
            return new PackReport
            {
                InputSize = new FileInfo(opts.InputPath).Length,
                OutputSize = new FileInfo(opts.OutputPath).Length,
                OutputPath = opts.OutputPath,
            };
        }
        finally
        {
            try { File.Delete(tempInput); } catch { }
            try { File.Delete(tempOutput); } catch { }
        }
    }

    private static PackReport PackWithTempfile(
        StubManifest stub,
        byte[] original,
        PeInfo peInfo,
        PackOptions opts,
        IProgress<int> progress,
        Action<string> logger)
    {
        // 原来的 PackCore.Pack 逻辑，把 stub 字节从 stub.MainFilePath 读
        byte[] stubBytes = File.ReadAllBytes(stub.MainFilePath);
        progress?.Report(30);

        // ... 后续 payload 构建 + AES 加密 + 写入（原逻辑不变）...

        // 注意：原 csproj 的 CopyStubs Target 和 EmbeddedResource 要去掉
        // StubLoader.SelectStub 改为从 StubRegistry 取
    }

    private static string FindStubDir()
    {
        // applocker.exe 同目录的 stub/
        string exeDir = Path.GetDirectoryName(
            System.Reflection.Assembly.GetExecutingAssembly().Location);
        return Path.Combine(exeDir, "stub");
    }

    private static StubSubsystem MapSubsystem(ushort raw)
    {
        return raw == 2 /* WindowsGui */ ? StubSubsystem.Gui : StubSubsystem.Console;
    }
}
```

#### StubLoader.cs（改造为从 stub/ 读）

```csharp
internal static class StubLoader
{
    /// <summary>从 stub/ 目录读 stub 字节（不再从 EmbeddedResource）。</summary>
    public static byte[] LoadStubBytes(string stubDir, string stubFileName)
    {
        string path = Path.Combine(stubDir, stubFileName);
        if (!File.Exists(path))
            throw new FileNotFoundException($"stub 文件不存在: {path}");
        return File.ReadAllBytes(path);
    }

    /// <summary>在 stub 字节中搜索 WAL_VER|...|WAL_END 标记（保留原逻辑）。</summary>
    public static string ReadStubVersion(byte[] stubBytes)
    {
        // ... 原逻辑不变 ...
    }
}
```

#### WinAppLocker.Packer.csproj（去掉 EmbeddedResource）

```xml
<!-- 去掉原来的 CopyStubs Target 和 EmbeddedResource Include="Resources\stub_*.exe" -->
<!-- 原来的：
<Target Name="CopyStubs" BeforeTargets="BeforeBuild">
  <Copy SourceFiles="..." DestinationFolder="..." />
  <ItemGroup>
    <EmbeddedResource Include="Resources\stub_gui.exe" ... />
    ...
  </ItemGroup>
</Target>
-->

<!-- 改为：把 stub/ 目录作为发布时拷贝内容 -->
<ItemGroup>
  <None Include="..\stub\bin\$(Configuration)\stub_gui.exe" CopyToOutputDirectory="PreserveNewest" />
  <None Include="..\stub\bin\$(Configuration)\stub_gui.exe.meta.json" CopyToOutputDirectory="PreserveNewest" />
  <None Include="..\stub.console\bin\$(Configuration)\stub_console.exe" CopyToOutputDirectory="PreserveNewest" />
  <None Include="..\stub.console\bin\$(Configuration)\stub_console.exe.meta.json" CopyToOutputDirectory="PreserveNewest" />
  <None Include="..\stub.test\bin\$(Configuration)\stub_test.exe" CopyToOutputDirectory="PreserveNewest" />
  <None Include="..\stub.test\bin\$(Configuration)\stub_test.exe.meta.json" CopyToOutputDirectory="PreserveNewest" />
</ItemGroup>
```

**注意**：WinLock 的 `winlock_builder.exe` / `stub_x64.bin` / `stub_x86.bin` / `stub_x86.exe`
不由 packer 的 csproj 管理，它们是 WinLock 项目的产物，需要**手动复制**或写个
`build.ps1` 步骤从 winlock 项目拷过来。详见 §6。

#### MainForm.cs（UI 动态列 stub）

UI 的 stub 选择下拉框从硬编码 3 选项改为动态：

```csharp
private List<StubManifest> _availableStubs;

private void LoadStubList()
{
    string stubDir = Path.Combine(
        Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
        "stub");
    _availableStubs = StubRegistry.LoadAll(stubDir);

    stubComboBox.Items.Clear();
    stubComboBox.Items.Add(new StubListItem(null, "自动（按原 EXE 子系统选）"));
    foreach (var s in _availableStubs.Where(s => s.IsAvailable))
    {
        string label = $"{s.Name} - {s.Description}";
        if (s.Kind == StubKind.InplaceBuilder)
            label += " (兼容性较低)";
        stubComboBox.Items.Add(new StubListItem(s, label));
    }
    stubComboBox.SelectedIndex = 0;
}

private void OnInputExeChanged(string exePath)
{
    // 当用户选了原 EXE 后，检查是否是 Console 子系统 + 用户选了 WinLock
    // 是的话弹警告：WinLock 仅支持 GUI，建议用 AppLocker Console 模式
    var peInfo = PeReader.Parse(File.ReadAllBytes(exePath));
    if (peInfo.Subsystem != 2 /* WindowsGui */)
    {
        var selected = (StubListItem)stubComboBox.SelectedItem;
        if (selected.Manifest?.Kind == StubKind.InplaceBuilder)
        {
            MessageBox.Show(
                "WinLock 模式仅支持 GUI 程序。\n建议改用 AppLocker Console 模式。",
                "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
```

### 5.4 测试相关

#### 测试用 stub（stub_test.exe.meta.json）

测试用的 `stub_test.exe`（硬编码密码 test1234）保持 tempfile 模式：

```json
{
  "name": "applocker-test",
  "kind": "tempfile",
  "subsystem": "test",
  "description": "AppLocker Test stub (hardcoded password test1234)",
  "version": "1.0.0"
}
```

CI 测试时仍选这个 stub，走 tempfile 路径，不受 WinLock 影响。

如果要做 WinLock 的端到端测试，可以加一个 `winlock_builder_test.exe`（builder 带 `-t` 参数，
stub 用 `STUB_FLAG_TEST_MODE` 跳过弹框），但这需要 WinLock 侧支持（见 §4.2）。
**初始集成不做这个**，先手动测试 WinLock 模式即可。

---

## 6. 构建流程

### 6.1 WinLock 侧构建

WinLock 仍然独立构建（用 w64devkit GCC + msys2 mingw32）：

```powershell
# 在 winlock 目录
make all all-x86
```

产出：
- `builder/builder.exe`
- `stub/stub_x64.bin`
- `stub/stub_x64.exe`（不用）
- `stub/stub_x86.bin`
- `stub/stub_x86.exe`（builder 读取 .reloc 用）

### 6.2 AppLocker 侧构建

AppLocker 的 `build.ps1` 增加一步：调用 WinLock 构建，拷贝产物到 `stub/`。

```powershell
# build.ps1 增加（在编译 packer 之前）

# 1. 构建 WinLock
$winlockDir = "C:\Home\Projects\applocker\winlock"  # WinLock 代码所在
Push-Location $winlockDir
make all all-x86
Pop-Location

# 2. 拷贝 WinLock 产物到 packer/stub/
$stubDir = "$PSScriptRoot\dotnet\stub"
Copy-Item "$winlockDir\builder\builder.exe" "$stubDir\winlock_builder.exe" -Force
Copy-Item "$winlockDir\stub\stub_x64.bin" "$stubDir\" -Force
Copy-Item "$winlockDir\stub\stub_x86.bin" "$stubDir\" -Force
Copy-Item "$winlockDir\stub\stub_x86.exe" "$stubDir\" -Force

# 3. 生成 WinLock 的 meta.json（如果不存在）
$winlockMeta = "$stubDir\winlock_builder.exe.meta.json"
if (-not (Test-Path $winlockMeta)) {
    $meta = @{
        name = "winlock"
        kind = "inplace-builder"
        subsystem = "gui"
        description = "WinLock in-place packer (GUI dialog, no plaintext tempfile)"
        version = "2.0.0"
        components = @{
            stub_x64 = "stub_x64.bin"
            stub_x86 = "stub_x86.bin"
            stub_x86_exe = "stub_x86.exe"
        }
        supported_machines = @("amd64", "i386")
    }
    $meta | ConvertTo-Json -Depth 5 | Out-File -FilePath $winlockMeta -Encoding UTF8
}

# 4. 构建 AppLocker stub（GUI/Console/Test）
# dotnet build stub/ stub.console/ stub.test/

# 5. 生成 AppLocker stub 的 meta.json
# (同上，每个 stub 一个 meta.json)

# 6. 构建 packer
# dotnet build packer/

# 7. 发布：把 stub/ 目录连同所有文件一起打包
# dist/
# ├── WinAppLocker.exe
# └── stub/
#     ├── stub_gui.exe + .meta.json
#     ├── stub_console.exe + .meta.json
#     ├── stub_test.exe + .meta.json
#     ├── winlock_builder.exe + .meta.json
#     ├── stub_x64.bin + .meta.json
#     ├── stub_x86.bin + .meta.json
#     └── stub_x86.exe
```

### 6.3 发布产物

发布时需要分发**两个东西**：
1. `WinAppLocker.exe`（packer 本体）
2. `stub/` 目录（所有 stub + meta.json）

用户拿到后必须把 `stub/` 放在 `WinAppLocker.exe` 同目录。

**注意**：这跟原来嵌资源单文件发布不同，需要在 README 里说明。

---

## 7. 集成测试清单

### 7.1 基本功能测试

| # | 测试项 | 验证 |
|---|--------|------|
| 1 | AppLocker 现方案 GUI stub 仍工作 | 跑 `test.ps1` 通过 |
| 2 | AppLocker 现方案 Console stub 仍工作 | 用 console 样本测试 |
| 3 | AppLocker 测试 stub 仍工作 | 跑 `test.ps1` |
| 4 | WinLock 模式 GUI 程序 | 用 hellogui 测试，弹密码框 → 输密码 → 程序运行 |
| 5 | WinLock 模式 x86 程序 | 用 helloguix86 测试 |
| 6 | WinLock 模式 TLS_PROXY | 用 hellomingw 测试 |
| 7 | WinLock 模式 Chrome 失败并提示 | 选 WinLock 加 Chrome，应失败 |
| 8 | WinLock 模式 Console 程序警告 | 选 Console EXE + WinLock，应弹警告 |
| 9 | stub 目录缺失某文件 | UI 应禁用对应选项 |

### 7.2 兼容性测试矩阵

| 程序 | AppLocker tempfile | WinLock | 说明 |
|------|-------------------|---------|------|
| hellogui | ✅ | ✅ | 基本验证 |
| helloguix86 | ✅ | ✅ | x86 验证 |
| Notepad4 | ✅ | ✅ | 第三方 GUI |
| DontSleep | ✅ | ✅ | 带签名 |
| Bandizip | ✅ | ✅ | ASLR + CFG |
| Chrome | ✅ | ❌（已知，UIA hook） | WinLock 应在加壳时报错或运行时报错 |
| QQ | ✅ | ❌（已知，WinVerifyTrust） | 同上 |
| .NET EXE | ✅ | ❌（WinLock 不支持） | WinLock 应在加壳时拒绝 |

### 7.3 错误处理测试

| 场景 | 期望行为 |
|------|---------|
| stub 目录不存在 | UI 显示"无可用 stub"，禁用加密按钮 |
| winlock_builder.exe 缺失 | WinLock 选项灰显 + tooltip 提示 |
| stub_x64.bin 缺失但 stub_x86.bin 在 | WinLock 仅支持 x86，加 x64 程序时报错 |
| builder 退出码非 0 | packer 显示 builder 的 stdout/stderr |
| 原目录无写权限 | WinLock 模式正常（builder 在临时目录工作），tempfile 模式失败 |

---

## 8. 安全性考量

### 8.1 WinLock 模式的安全优势

- **无明文临时文件**：原 EXE 字节从不落盘，仅在内存中解密 `.text` 节
- **无临时文件残留风险**：异常退出不会留下明文 PE
- **.text 节加密**：反汇编者拿到加壳 exe 只能看到密文 .text

### 8.2 WinLock 模式的安全劣势

- **加密算法弱**：XTEA（128-bit，32 轮）vs AppLocker 的 AES-256-CBC + HMAC-SHA256
- **KDF 简单**：SHA-256(password + salt)，无 PBKDF2 迭代，易暴力破解
- **密码 hash 可 dump**：stub_data 结构在 PE 里可被搜索（虽然有 STUB_DATA_MAGIC 但可定位）
- **.rdata/.data/.rsrc 不加密**：只有 .text 加密，资源/字符串仍可读

### 8.3 改进方向（未来工作）

如果 WinLock 模式需要更高安全级别：
1. **升级加密**：把 XTEA 换成 AES-256-GCM（需要重写 stub.c 的加密函数，但 stub.bin 会变大）
2. **升级 KDF**：密码用 PBKDF2/Argon2 派生密钥，不用 SHA-256(password+salt)
3. **加密更多节**：`.rdata` / `.data` 也加密（但要处理 IAT 引用，复杂度高）
4. **反调试**：加 `IsDebuggerPresent` 检测、PEB BeingDebugged 检测

**初始集成不做这些**，先让 WinLock 作为"快速、轻量、低兼容性"的选项存在。

---

## 9. 工作量估算

### 9.1 WinLock 侧改动

| 任务 | 难度 | 工作量 |
|------|------|--------|
| builder.c 加 `--stub-dir` 参数 | 低 | 0.5h |
| builder.c 加 `--json` 输出选项（可选） | 低 | 0.5h |
| builder 同时支持找 stub_x86.exe 的 `--stub-dir` | 低 | 0.3h |
| 测试 builder 的 `--stub-dir` 参数 | 低 | 0.5h |
| **小计** | — | **1.8h** |

### 9.2 AppLocker 侧改动

| 任务 | 难度 | 工作量 |
|------|------|--------|
| 新增 StubManifest.cs | 低 | 1h |
| 新增 StubRegistry.cs | 中 | 2h |
| 新增 WinLockPacker.cs | 低 | 1h |
| 改造 StubLoader.cs（从 stub/ 读） | 低 | 1h |
| 改造 PackCore.cs（加分支） | 中 | 2h |
| 改造 MainForm.cs（动态 stub 列表） | 中 | 2h |
| 改造 csproj（去 EmbeddedResource） | 低 | 1h |
| 写 meta.json 文件（6 个） | 低 | 0.5h |
| 改 build.ps1（加 WinLock 构建步骤） | 低 | 1h |
| 更新 dotnet/README.md | 低 | 1h |
| **小计** | — | **12.5h** |

### 9.3 测试

| 任务 | 难度 | 工作量 |
|------|------|--------|
| 基本功能回归测试 | 中 | 2h |
| WinLock 模式端到端测试 | 中 | 2h |
| 兼容性测试矩阵 | 中 | 2h |
| 错误处理测试 | 低 | 1h |
| **小计** | — | **7h** |

### 9.4 总计

**总工作量**：约 21.3h（含测试）

**关键路径**：WinLock 侧改动（1.8h）→ AppLocker 侧改动（12.5h）→ 测试（7h）

---

## 10. 实施步骤建议

### 阶段 1：WinLock 侧改造（独立完成，不影响 AppLocker）

1. 改 `builder.c` 加 `--stub-dir` 参数
2. 编译验证 `make all all-x86`
3. 手动测试：`builder.exe -i test.exe -o out.exe --stub-dir /path/to/stub`
4. （可选）加 `--json` 输出

### 阶段 2：AppLocker 侧改造（可独立开发，不动现有 stub）

1. 新增 `StubManifest.cs`、`StubRegistry.cs`、`WinLockPacker.cs`
2. 改造 `StubLoader.cs`（保留旧接口做 fallback）
3. 改造 `PackCore.cs` 加 WinLock 分支
4. 改造 csproj：去掉 CopyStubs Target 和 EmbeddedResource
5. 改造 `MainForm.cs`：动态 stub 列表
6. 写 6 个 `.meta.json` 文件
7. 改 `build.ps1` 加 WinLock 构建步骤

### 阶段 3：集成测试

1. 跑现有 `test.ps1` 确认 AppLocker 现方案不退化
2. 手动测 WinLock 模式：hellogui / helloguix86 / Notepad4 / DontSleep
3. 测兼容性矩阵：Chrome 应失败、QQ 应失败
4. 测错误处理：stub 缺文件、目录无权限
5. 更新文档

### 阶段 4：发布

1. Release 构建：`build.ps1 -Release`
2. 验证 `dist/` 包含 `WinAppLocker.exe` + `stub/` 完整目录
3. 在干净机器测试（无开发环境）
4. 更新用户文档

---

## 11. 风险与未决问题

### 11.1 已知风险

| 风险 | 影响 | 缓解 |
|------|------|------|
| 发布产物从单文件变 exe+目录 | 用户分发流程改变 | 文档明确说明，或后续考虑用 NSIS/InnoSetup 打包 |
| stub 目录被用户误删 | WinLock 模式不可用 | packer 启动时检查，缺文件时 UI 禁用对应选项 |
| WinLock builder 是 C 程序，与 .NET 项目混用 | 构建流程复杂 | build.ps1 自动化，用户不直接接触 GCC |
| builder 进程调用失败（路径含空格、权限等） | WinLock 加壳失败 | 错误处理完善，stdout/stderr 全部捕获并显示 |
| 反病毒误报 WinLock 加壳后的 exe | 用户被 AV 拦截 | UI 警告 + 文档说明，无法技术解决 |

### 11.2 未决问题

1. **WinLock 是否需要支持 Console 程序？**
   - 当前方案：不支持，UI 警告用户改用 AppLocker Console 模式
   - 如果要支持：stub.c 需要加 `ReadConsoleW` 密码输入路径，约 200 行 C 代码
   - **建议：先不支持**，看用户反馈再决定

2. **WinLock 加壳后的 exe 是否要保留图标？**
   - 当前 builder 不处理图标，加壳后 exe 用默认图标
   - AppLocker 现方案用 `IconCopier` 复制图标
   - **建议**：packer 调 builder 后，再用 `IconCopier` 复制图标（已在 §5.3 的 `PackWithWinLock` 里做了）

3. **WinLock 的密码强度策略与 AppLocker 是否统一？**
   - AppLocker 现方案：最少 4 字符，PBKDF2 200K 迭代
   - WinLock：无长度限制，SHA-256(password+salt) 无迭代
   - **建议**：packer 在调 builder 前统一做密码长度检查（≥4），但 WinLock 的 KDF 弱点是固有的，UI 应警告

4. **是否要在 WinLock 加壳时记录元数据到 payload？**
   - AppLocker 现方案把原文件名、打包时间、CRC 等记到 payload Extension TLV
   - WinLock 没有这个机制，加壳后的 exe 看不到原信息
   - **建议**：不做，WinLock 模式的元数据由 builder 自己的 stub_data 结构管理

---

## 12. 文件清单汇总

### 12.1 WinLock 侧产出（复制到 applocker/dotnet/stub/）

| 文件 | 来源 | 说明 |
|------|------|------|
| `winlock_builder.exe` | `F:\Temp\pe\winlock\builder\builder.exe` | 加壳器 |
| `stub_x64.bin` | `F:\Temp\pe\winlock\stub\stub_x64.bin` | x64 stub |
| `stub_x86.bin` | `F:\Temp\pe\winlock\stub\stub_x86.bin` | x86 stub |
| `stub_x86.exe` | `F:\Temp\pe\winlock\stub\stub_x86.exe` | x86 stub 完整 PE（builder 读 .reloc） |

### 12.2 AppLocker 侧新增文件

| 文件 | 路径 |
|------|------|
| `StubManifest.cs` | `dotnet/packer/StubManifest.cs` |
| `StubRegistry.cs` | `dotnet/packer/StubRegistry.cs` |
| `WinLockPacker.cs` | `dotnet/packer/WinLockPacker.cs` |

### 12.3 AppLocker 侧改造文件

| 文件 | 改动 |
|------|------|
| `StubLoader.cs` | 从 EmbeddedResource 改为从 stub/ 目录读 |
| `PackCore.cs` | 加 WinLock 分支 |
| `MainForm.cs` | stub 列表动态化 |
| `WinAppLocker.Packer.csproj` | 去 CopyStubs Target，加 None CopyToOutput |
| `build.ps1` | 加 WinLock 构建步骤 |
| `dotnet/README.md` | 更新使用说明 |

### 12.4 meta.json 文件清单

| 文件 | 内容 |
|------|------|
| `stub/stub_gui.exe.meta.json` | AppLocker GUI stub 元数据 |
| `stub/stub_console.exe.meta.json` | AppLocker Console stub 元数据 |
| `stub/stub_test.exe.meta.json` | AppLocker Test stub 元数据 |
| `stub/winlock_builder.exe.meta.json` | WinLock builder 元数据（含 components 引用） |
| `stub/stub_x64.bin.meta.json` | 可选，被 builder meta 引用 |
| `stub/stub_x86.bin.meta.json` | 可选，被 builder meta 引用 |
| `stub/stub_x86.exe.meta.json` | 可选，被 builder meta 引用 |

---

## 13. 附录

### 13.1 WinLock builder 命令行接口

```
WinLock v2 - PE Password Gate Packer

Usage:
  winlock_builder.exe -i <input.exe> [-o <output.exe>] [-p <password>] [-t] [--stub-dir <path>]

Options:
  -i, --input <file>     Input PE EXE (x86 or x64)
  -o, --output <file>    Output path (default: <input_dir>/<base>_locked.exe)
  -p, --password <pwd>   Password (default: hello123)
  -t, --test             Test mode (hardcoded password test123, no dialog)
  --stub-dir <path>      Stub.bin search directory (default: ./stub/)
  -h, --help             Show help
```

退出码：
- 0：成功
- 1：参数错误 / 文件读取失败 / 加壳失败

输出（stdout）：
- `[+] Run        : <output_path>` 成功时输出最终路径
- `[-] <error>` 失败时输出错误

### 13.2 WinLock stub_data 结构（v3）

builder 在 stub.bin 中搜索 `STUB_DATA_MAGIC`（`"WINLOCK!"` = `0x214B434F4C4E4957`）
定位 stub_data 结构并填充字段。详细结构见 `F:\Temp\pe\winlock\config.h`。

关键字段：
- `magic`（8B）：`0x214B434F4C4E4957`
- `version`（2B）：3
- `flags`（2B）：bit0=hash / bit1=test / bit2=tls_proxy / bit3=aslr
- `oep_rva`（8B）：原 AddressOfEntryPoint
- `text_rva` / `text_size`：加密节信息
- `xtea_key`（16B）：XTEA 密钥
- `salt`（16B）：SHA-256 salt
- `pwd_hash`（32B）：SHA-256(utf8(pwd) + salt)

### 13.3 WinLock 当前已验证样本

| 程序 | 架构 | 特性 | 结果 |
|------|------|------|------|
| hellocli | x64 | CLI | ✅ test mode |
| hellogui | x64 | GUI | ✅ 正/错密码 |
| DontSleep | x64 | 带签名 | ✅ |
| Notepad4 | x64 | ASLR | ✅ |
| Bandizip | x64 | ASLR + CFG | ✅（CFG 禁用后） |
| hellomingw | x64 | TLS callbacks | ✅（TLS_PROXY） |
| helloguix86 | x86 | x86 GUI | ✅ |
| hellox86 | x86 | x86 + TLS | ✅ |
| Chrome | x64 | UIA hook | ❌ loader lock 死锁 |
| QQ | x86 | WinVerifyTrust | ❌ 签名验证失败 |

### 13.4 参考资料

- WinLock README：`F:\Temp\pe\winlock\README.md`
- WinLock DEVENV：`F:\Temp\pe\winlock\DEVENV.md`
- WinLock PLAN：`F:\Temp\pe\winlock\PLAN.md`
- AppLocker .NET README：`C:\Home\Projects\applocker\dotnet\README.md`
- AppLocker .NET 设计文档：`C:\Home\Projects\applocker\docs\WinAppLocker-DotNet-Design.md`

---

**文档版本**：1.0
**最后更新**：2026-07-18
