# WinAppLocker 设计文档（.NET 全新实现）

本文档描述 WinAppLocker 的 **完全 .NET 重新实现方案**，**不考虑与现有 Rust 实现的兼容性**。stub 和 packer 都用 C# + .NET Framework 4.7.2（Win10/11 自带，用户无需装运行时）。

---

## 目录

- [1. 总览](#1-总览)
- [2. stub 章节](#2-stub-章节)
  - [2.1 职责](#21-职责)
  - [2.2 项目结构](#22-项目结构)
  - [2.3 运行时流程](#23-运行时流程)
  - [2.4 密码 UI](#24-密码-ui)
  - [2.5 加密与密钥派生](#25-加密与密钥派生)
  - [2.6 临时文件与子进程](#26-临时文件与子进程)
  - [2.7 版本信息](#27-版本信息)
  - [2.8 错误处理](#28-错误处理)
- [3. packer 章节](#3-packer-章节)
  - [3.1 职责](#31-职责)
  - [3.2 项目结构](#32-项目结构)
  - [3.3 打包流程](#33-打包流程)
  - [3.4 PE 解析与图标复制](#34-pe-解析与图标复制)
  - [3.5 stub 嵌入](#35-stub-嵌入)
  - [3.6 GUI 界面](#36-gui-界面)
  - [3.7 版本信息](#37-版本信息)
- [4. Payload 二进制格式](#4-payload-二进制格式)
- [5. 构建与发布](#5-构建与发布)
- [6. 技术选型](#6-技术选型)
- [7. 安全说明](#7-安全说明)

---

## 1. 总览

WinAppLocker 由两个独立的 .NET 程序组成：

| 组件 | 语言/框架 | 子系统 | 用途 |
|---|---|---|---|
| **stub** | C# + .NET Framework 4.7.2 + WinForms | GUI 或 Console | 加密后 EXE 的引导程序，弹出密码框、解密原 EXE、释放临时文件并启动子进程 |
| **packer** | C# + .NET Framework 4.7.2 + WinForms | GUI | 打包工具，把原 EXE 加密后追加到 stub 末尾，生成加密 EXE |

两者通过 **二进制 payload 格式**（追加在 stub exe 末尾）解耦，不共享代码也不互相调用。packer 在编译时把 stub 字节嵌入自己的 exe，发布产物是单一 `WinAppLocker.exe`。

### 关键设计原则

1. **stub 和 packer 完全独立**：分两个 C# 项目，互不引用，仅通过 payload 字节格式约定
2. **零运行时依赖**：.NET Framework 4.7.2 是 Win10/11 自带组件，用户机器无需安装任何东西
3. **单一发布文件**：packer 通过 `EmbeddedResource` 把两个 stub（GUI / Console）字节嵌入，发布只需一个 exe
4. **不追求内存级安全**：临时文件方案本身就是"掩耳盗铃"，加密算法选型以 .NET Framework 4.7.2 原生支持为准，不引入额外 NuGet 包

---

## 2. stub 章节

### 2.1 职责

stub 是加密后 EXE 的**前置引导程序**。运行加密后的 EXE 时，实际执行的是 stub，stub 负责：

1. 读取自身 EXE 字节
2. 从 EXE 末尾解析 payload（含加密的原 EXE 数据）
3. 弹出密码输入框（GUI 模式）或控制台输入（Console 模式）
4. 用密码 + salt + KDF 派生密钥
5. AEAD 解密得到原 EXE 明文
6. 校验明文长度与 CRC32
7. 在**原 EXE 所在目录**创建隐藏临时文件，写入明文 PE
8. `CreateProcessW` 启动临时文件作为子进程，工作目录 = 原目录
9. 等待子进程退出
10. 删除临时文件，退出

### 2.2 项目结构

```
stub/
├── WinAppLocker.Stub.sln
├── WinAppLocker.Stub.csproj          # 主项目（生成 stub.exe）
├── packages.config                   # NuGet 包配置
├── Properties/
│   ├── AssemblyInfo.cs
│   └── Resources.resx                # 图标、字符串等资源
├── Program.cs                        # 入口，分发 GUI / Console 模式
├── StubEntry.cs                     # stub 主流程（读 payload / 解密 / 启动子进程）
├── PayloadReader.cs                 # 从 EXE 末尾解析 payload
├── CryptoUtil.cs                    # KDF + AEAD 解密
├── PasswordForm.cs                  # GUI 密码对话框（WinForms）
├── PasswordForm.Designer.cs         # VS 自动生成的界面布局
├── ProcessLauncher.cs               # 创建隐藏临时文件 + CreateProcessW
└── VersionInfo.cs                   # 版本标记（构建时注入）
```

**项目文件关键配置**：

```xml
<!-- WinAppLocker.Stub.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net472</TargetFramework>
    <OutputType>WinExe</OutputType>      <!-- GUI stub：无控制台窗口 -->
    <UseWindowsForms>true</UseWindowsForms>
    <ApplicationIcon>app.ico</ApplicationIcon>
    <Version>0.1.0</Version>
    <AssemblyName>stub_gui</AssemblyName> <!-- 生成 stub_gui.exe -->
  </PropertyGroup>
</Project>
```

Console stub 复用同一份源码，通过条件编译切换：

```xml
<!-- 定义两个 build 配置：GUI 和 Console -->
<PropertyGroup Condition="'$(StubMode)' == 'Console'">
  <OutputType>Exe</OutputType>           <!-- Console stub：保留控制台 -->
  <AssemblyName>stub_console</AssemblyName>
  <DefineConstants>$(DefineConstants);STUB_CONSOLE</DefineConstants>
</PropertyGroup>
```

构建命令：

```powershell
# GUI stub
dotnet build -c Release -p:StubMode=Gui

# Console stub
dotnet build -c Release -p:StubMode=Console
```

### 2.3 运行时流程

```
[stub.exe 启动]
       │
       ▼
[读自身 exe 字节]
       │
       ▼
[从末尾解析 payload] ──失败──> [弹错误框 / 退出码 1]
       │
       ▼
[弹密码框 / 控制台输入] ──取消──> [退出码 2]
       │
       ▼
[密码 + salt + KDF 派生密钥]
       │
       ▼
[AEAD 解密] ──失败──> [密码错误，直接退出] (不重试)
       │
       ▼
[校验明文长度 + CRC32]
       │
       ▼
[在原目录创建隐藏临时文件 el_{pid}.exe]
       │
       ▼
[写入明文 PE 字节]
       │
       ▼
[CreateProcessW 启动临时文件，工作目录=原目录]
       │
       ▼
[WaitForSingleObject 等待子进程退出]
       │
       ▼
[删除临时文件（带重试）]
       │
       ▼
[退出，返回子进程退出码]
```

### 2.4 密码 UI

**GUI 模式**：WinForms `Form`，VS 拖控件即可。

```csharp
// PasswordForm.cs
public partial class PasswordForm : Form
{
    public string Password { get; private set; } = "";

    public PasswordForm(string? errorMessage = null)
    {
        InitializeComponent();
        if (errorMessage != null)
        {
            lblError.Text = errorMessage;
            lblError.Visible = true;
        }
    }

    private void btnOk_Click(object sender, EventArgs e)
    {
        if (string.IsNullOrEmpty(txtPassword.Text))
        {
            MessageBox.Show("密码不能为空", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        Password = txtPassword.Text;
        DialogResult = DialogResult.OK;
        Close();
    }

    private void btnCancel_Click(object sender, EventArgs e)
    {
        DialogResult = DialogResult.Cancel;
        Close();
    }
}
```

`PasswordForm.Designer.cs`（VS 自动生成）：
- `txtPassword`：`TextBox`，`PasswordChar = '*'`，`MaxLength = 256`
- `btnOk`：`Button`，`Text = "确定"`，`DialogResult = OK`
- `btnCancel`：`Button`，`Text = "取消"`，`DialogResult = Cancel`
- `lblError`：`Label`，默认隐藏
- 窗口：`FormBorderStyle = FixedDialog`，`StartPosition = CenterScreen`，`MaximizeBox = false`，`MinimizeBox = false`

**Console 模式**：用 `Console.ReadKey(true)` 逐字符读取，不回显。

```csharp
public static string ReadPasswordConsole()
{
    Console.Write("请输入密码: ");
    var sb = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
        {
            sb.Remove(sb.Length - 1, 1);
            Console.Write("\b \b");
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
```

### 2.5 加密与密钥派生

**算法选型**（基于 .NET Framework 4.7.2 原生支持）：

| 用途 | 算法 | .NET 类 | 理由 |
|---|---|---|---|
| AEAD | **AES-256-GCM** | `System.Security.Cryptography.AesGcm`（via `Microsoft.Bcl.Cryptography` NuGet）| GCM 是 AEAD，提供机密性 + 完整性 |
| 备选 AEAD | **AES-256-CBC + HMAC-SHA256** | `AesCng` + `HMACSHA256`（.NET 4.7.2 原生）| 若不想引 NuGet，可用 Encrypt-then-MAC 手动实现 |
| KDF | **PBKDF2-SHA256** | `Rfc2898DeriveBytes(..., HashAlgorithmName.SHA256)`（原生）| 抗暴力破解，工业标准 |

**推荐方案**：用 `Microsoft.Bcl.Cryptography` NuGet 包的 `AesGcm`，API 和 .NET 5+ 完全一致，密文与标准 AES-GCM 字节级兼容。

```csharp
// CryptoUtil.cs
public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] nonce, byte[]? aad)
{
    using var aes = new AesGcm(key, 16);  // 16 字节 tag
    var tag = ciphertext[^16..];
    var actualCiphertext = ciphertext[..^16];
    var plaintext = new byte[actualCiphertext.Length];
    aes.Decrypt(nonce, actualCiphertext, tag, plaintext, aad);
    return plaintext;
}

public static byte[] DeriveKey(string password, byte[] salt, int iterations)
{
    using var kdf = new Rfc2898DeriveBytes(
        password, salt, iterations, HashAlgorithmName.SHA256);
    return kdf.GetBytes(32);  // AES-256 = 32 字节密钥
}
```

**默认参数**：
- KDF 迭代次数：600,000（抗 GPU 暴力破解）
- salt 长度：16 字节
- nonce 长度：12 字节（GCM 标准）
- tag 长度：16 字节（GCM 推荐）
- 密钥长度：32 字节（AES-256）

### 2.6 临时文件与子进程

**文件名规则**：`el_{stub_pid}.exe`（确定性，便于残留排查；多实例通过 PID 区分天然不冲突）。

**关键点**：
- 临时文件必须在**原 EXE 所在目录**（保证 SxS manifest 探测、DLL 搜索路径、`GetModuleFileNameW` 返回正确路径）
- 创建时即设置 `FILE_ATTRIBUTE_HIDDEN`（用 `CreateFileW` 直接带，避免 `File.Create` 与 `SetFileAttributes` 之间的可见窗口）
- 子进程退出**之后**才删除临时文件（运行期间 PE loader 持有镜像，`DeleteFile` 会 sharing violation 失败）
- 删除带重试（5 次 × 50ms），应对 OS 异步释放 / 杀软扫描占用

```csharp
// ProcessLauncher.cs
public static int LaunchAndWait(byte[] peBytes, string originalDir)
{
    int pid = Process.GetCurrentProcess().Id;
    string tempPath = Path.Combine(originalDir, $"el_{pid}.exe");

    // 创建隐藏文件并写入 PE 字节
    WriteHiddenFile(tempPath, peBytes);

    // 启动子进程
    var si = new STARTUPINFO();
    si.cb = Marshal.SizeOf<STARTUPINFO>();
    var pi = new PROCESS_INFORMATION();

    bool ok = CreateProcessW(
        tempPath,
        null, null, null, false,
        CREATE_UNICODE_ENVIRONMENT,
        IntPtr.Zero, originalDir, ref si, out pi);

    if (!ok) throw new Win32Exception(Marshal.GetLastWinError());

    CloseHandle(pi.hThread);

    // 等待子进程退出
    WaitForSingleObject(pi.hProcess, INFINITE);

    GetExitCodeProcess(pi.hProcess, out uint exitCode);
    CloseHandle(pi.hProcess);

    // 删除临时文件（带重试）
    TryDeleteWithRetry(tempPath);

    return (int)exitCode;
}

private static void WriteHiddenFile(string path, byte[] data)
{
    // CreateFileW + FILE_ATTRIBUTE_HIDDEN，文件从创建起就隐藏
    var handle = CreateFileW(
        path,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        IntPtr.Zero,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN,
        IntPtr.Zero);

    if (handle == INVALID_HANDLE_VALUE)
        throw new Win32Exception(Marshal.GetLastWinError());

    using (var fs = new FileStream(handle, FileAccess.Write))
    {
        fs.Write(data, 0, data.Length);
        fs.Flush();
    }  // 关闭句柄，让子进程能独占打开
}

private static void TryDeleteWithRetry(string path)
{
    for (int i = 0; i < 5; i++)
    {
        try { File.Delete(path); return; }
        catch (IOException) { Thread.Sleep(50); }
    }
    // 删除失败只记日志，不抛异常（残留可手动清理）
}
```

P/Invoke 声明：

```csharp
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess,
    uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile);

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine,
    IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
    uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
    ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

[DllImport("kernel32.dll", SetLastError = true)]
static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool CloseHandle(IntPtr hObject);
```

### 2.7 版本信息

stub 通过 `AssemblyInfo` + 编译时常量携带版本信息：

- **版本号**：`AssemblyVersion`（来自 csproj 的 `<Version>`）
- **Git hash**：MSBuild Target 在编译前执行 `git rev-parse --short HEAD` 写入 `VersionInfo.cs`
- **构建时间**：MSBuild Target 在编译前写入 UTC 时间

```csharp
// VersionInfo.cs（由 build target 自动生成，不要手动编辑）
namespace WinAppLocker.Stub
{
    public static class VersionInfo
    {
        public const string Version = "0.1.0";
        public const string GitHash = "a1b2c3d";
        public const string BuildTime = "2026-07-17 12:00:00 UTC";
    }
}
```

**packer 读取 stub 版本**：packer 在嵌入 stub 时通过搜索字节标记读取版本（不依赖 .NET 反射，因为是裸字节）：

```
WAL_VER|0.1.0|2026-07-17 12:00:00 UTC|a1b2c3d|WAL_END
```

stub 在 Program.cs 里用 `#if DEBUG` 注入一个 `const string`，发布版用 `InternalsVisibleTo` + 编译时常量保留这段字符串到二进制。

### 2.8 错误处理

- **payload 损坏**：弹错误框 "EXE 文件已损坏"，退出码 1
- **用户取消密码**：直接退出，退出码 2
- **密码错误**：弹错误框 "密码错误"，**直接退出，不重试**（防暴力破解）
- **解密失败**：弹错误框 "解密失败"，退出码 3
- **临时文件创建失败**：弹错误框 "无法创建临时文件"，退出码 4
- **子进程启动失败**：弹错误框 "无法启动原程序"，退出码 5

---

## 3. packer 章节

### 3.1 职责

packer 是打包工具，职责：

1. 读取原 EXE
2. PE 解析（提取子系统、机器类型，检测 .NET 托管）
3. 根据原 EXE 子系统选择 stub（GUI / Console）
4. 生成 salt / nonce
5. KDF 派生密钥
6. AEAD 加密原 EXE
7. 组装 payload（header + salt + nonce + ciphertext + footer）
8. 写入输出文件：stub 字节 → 复制图标资源 → 追加 payload
9. 显示打包进度与结果

### 3.2 项目结构

```
packer/
├── WinAppLocker.Packer.sln
├── WinAppLocker.Packer.csproj       # 主项目（生成 WinAppLocker.exe）
├── packages.config
├── Properties/
│   ├── AssemblyInfo.cs
│   └── Resources.resx               # 嵌入 stub_gui.exe / stub_console.exe
├── Program.cs                        # WinForms 入口
├── MainForm.cs                       # 主界面
├── MainForm.Designer.cs              # VS 自动生成的界面布局
├── PackCore.cs                       # 打包核心逻辑（与 UI 解耦）
├── PayloadBuilder.cs                 # 组装 payload 二进制
├── CryptoUtil.cs                     # KDF + AEAD 加密
├── PeReader.cs                       # PE 解析 + 图标复制（用 AsmResolver）
├── StubLoader.cs                     # 从嵌入资源读 stub 字节
├── VersionInfo.cs                    # packer 自身版本（编译时注入）
└── assets/
    └── app.ico                      # packer 图标
```

**项目文件关键配置**：

```xml
<!-- WinAppLocker.Packer.csproj -->
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net472</TargetFramework>
    <OutputType>WinExe</OutputType>
    <UseWindowsForms>true</UseWindowsForms>
    <ApplicationIcon>assets\app.ico</ApplicationIcon>
    <Version>0.1.0</Version>
    <AssemblyName>WinAppLocker</AssemblyName>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="AsmResolver.PE" Version="6.0.0" />
    <PackageReference Include="Microsoft.Bcl.Cryptography" Version="..." />
  </ItemGroup>

  <!-- 嵌入 stub 字节（由 build target 在编译前从 stub/build/ 复制过来）-->
  <ItemGroup>
    <EmbeddedResource Include="Resources\stub_gui.exe" />
    <EmbeddedResource Include="Resources\stub_console.exe" />
  </ItemGroup>
</Project>
```

### 3.3 打包流程

```csharp
// PackCore.cs
public static PackReport Pack(PackOptions opts, IProgress<int>? progress = null)
{
    // 1. 校验
    if (string.IsNullOrEmpty(opts.Password))
        throw new ArgumentException("密码不能为空");
    if (opts.Password.Length < 4)
        throw new ArgumentException("密码至少 4 个字符");

    // 2. 读取原 EXE
    byte[] original = File.ReadAllBytes(opts.InputPath);
    progress?.Report(15);

    // 3. PE 解析
    var peInfo = PeReader.Parse(original);
    if (peInfo.IsDotNet) throw new InvalidOperationException(".NET 托管程序暂不支持");
    progress?.Report(25);

    // 4. 选择 stub
    byte[] stubBytes = StubLoader.SelectStub(peInfo.Subsystem, opts.StubPreference);
    progress?.Report(30);

    // 5. 生成 salt / nonce
    byte[] salt = CryptoUtil.RandomBytes(16);
    byte[] nonce = CryptoUtil.RandomBytes(12);
    progress?.Report(35);

    // 6. KDF 派生密钥
    byte[] key = CryptoUtil.DeriveKey(opts.Password, salt, opts.KdfIterations);
    progress?.Report(50);

    // 7. AEAD 加密
    byte[]? aad = opts.UseAad ? PayloadBuilder.BuildAad(peInfo, opts) : null;
    byte[] ciphertext = CryptoUtil.Encrypt(original, key, nonce, aad);
    progress?.Report(75);

    // 8. 组装 payload
    byte[] payload = PayloadBuilder.Build(
        ciphertext, salt, nonce, peInfo, opts, original.Length);
    progress?.Report(90);

    // 9. 写入输出文件
    using (var fs = new FileStream(opts.OutputPath, FileMode.Create))
    {
        fs.Write(stubBytes, 0, stubBytes.Length);  // 先写 stub
    }

    // 10. 复制图标资源（必须先于 payload，因为会重写 PE 资源段可能截断尾部）
    PeReader.CopyIconAndVersionResources(opts.InputPath, opts.OutputPath);

    // 11. 追加 payload
    using (var fs = new FileStream(opts.OutputPath, FileMode.Append))
    {
        fs.Write(payload, 0, payload.Length);
    }
    progress?.Report(100);

    return new PackReport(original.Length, new FileInfo(opts.OutputPath).Length);
}
```

**输出文件结构**：
```
[stub 字节] [可能修改后的资源段] [payload: header | salt | nonce | ciphertext | footer]
```

顺序非常重要：
1. 先写 stub 字节
2. 再用 `UpdateResourceW` 复制原 EXE 的图标/版本资源到 stub（会重写 PE 资源段，可能截断尾部）
3. 最后追加 payload（在资源更新之后，避免被截断）

### 3.4 PE 解析与图标复制

使用 **AsmResolver.PE** 包（最新版 6.0.0，支持 .NET Framework 3.5+）。

**PE 解析**（提取子系统、机器类型、检测 .NET）：

```csharp
// PeReader.cs
using AsmResolver.PE;
using AsmResolver.PE.File.Headers;

public static PeInfo Parse(byte[] peBytes)
{
    var peFile = PEFile.FromBytes(peBytes);
    var peImage = PEImage.FromFile(peFile);

    return new PeInfo
    {
        Subsystem = peFile.FileHeader.Subsystem,
        Machine = peFile.FileHeader.Machine,
        IsDotNet = peImage.DotNetDirectory != null,
        // 提取原 EXE 的图标资源
        IconResources = peImage.Resources.OfType<IconGroupResource>().ToList()
    };
}
```

**图标复制**（用 Win32 `UpdateResourceW`）：

```csharp
public static void CopyIconAndVersionResources(string srcExe, string dstExe)
{
    // 1. 用 AsmResolver 从 srcExe 读 RT_ICON / RT_GROUP_ICON / VS_VERSIONINFO 资源
    // 2. 用 BeginUpdateResource / UpdateResource / EndUpdateResource 写到 dstExe
    // 3. 失败不影响主流程，只记日志
}
```

### 3.5 stub 嵌入

packer 把 stub 字节作为 `EmbeddedResource` 嵌入：

**MSBuild target**（在 csproj 里或单独的 `build.targets`）：

```xml
<Target Name="CopyStubs" BeforeTargets="BeforeBuild">
  <Copy SourceFiles="$(MSBuildThisFileDirectory)..\stub\build\stub_gui.exe"
        DestinationFolder="$(MSBuildProjectDirectory)\Resources" />
  <Copy SourceFiles="$(MSBuildThisFileDirectory)..\stub\build\stub_console.exe"
        DestinationFolder="$(MSBuildProjectDirectory)\Resources" />
</Target>
```

运行时读取嵌入资源：

```csharp
// StubLoader.cs
public static byte[] SelectStub(Subsystem subsystem, StubPreference pref)
{
    byte[] bytes = pref switch
    {
        StubPreference.Gui => LoadEmbedded("stub_gui.exe"),
        StubPreference.Console => LoadEmbedded("stub_console.exe"),
        StubPreference.Auto => subsystem == Subsystem.WindowsGui
            ? LoadEmbedded("stub_gui.exe")
            : LoadEmbedded("stub_console.exe"),
        _ => throw new ArgumentException()
    };

    return bytes;
}

private static byte[] LoadEmbedded(string name)
{
    var asm = Assembly.GetExecutingAssembly();
    using var stream = asm.GetManifestResourceStream($"WinAppLocker.Packer.Resources.{name}")
        ?? throw new InvalidOperationException($"嵌入资源 {name} 未找到");
    using var ms = new MemoryStream();
    stream.CopyTo(ms);
    return ms.ToArray();
}
```

**读取嵌入 stub 的版本信息**：

```csharp
// VersionInfo.cs
public static string? ReadStubVersion(byte[] stubBytes, StubKind kind)
{
    string magic = "WAL_VER|";
    string endMarker = "|WAL_END";

    string text = Encoding.ASCII.GetString(stubBytes);
    int start = text.IndexOf(magic);
    if (start < 0) return null;
    int dataStart = start + magic.Length;
    int end = text.IndexOf(endMarker, dataStart);
    if (end < 0) return null;

    // 格式：version|build_time|git_hash
    string[] parts = text.Substring(dataStart, end - dataStart).Split('|');
    return parts.Length >= 3 ? $"{parts[0]} ({parts[2]}, {parts[1]})" : null;
}
```

### 3.6 GUI 界面

WinForms 主界面（VS 拖控件）：

```
┌──────────────────────────────────────────────────┐
│ WinAppLocker - EXE 密码保护工具        [_][□][X] │
├──────────────────────────────────────────────────┤
│                                                  │
│  原 EXE:   [________________________] [浏览…]    │
│  输出:     [________________________] [浏览…]    │
│                                                  │
│  密码:     [________________] [👁]              │
│  确认:     [________________]                   │
│                                                  │
│  ▶ 高级选项                                      │
│                                                  │
│  [════════════════════════════] 75%             │
│  ✓ 加密成功：1.2MB → 1.5MB                       │
│                                                  │
│  [           加密           ]                    │
│                                                  │
│  提示：加密后的 EXE 需放在原目录运行              │
├──────────────────────────────────────────────────┤
│ WinAppLocker v0.1.0  git: a1b2c3d                │
│ build: 2026-07-17 12:00:00 UTC                   │
│ Stub GUI    v0.1.0  git: a1b2c3d                 │
│ Stub Console v0.1.0  git: a1b2c3d                │
└──────────────────────────────────────────────────┘
```

**MainForm 关键元素**：
- `txtInputPath` / `btnBrowseInput`：原 EXE 选择
- `txtOutputPath` / `btnBrowseOutput`：输出路径选择
- `txtPassword` / `txtConfirm`：密码输入（`PasswordChar = '*'`）
- `btnTogglePassword`：显示/隐藏密码（👁 / 🙈）
- `collapsiblePanelAdvanced`：高级选项（算法/KDF/迭代次数/salt长度/AAD/Stub 偏好）
- `progressBar`：进度条
- `lblResult`：结果显示（成功/失败）
- `btnPack`：加密按钮
- `lblVersion`：底部版本信息（packer + stub 版本分行显示）

**窗口属性**：
- `StartPosition = CenterScreen`（窗口默认居中）
- `FormBorderStyle = FixedDialog`（不可调整大小）
- `MaximizeBox = false` / `MinimizeBox = false`
- `Icon`：从 `app.ico` 加载
- `Text = "WinAppLocker"`

**加密后台线程**：用 `Task.Run` 避免 UI 卡死，`IProgress<int>` 报进度。

### 3.7 版本信息

packer 自身版本通过 MSBuild target 注入 `VersionInfo.cs`：

```xml
<Target Name="GenerateVersionInfo" BeforeTargets="BeforeBuild">
  <Exec Command="git rev-parse --short HEAD" ConsoleToMSBuild="true">
    <Output TaskParameter="ConsoleOutput" PropertyName="GitHash" />
  </Exec>
  <PropertyGroup>
    <BuildTime>$([System.DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"))</BuildTime>
  </PropertyGroup>
  <WriteLinesToFile File="VersionInfo.cs"
    Lines='namespace WinAppLocker.Packer { public static class VersionInfo { public const string Version = "$(Version)"; public const string GitHash = "$(GitHash)"; public const string BuildTime = "$(BuildTime)"; } }'
    Overwrite="true" />
</Target>
```

界面底部显示：
- packer 版本（`v0.1.0  git: a1b2c3d  build: 2026-07-17 12:00:00 UTC`）
- Stub GUI 版本（从嵌入字节搜索 `WAL_VER|...|WAL_END` 标记）
- Stub Console 版本（同上）

---

## 4. Payload 二进制格式

payload 追加在 stub 末尾，结构如下（所有多字节整数用小端序）：

```
┌─────────────────────────────────────────────────────────┐
│ Header (固定 64 字节)                                   │
│   - magic         [8]  "WALOCK\x01\x00"                 │
│   - version       [2]  u16 = 1                          │
│   - header_size   [2]  u16 = 64                         │
│   - header_crc32  [4]  u32  (对 header 其余部分)        │
│   - algorithm_id  [2]  u16 (1 = AES-256-GCM)            │
│   - kdf_id        [2]  u16 (1 = PBKDF2-SHA256)          │
│   - kdf_iterations [4] u32                              │
│   - flags         [4]  u32 (bit0=use_aad, bit1=erase)   │
│   - salt_len      [2]  u16                              │
│   - nonce_len     [2]  u16                              │
│   - plaintext_len [8]  u64                             │
│   - plaintext_crc32 [4] u32                            │
│   - subsystem     [4]  u32 (原 EXE 子系统)              │
│   - machine       [4]  u32 (原 EXE 机器类型)            │
│   - timestamp     [8]  u64 (打包时间 unix epoch)        │
│   - reserved      [8]  全 0                            │
├─────────────────────────────────────────────────────────┤
│ Salt          [salt_len]  随机字节                      │
│ Nonce         [nonce_len] 随机字节                      │
│ Ciphertext    [plaintext_len + 16]  (含 16 字节 GCM tag) │
├─────────────────────────────────────────────────────────┤
│ Extension TLV (可选, 可重复)                            │
│   - tag   [2]  u16                                     │
│   - len   [2]  u16                                     │
│   - value [len]                                        │
├─────────────────────────────────────────────────────────┤
│ Footer (固定 32 字节)                                   │
│   - payload_len  [8]  u64 (从 header 起到 footer 前)   │
│   - footer_crc32 [4]  u32                              │
│   - magic_a      [8]  "WALEND\xAA\xAA"                 │
│   - magic_b      [8]  "WALEND\xBB\xBB"                 │
│   - footer_pad   [4]  全 0                             │
└─────────────────────────────────────────────────────────┘
```

**设计要点**：
- header 和 footer 各有一个 magic（双 magic 防尾部追加混淆）
- header 有 CRC32 校验，footer 有 CRC32 校验，plaintext 有 CRC32 + 长度双重校验
- 扩展区用 TLV 结构，支持未来添加自定义元数据（如原文件名、作者签名等）
- stub 从文件**尾部**读 footer，反向定位 header 起点

---

## 5. 构建与发布

### 5.1 解决方案结构

```
applocker/
├── WinAppLocker.sln                # 总解决方案
├── stub/
│   └── WinAppLocker.Stub.csproj    # stub 项目
├── packer/
│   └── WinAppLocker.Packer.csproj  # packer 项目
├── shared/
│   └── WinAppLocker.Shared.csproj  # 可选：共享常量（算法 ID、payload 格式常量）
├── tests/
│   ├── WinAppLocker.Tests.csproj   # 单元测试
│   └── samples/                    # 测试用样例 EXE
├── build/
│   ├── build.ps1                   # 编译脚本
│   ├── test.ps1                    # 自动化测试脚本
│   └── version.targets             # MSBuild 版本注入 target
└── dist/                           # 发布输出
```

### 5.2 构建顺序

```
1. dotnet build stub  -c Release  -p:StubMode=Gui      → stub/build/stub_gui.exe
2. dotnet build stub  -c Release  -p:StubMode=Console  → stub/build/stub_console.exe
3. dotnet build packer -c Release                     → packer/bin/Release/WinAppLocker.exe
   (packer 的 BeforeBuild target 自动把 stub 字节拷到 Resources/)
4. copy packer/bin/Release/WinAppLocker.exe dist/
```

### 5.3 发布产物

```
dist/
└── WinAppLocker.exe      # 单一可执行文件（stub 已嵌入）
```

发布只需一个文件。用户机器上的 .NET Framework 4.7.2（Win10/11 自带）提供运行时。

### 5.4 构建脚本

```powershell
# build.ps1
param([switch]$Release)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$config = if ($Release) { "Release" } else { "Debug" }

# 1. 编译 stub_gui
Write-Host "==> building stub_gui..." -ForegroundColor Cyan
dotnet build stub -c $config -p:StubMode=Gui
if ($LASTEXITCODE -ne 0) { throw "stub_gui build failed" }

# 2. 编译 stub_console
Write-Host "==> building stub_console..." -ForegroundColor Cyan
dotnet build stub -c $config -p:StubMode=Console
if ($LASTEXITCODE -ne 0) { throw "stub_console build failed" }

# 3. 编译 packer（自动嵌入 stub）
Write-Host "==> building packer..." -ForegroundColor Cyan
dotnet build packer -c $config
if ($LASTEXITCODE -ne 0) { throw "packer build failed" }

if ($Release) {
    New-Item -ItemType Directory -Path "$root\dist" -Force | Out-Null
    Copy-Item "packer\bin\$config\WinAppLocker.exe" "$root\dist\WinAppLocker.exe" -Force
    Write-Host "==> dist/WinAppLocker.exe ready" -ForegroundColor Green
} else {
    Write-Host "==> packer\bin\$config\WinAppLocker.exe ready" -ForegroundColor Green
}
```

---

## 6. 技术选型

### 6.1 为什么选 .NET Framework 4.7.2 + WinForms

| 维度 | .NET Framework 4.7.2 + WinForms | 其他方案 |
|---|---|---|
| 用户运行时 | Win10/11 自带，**零安装** | .NET 8 需装运行时（70MB+）或自包含发布 |
| UI 开发体验 | **VS 拖控件，5 分钟出 UI** | egui / iced / 手写 Win32 都很别扭 |
| 加密 API | `AesGcm`（via NuGet）+ `Rfc2898DeriveBytes`（原生） | C++ 需自己引 CryptoPP / bcrypt |
| PE 解析 | AsmResolver 6.0 原生支持 4.7.2 | Rust goblin 也能用，但 UI 还是别扭 |
| 调试体验 | VS 断点 / Edit and Continue / 热重载 | Rust cargo-watch 重新编译重启 |
| 发布体积 | ~200KB exe + 系统 .NET 运行时 | Rust 4.7MB 单文件（更轻，但 UI 别扭） |

### 6.2 PE 库选型：AsmResolver vs PeNet

| 维度 | AsmResolver 6.0.0 | PeNet 5.1.0 |
|---|---|---|
| .NET Framework 4.7.2 支持 | ✅ 原生（3.5+） | ✅ 原生（4.8+，4.7.2 向下兼容） |
| 最新版本 .NET Framework 支持 | ✅ 6.0.0（2026-05） | ⚠️ 5.1.0（已停更，6.x 放弃） |
| PE 头解析 | ✅ | ✅ |
| 资源（图标）操作 | ✅ `AsmResolver.PE.Win32Resource` | ✅ |
| .NET 元数据 | ✅ `AsmResolver.DotNet`（更强） | ✅（重点） |
| 许可证 | MIT | Apache-2.0 |
| 维护活跃度 | 活跃（3,468 commits） | 活跃但 4.x 后已放弃 .NET Framework |
| 定位 | PE 读写操作 | 偏恶意软件分析 |

**最终选择**：**AsmResolver.PE 6.0.0**
- 最新版本原生支持 .NET Framework 3.5+
- PE 读写 + 资源操作能力完整，正好覆盖需求
- 不需要降级到老版本（PeNet 必须用 5.1.0，已停更）

### 6.3 加密库选型

| 方案 | 来源 | 是否需要 NuGet | 推荐 |
|---|---|---|---|
| **AES-256-GCM** | `Microsoft.Bcl.Cryptography` | ✅ 需要 | ⭐⭐⭐ 推荐 |
| AES-256-CBC + HMAC-SHA256 | `System.Security.Cryptography`（原生） | ❌ 不需要 | 备选（不引 NuGet） |
| ChaCha20-Poly1305 | `Microsoft.Bcl.Cryptography` | ✅ 需要 | 备选 |

**最终选择**：**AES-256-GCM via `Microsoft.Bcl.Cryptography`**
- GCM 是 AEAD，提供机密性 + 完整性
- API 和 .NET 5+ 完全一致，便于未来迁移
- 标准算法，密文与任何标准实现字节级兼容

### 6.4 KDF 选型

`Rfc2898DeriveBytes`（PBKDF2-SHA256）是 .NET Framework 4.7.2 原生支持的，无需额外依赖。默认 600,000 次迭代。

---

## 7. 安全说明

### 7.1 临时文件方案的本质

本项目用临时文件 + CreateProcess 方案释放原 EXE，本质是**掩耳盗铃**：

- 运行时明文 PE 会短暂存在于原目录（即使设了 HIDDEN 属性）
- 加密保护的是**静态 EXE 文件在磁盘上的机密性**（防止直接拷走原 EXE）
- 不能阻止有管理员权限的攻击者在运行时 dump 内存或抓取临时文件

### 7.2 实际威胁模型

| 威胁 | 防护能力 | 说明 |
|---|---|---|
| 直接拷走加密后的 EXE | ✅ 防护 | 无密码无法解密 |
| 暴力破解密码 | ✅ 防护 | PBKDF2 600k 迭代，密码输错直接退出 |
| 运行时内存 dump | ❌ 不防护 | 明文在内存中，可被调试器/dumper 抓走 |
| 运行时临时文件抓取 | ⚠️ 部分防护 | 文件 HIDDEN + pending delete，但管理员可见 |
| Reverse engineering stub | ⚠️ 部分防护 | .NET 程序集可被反编译（可用 obfuscator 缓解） |

### 7.3 临时文件清理

- 临时文件创建时设 `FILE_ATTRIBUTE_HIDDEN`
- 子进程退出后**立即删除**（带 5 次 50ms 重试）
- 文件名 `el_{stub_pid}.exe`（确定性，便于残留排查）
- 若删除失败（杀软占用 / 权限问题），只记日志不阻塞退出

### 7.4 密码策略

- **密码输错一次直接退出，不重试**（防暴力破解）
- 最小长度 4 字符（packer 端校验）
- 密码用 `SecureString` 或用完立即清零的 `byte[]`（.NET Framework 限制，无法真正零内存）

### 7.5 .NET 反编译防护

stub 和 packer 都是 .NET 程序集，可被 `dnSpy` / `ILSpy` 反编译。缓解方案：
- **Obfuscar**（开源）：混淆符号名、控制流
- **ConfuserEx**（开源）：混淆 + 加密
- 商业混淆器：Eazfuscator.NET、.NET Reactor 等

是否加混淆取决于威胁模型。如果只是防普通用户拷走 EXE，不混淆也够用。

---

## 附录：从 Rust 迁移的注意点

本设计是**完全重新实现**，不保留与 Rust 版本的兼容性。迁移时注意：

| 维度 | Rust 实现 | .NET 实现 |
|---|---|---|
| payload 格式 | `exelock-payload` crate 自定义格式 | 重新设计（见 §4，可参考但不强求兼容） |
| 算法 ID | `algorithm::id::AES_256_GCM = 0x0001` | 重新定义，可沿用 0x0001 |
| stub 临时文件名 | `el_{pid}.exe` | 沿用 |
| 图标复制 | `UpdateResourceW` via `windows` crate | `UpdateResourceW` via P/Invoke |
| 密码 UI | 手写 `DLGTEMPLATE` 内存模板 | WinForms 拖控件 |
| PE 解析 | `goblin` crate | AsmResolver.PE |
| 加密 | `aes-gcm` crate | `Microsoft.Bcl.Cryptography.AesGcm` |
| KDF | `pbkdf2` crate | `Rfc2898DeriveBytes` |
| stub 嵌入 | `include_bytes!` 编译期 | `EmbeddedResource` 编译期 |
| 版本注入 | `cargo:rustc-env` + `env!()` | MSBuild `<WriteLinesToFile>` + `const` |
