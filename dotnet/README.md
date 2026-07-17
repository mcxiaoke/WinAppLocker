# WinAppLocker (.NET)

一个把 EXE 加密码保护的工具：用密码（PBKDF2 派生密钥）对原程序进行 AES-256-CBC + HMAC-SHA256
加密，打包进一个带密码输入框的"壳"程序（stub）。运行时输入正确密码，壳程序在内存解密并启动
原程序（以隐藏临时文件方式运行，退出后自动删除）。

当前版本：**1.0.0**

---

## 功能特性

- **密码保护**：对 EXE 进行强加密，无正确密码无法运行。
- **算法**：PBKDF2-HMAC-SHA256（默认 20 万次迭代）派生密钥；AES-256-CBC 加密 +
  HMAC-SHA256 完整性校验（Encrypt-then-MAC），可抵抗篡改。
- **自动适配**：根据原 EXE 子系统（GUI / 控制台）自动选择对应 stub，也可手动指定。
- **图标继承**：打包后保留原程序的主图标和版本信息，外观上与原程序一致。
- **跨类型支持**：支持原生 EXE 与 .NET EXE。
- **三种运行壳**：
  - `Gui`：弹出图形密码框（适合 GUI 程序）。
  - `Console`：控制台密码输入（适合命令行程序）。
  - `Test`：内置密码 `test1234`，跳过密码输入（仅供自动化测试，切勿用于实际加密）。
- **自检命令**：`--info` 可解析已加密 EXE 的头部/尾部/扩展元数据并校验完整性。

---

## 使用方法

### 1. 构建

```powershell
# Debug 构建（产物在 packer/bin/Debug）
.\build.ps1

# Release 构建，输出单文件 dist/WinAppLocker.exe（+ .config）
.\build.ps1 -Release

# 清理后重建
.\build.ps1 -Release -Clean
```

构建顺序：先编译三个 stub（GUI / 控制台 / 测试），再编译 packer；packer 会把 stub 作为
嵌入资源打包，并用 Costura 将依赖 DLL 嵌入为单文件 exe。

### 2. 图形界面（GUI）

直接运行 `WinAppLocker.exe`，在窗口中：

1. 选择**输入 EXE**（原程序）和**输出 EXE** 路径。
2. 输入并确认**密码**（至少 4 个字符）。
3. 选择 Stub 类型（默认"自动"）与迭代次数（默认 200000）。
4. 点击"执行加密操作"，生成的加密 EXE 需放在原目录运行。

### 3. 命令行（CLI）

```powershell
# 加密：把 input.exe 加密为 output.exe
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码

# 指定 stub 与迭代次数
WinAppLocker.exe --pack -i input.exe -o output.exe -p 你的密码 --stub Auto --iterations 300000

# 查看已加密 EXE 的信息与完整性校验
WinAppLocker.exe --info output.exe

# 查看版本
WinAppLocker.exe --version
```

> 注意：加密后的 EXE 运行时会在**自身所在目录**释放一个隐藏临时文件并启动它，
> 因此请务必与原目录一起移动/分发，且目录需有写入权限。

---

## 开发测试方法

- **构建**：`.\build.ps1 -Release` 生成 `dist/WinAppLocker.exe`。
- **自动化测试**：`.\test.ps1` 使用内置密码的 `stub_test` 做端到端 round-trip 测试，
  默认对 `..\tests\samples` 下的 CLI/GUI 样本加解密并验证运行；可加 `-Info` 同时校验
  `--info` 输出，或 `-Samples "a.exe,b.exe"` 指定样本。
- **手动验证**：`WinAppLocker.exe --info <加密文件>` 检查头部/尾部 CRC 与扩展元数据是否一致；
  实际运行加密 EXE 输入密码确认能正常启动原程序。
- **版本号**：统一在 `Directory.Build.props` 的 `Major/Minor/Patch` 中维护（当前 1.0.0），
  编译期自动注入 Git 提交、构建时间等元数据。
