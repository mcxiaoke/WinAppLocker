# WinAppLocker - EXE 密码保护工具

给 Windows EXE 文件加密码保护，加密后的 EXE 放在原目录运行，输入正确密码后才能启动，不影响原程序的任何功能和依赖。

## 工作原理

1. **打包时**：用 AES-256-GCM 加密原 EXE 的 PE 数据，将加密数据附加到 stub（引导程序）尾部，生成新的 EXE。
2. **运行时**：stub 弹出密码输入框 → 验证密码 → 解密原 EXE → 在**原 EXE 所在目录**创建随机名临时文件 → `CreateProcessW` 启动子进程 → 立即删除临时文件（pending delete，目录中不可见）→ stub 等待子进程退出后退出。子进程退出后 OS 自动清理临时文件数据。

### 为什么不用 RunPE / Process Hollowing？

- **RunPE（内存加载）**：在当前进程内映射并跳转执行 PE，CRT/堆/TLS/PEB 等进程资源冲突，复杂程序（Chrome、Notepad3 等）会崩溃。
- **Process Hollowing**：创建挂起子进程替换镜像，需要手动处理导入表、重定位、TLS 回调、异常处理等，实现复杂且容易有兼容性问题。
- **临时文件方案**：让 Windows 原生加载器处理所有 PE 加载细节（SxS、DLL 搜索、TLS、异常、ASLR、Manifest 等），兼容性最高，等同于原 EXE 直接运行。

### 安全说明

- 临时文件创建在原 EXE 所在目录（确保 SxS 探测、DLL 搜索路径、`GetModuleFileNameW` 返回正确路径），文件名 `el_{stub_pid}.exe`（确定性，便于残留排查，多实例通过 PID 区分）。
- 临时文件在创建时即设置 **`FILE_ATTRIBUTE_HIDDEN`**，资源管理器默认设置下不可见。
- **子进程退出后才删除临时文件**：子进程运行期间 PE loader 持有 EXE 镜像，此时 DeleteFile 会因 sharing violation 失败；改为 `WaitForSingleObject` 等子进程退出后再删，配合短重试（50ms × 5）应对 OS 异步释放 / 杀软扫描占用。
- 父进程（stub）持有进程句柄等待子进程退出，子进程退出后所有句柄释放，临时文件被删除，磁盘上无残留。
- **密码输错一次直接退出**：不提供重试，避免暴力破解。
- 加密算法：AES-256-GCM，密钥派生：PBKDF2-SHA256（100,000 次迭代）。

## 项目结构

```
applocker/
├── crates/
│   ├── exelock-crypto/    # 加密/解密（AES-GCM, ChaCha20-Poly1305, PBKDF2）
│   ├── exelock-payload/   # 二进制打包格式（TLV 结构）
│   └── exelock-pe/        # PE 解析 + loader（临时文件+CreateProcess）
├── stub/
│   ├── build.rs           # 注入 git hash + 构建时间到 stub 二进制
│   └── src/bin/
│       ├── stub_gui.rs    # GUI stub（无控制台窗口，弹出密码对话框）
│       ├── stub_console.rs # Console stub（保留控制台，密码命令行输入）
│       └── stub_test.rs   # 测试用 stub（硬编码密码，跳过密码 UI）
├── packer/
│   ├── assets/
│   │   └── app.ico        # packer 图标
│   ├── build.rs           # 嵌入图标 + 注入版本信息 + 拷贝 stub 到 OUT_DIR
│   ├── src/
│   │   ├── main.rs        # GUI 打包工具入口（eframe/egui）
│   │   ├── app.rs         # GUI 界面
│   │   ├── pack.rs        # 打包核心逻辑
│   │   ├── icon.rs        # 图标提取与设置
│   │   ├── stub_selector.rs # 通过 include_bytes! 嵌入 stub
│   │   ├── version.rs     # 版本信息（自身 + 读取嵌入 stub 的版本）
│   │   └── strength.rs    # 密码强度评估
│   └── examples/
│       ├── pack_cli.rs    # 命令行打包工具
│       ├── pack_test.rs   # 测试用打包（用 stub_test，硬编码密码）
│       └── diagnose.rs    # PE 诊断工具
├── tests/samples/         # 测试用样例 EXE
├── rebuild.ps1            # 编译脚本
├── test_locked.ps1        # 自动化测试脚本
└── dist/                  # 发布输出目录（-Release 时生成）
```

## 版本信息

stub 和 packer 都通过 `build.rs` 在编译时注入版本信息：
- **版本号**：Cargo.toml 中的 `version` 字段
- **Git hash**：`git rev-parse --short HEAD`
- **构建时间**：UTC 时间

packer 界面底部显示自身版本和 stub 版本。stub 在二进制中嵌入可搜索标记 `EXELOCK_VER|version|build_time|git_hash|EXELOCK_END`，packer 从嵌入的 stub 字节中搜索提取。

## stub 嵌入机制

packer 通过 `include_bytes!(concat!(env!("OUT_DIR"), "/stub_gui.exe"))` 把 stub 字节直接编进自己的 exe：
- `rebuild.ps1` 先编译 stub，生成 `target/<profile>/stub_gui.exe` / `stub_console.exe`
- packer 的 `build.rs` 把这两个 stub 文件拷到 `OUT_DIR`
- packer 源码用 `include_bytes!` 在编译期读取，stub 字节成为 packer exe 的一部分
- 发布产物是**单一的 `WinAppLocker.exe`**，不再需要外部 `stub/` 目录

## 开发环境

- Windows 10/11
- Rust (MSVC toolchain)，推荐 1.80+
- Visual Studio 2022 Build Tools（或完整 VS）
- PowerShell 5.1+

## 开发流程

### 1. 编译

```powershell
# Debug 构建（开发调试用，编译快，含调试信息）
.\rebuild.ps1

# Release 构建（发布用，LTO 优化，strip 符号）
.\rebuild.ps1 -Release
```

`rebuild.ps1` 做以下事情：
1. 编译 stub（gui + console），注入 git hash + 构建时间到 stub 二进制
2. 编译 packer（`WinAppLocker.exe`）：
   - packer 的 `build.rs` 把 stub 从 `target/<profile>/` 拷到 `OUT_DIR`
   - packer 源码用 `include_bytes!` 在编译期读取 stub 字节，编进 packer exe
   - 同时嵌入图标 + 注入 packer 自身版本信息

Release 模式输出到 `dist/`：
```
dist/
└── WinAppLocker.exe      # 单一可执行文件（stub 已嵌入）
```

### 2. 自动化测试

```powershell
# 编译并测试所有内置样例（hellogui/DontSleep/notepad3）
.\test_locked.ps1

# 等待8秒后检测进程（启动慢的程序可用）
.\test_locked.ps1 -Wait 8

# 测试指定 EXE
.\test_locked.ps1 -Target "C:\path\to\chrome.exe"

# 启用调试日志（写入 %TEMP%\exelock_debug.log）
.\test_locked.ps1 -Debug
```

### 3. 调试

设置环境变量 `EXELOCK_DEBUG=1` 启用调试日志：

```powershell
$env:EXELOCK_DEBUG = "1"
# 运行加密后的 EXE...
Get-Content "$env:TEMP\exelock_debug.log" -Tail 30
```

### 4. 命令行打包测试

```powershell
# 用 stub_test 打包（密码硬编码 test1234，用于自动化测试）
cargo build --release -p exelock-packer --example pack_test
$env:STUB_TEST_PATH = "target/release/stub_test.exe"
cargo run --release -p exelock-packer --example pack_test -- path/to/input.exe path/to/output.exe

# 正式 CLI 打包（用 stub_gui/stub_console，弹出密码框）
cargo build --release -p exelock-packer --example pack_cli
cargo run --release -p exelock-packer --example pack_cli -- input.exe output.exe YourPassword
```

## 发布流程

```powershell
# 1. Release 构建
.\rebuild.ps1 -Release

# 2. 快速验证（可选）
.\test_locked.ps1 -Wait 5

# 3. 发布产物在 dist/ 目录
#    dist/WinAppLocker.exe（单一文件，stub 已嵌入）
```

发布时只需分发 `dist/WinAppLocker.exe` 这一个文件。

## 使用流程

### 方式一：GUI 工具

1. 将 `WinAppLocker.exe` 放到任意位置
2. 运行 `WinAppLocker.exe`
3. 选择要加密的 EXE 文件
4. 设置密码并确认
5. 选择输出路径（或直接覆盖原文件，建议先备份）
6. 点击"加密"
7. 将加密后的 EXE 放回原目录（与依赖 DLL、资源文件等在一起）
8. 运行加密后的 EXE，输入密码即可正常启动原程序（输错一次直接退出）

### 方式二：命令行

```powershell
# 编译 CLI 工具
cargo build --release -p exelock-packer --example pack_cli

# 打包
.\target\release\examples\pack_cli.exe input.exe output.exe password
```

### 使用注意事项

1. **加密后的 EXE 必须放在原目录运行**（和原 EXE 的 DLL、资源、子目录在一起），不需要打包依赖文件。
2. 工具会根据原 EXE 的子系统自动选择 stub：GUI 程序用无控制台窗口的 stub，Console 程序用保留控制台的 stub。
3. **密码输错一次直接退出**，不提供重试。
4. 加密后的 EXE 可以重命名，但运行时仍需在原目录。
5. 建议加密前备份原 EXE。

## 支持的程序类型

- GUI 应用程序（Notepad3、DontSleep、Chrome 等）
- Console 应用程序
- .NET 应用程序
- 多进程应用（Chrome 等会启动子进程的程序）
- 带 SxS manifest 的应用
- 带 DLL 依赖和资源文件的应用
- 带版本子目录（Chrome 式目录结构）的应用
- 有 ASLR/无 ASLR 的 EXE
