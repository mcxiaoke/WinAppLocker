# 本机开发环境手册

本机已安装的开发工具清单，按类别整理。路径均为绝对路径，可直接调用。

> 维护原则：新装工具请同时更新此文档；废弃工具也请标注移除。

---

## 0. 路径速查

| 来源 | 根路径 | 说明 |
|------|--------|------|
| 开发工具 | `C:\Home\Develop\` | 编译器、调试器、SDK、IDE |
| 便携工具 | `C:\Home\Tools\`    | 系统工具、多媒体、效率工具 |
| Scoop    | `C:\Home\Develop\Scoop\shims\` | 命令行工具 shim |
| Python   | `C:\Home\Develop\Python\`     | 系统 Python |
| 共享 venv | `C:\Home\Develop\venv\`      | 通用 venv（capstone/pefile 等） |
| msys2    | `C:\Home\Develop\msys64\`     | mingw32/mingw64 工具链 |
| Git      | `C:\Home\Develop\Git\`        | Git for Windows（含 git-bash） |
| cygwin   | `C:\Home\Develop\cygwin64\`   | cygwin 工具集 |

---

## 1. 编译器 / 工具链

### C/C++

| 工具 | 路径 | 说明 |
|------|------|------|
| w64devkit | `C:\Home\Develop\w64devkit\bin\` | GCC 13+/mingw-w64 x64 工具链 |
| msys2 mingw32 | `C:\Home\Develop\msys64\mingw32\bin\` | x86 GCC |
| msys2 mingw64 | `C:\Home\Develop\msys64\mingw64\bin\` | x64 GCC 备选 |
| msys2 clang64 | `C:\Home\Develop\msys64\clang64\bin\` | x64 GCC 备选 |
| msys2 shell   | `C:\Home\Develop\msys64\msys2.exe`     | msys2 终端 |
| cygwin64      | `C:\Home\Develop\cygwin64\bin\`        | cygwin 工具集 |

> 安装 mingw32：`pacman -S mingw-w64-i686-gcc`

### Rust

| 工具 | 路径 | 说明 |
|------|------|------|
| rustc / cargo | 通过 scoop shim：`rustc.exe`、`cargo.exe` | Rust 工具链 |

### Go

| 工具 | 路径 | 说明 |
|------|------|------|
| go / gofmt | `C:\Home\Develop\go\bin\go.exe` | Go 编译器 + gofmt |
| go env     | `C:\Home\Develop\go\go.env`      | Go 环境配置 |

### Node.js / Bun

| 工具 | 路径 | 说明 |
|------|------|------|
| node    | `C:\Home\Develop\nodejs\node.exe` | Node.js 运行时 |
| npm/npx | `C:\Home\Develop\nodejs\npm.cmd`   | 包管理 |
| corepack | `C:\Home\Develop\nodejs\corepack` | pnpm/yarn 管理 |
| bun/bunx | scoop shim: `bun.exe`             | Bun 运行时 |

### Java

| 工具 | 路径 | 说明 |
|------|------|------|
| java / jar / jdb | `C:\Home\Develop\JDK\bin\` | JDK |
| jcmd / jmap / jps / jmod | 同上 | JVM 诊断工具 |
| gradle | scoop shim: `gradle` / `gradle.cmd` | 构建工具 |

### Python

| 工具 | 路径 | 说明 |
|------|------|------|
| python3   | `C:\Home\Develop\Python\python.exe` | 系统 Python |
| python313 | scoop shim: `python313.exe`         | Scoop Python |
| pip       | `C:\Home\Develop\Python\Scripts\`  | pip |
| uv / uvx  | scoop shim: `uv.exe`、`uvx.exe`    | 现代 Python 包管理（推荐用 uv 建 venv） |
| idle3      | scoop shim: `idle3.cmd`            | IDLE |

### Flutter / Dart

| 工具 | 路径 | 说明 |
|------|------|------|
| dart / flutter | `C:\Home\Develop\flutter\bin\` | Flutter SDK |

---

## 2. 调试器 / 逆向工程

### 调试器（重点）

| 工具 | 路径 | 说明 |
|------|------|------|
| cdb (x64) | `C:\Home\Develop\WinDbg\x64\cdb.exe`     | 命令行 WinDbg，attach/启动 + 脚本化 dump 调用栈 |
| cdb (x86) | `C:\Home\Develop\WinDbg\x86\cdb.exe`     | x86 cdb（调试 32-bit 进程必用） |
| windbg    | `C:\Home\Develop\WinDbg\x64\windbg.exe`  | GUI WinDbg |
| kd        | `C:\Home\Develop\WinDbg\x64\kd.exe`      | 内核调试器 |
| x64dbg    | `C:\Home\Tools\x64debug\x96dbg.exe`      | x64dbg/x32dbg 启动器（GUI 反汇编 + 调试） |
| x32dbg    | `C:\Home\Tools\x64debug\x32\x32dbg.exe`  | 32-bit 调试 |
| x64dbg    | `C:\Home\Tools\x64debug\x64\x64dbg.exe`  | 64-bit 调试 |

### 反汇编 / 反编译

| 工具 | 路径 | 说明 |
|------|------|------|
| IDA Pro    | `C:\Home\Develop\IDAPro\ida64.exe`、`ida.exe`、`idat.exe` | IDA 反汇编器 |
| Ghidra     | `C:\Home\Develop\ghidra\ghidraRun`                      | Ghidra 反编译器 |
| PE-bear    | `C:\Home\Develop\PE-bear\`                              | PE 分析（GUI） |

### 十六进制编辑

| 工具 | 路径 | 说明 |
|------|------|------|
| HxD    | `C:\Home\Tools\HxD\HxD64.exe`、`HxD32.exe` | 十六进制编辑器 |
| WinHex | `C:\Home\Tools\WinHex\WinHex64.exe`        | WinHex（含模板/脚本） |
| M1T/WinHex | `C:\Home\Tools\M1T\winhex.exe`          | 同上副本 |

---

## 3. PE / 二进制分析

### 命令行工具

| 工具 | 路径 | 说明 |
|------|------|------|
| Dependencies CLI | scoop shim: `dependencies.exe` | Dependency Walker 替代 |
| Dependencies GUI | scoop shim: `dependenciesgui.exe` | 同上 GUI |
| upx              | scoop shim: `upx.exe`           | UPX 压缩/解压 |
| dark             | scoop shim: `dark.exe`          | WiX Dark 反汇编 MSI |
| nuget            | scoop shim: `nuget.exe`         | NuGet CLI |
| exiftool         | scoop shim: `exiftool.exe`      | 元数据提取（含 PE 信息） |

### Python 库（已装在 venv）

共享 venv：`C:\Home\Develop\venv\`，winlock venv：`F:\Temp\pe\winlock\.venv\`

| 库 | 用途 |
|----|------|
| pefile      | PE 解析（节表/导入/导出/资源/TLS/重定位） |
| capstone    | 反汇编（多架构） |
| unicorn     | CPU 模拟 |
| pywinauto   | Windows GUI 自动化（win32/uia backend） |
| pywin32     | Win32 API（win32gui/win32api/win32con） |
| psutil      | 进程/系统信息 |

> 新建 venv：`uv venv <path>` → `<path>\Scripts\activate` → `uv pip install <pkg>`

---

## 4. 编辑器 / IDE

| 工具 | 路径 | 说明 |
|------|------|------|
| Vim       | scoop shim: `vim.exe`、`gvim.exe`、`vimdiff.exe` | gVim |
| view/vi   | scoop shim: `vi.exe`、`view.exe`              | Vim 别名 |
| Sublime Text | `C:\Home\Tools\SublimeText\subl.exe`         | Sublime |

### Git 工具

| 工具 | 路径 | 说明 |
|------|------|------|
| git       | `C:\Home\Develop\Git\bin\git.exe` 或 scoop shim | Git |
| git-bash  | `C:\Home\Develop\Git\git-bash.exe` | Git Bash 终端 |
| gitk / tig | `C:\Home\Develop\Git\cmd\gitk.exe` / `tig.exe` | Git GUI / TUI |
| git-lfs  | scoop shim: `git-lfs.exe` | Git LFS |

---

## 5. 命令行增强

### Unix 命令移植

| 工具 | 来源 | 说明 |
|------|------|------|
| coreutils | `C:\Home\Tools\coreutils\*.exe` | cat/cp/ls/mv/rm/head/tail/wc/grep/sort/uniq/... |
| curl      | scoop shim: `curl.exe`           | HTTP 客户端 |
| wget      | scoop shim: `wget.exe`           | 下载工具 |
| file      | scoop shim: `file.exe`           | 文件类型识别 |
| sh        | scoop shim: `sh.exe`             | POSIX shell |
| ack       | scoop shim: `ack` / `ack.cmd`    | grep 替代 |

### 现代命令行工具（推荐）

| 工具 | 路径 | 说明 |
|------|------|------|
| ripgrep (rg) | scoop shim: `rg.exe`         | 极快 grep（推荐用，代替 grep） |
| fd           | scoop shim: `fd.exe`         | find 替代 |
| bat          | scoop shim: `bat.exe`        | cat 替代（语法高亮） |
| exa/eza      | scoop shim: `ex.exe`         | ls 替代 |
| fzf           | scoop shim: `fzf.exe`        | 模糊查找 |
| starship     | scoop shim: `starship.exe`   | shell prompt 美化 |
| xxd          | scoop shim: `xxd.exe`        | hex dump |
| dua          | scoop shim: `dua.exe`        | du 替代（磁盘占用） |
| gdu          | scoop shim: `gdu.exe`        | 磁盘占用分析 |
| croc         | scoop shim: `croc.exe`       | 跨设备文件传输 |
| ctop         | scoop shim: `ctop.exe`       | 容器/进程 top |
| copyq        | scoop shim: `copyq.exe`      | 剪贴板管理 |


---

## 6. 包管理 / 构建

| 工具 | 路径 | 说明 |
|------|------|------|
| scoop         | `C:\Home\Develop\Scoop\shims\scoop.cmd` | Scoop 包管理 |
| scoop-search  | scoop shim: `scoop-search.exe`           | 快速搜索 scoop 包 |
| uv / uvx      | scoop shim: `uv.exe`、`uvx.exe`          | Python 包/venv 管理 |
| nuget         | scoop shim: `nuget.exe`                  | .NET 包管理 |
| gradle        | scoop shim: `gradle.cmd`                 | Java/Android 构建 |
| npm / npx     | `C:\Home\Develop\nodejs\npm.cmd`          | Node 包管理 |
| corepack      | `C:\Home\Develop\nodejs\corepack`        | pnpm/yarn 管理 |



---

## 维护

- 新增工具：在对应分类下追加表格行，注明路径和用途
- 工具升级：更新版本号（如适用）
- 工具废弃：从表格移除或注明"已废弃"
- 路径变更：批量替换

最后更新：2026-07-18
