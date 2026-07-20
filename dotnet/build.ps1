# WinAppLocker .NET 构建脚本
# 用法：
#   .\build.ps1              # Debug 构建（不拷到 dist）
#   .\build.ps1 -Release     # Release 构建，输出 dist/WinAppLocker.exe + dist/stub/
#   .\build.ps1 -Clean       # 清理后构建
#   .\build.ps1 -SkipWinLock # 跳过 WinLock 编译（仅 dotnet 部分，调试用）
param(
    [switch]$Release,
    [switch]$Clean,
    [switch]$SkipWinLock
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
# Push-Location 而非 Set-Location：脚本退出（正常/异常）时用 finally 恢复调用方 cwd
Push-Location $root
try {

# applocker 仓库根目录（build.ps1 在 dotnet/ 下，根目录是上一层）
$applockerRoot = Split-Path -Parent $root
# WinLock 源码目录（packer 子目录是 winlock 项目的代码）
$winlockDir = Join-Path $applockerRoot "packer"

$config = if ($Release) { "Release" } else { "Debug" }
Write-Host "==> 配置: $config" -ForegroundColor Cyan

if ($Clean) {
    Write-Host "==> 清理..." -ForegroundColor Yellow
    dotnet clean shared -c $config 2>&1 | Out-Null
    dotnet clean stub -c $config 2>&1 | Out-Null
    dotnet clean stub.console -c $config 2>&1 | Out-Null
    dotnet clean stub.test -c $config 2>&1 | Out-Null
    dotnet clean packer -c $config 2>&1 | Out-Null
    foreach ($p in @("stub", "stub.console", "stub.test", "shared", "packer")) {
        foreach ($d in @("bin", "obj")) {
            $p2 = "$root\$p\$d"
            if (Test-Path $p2) { Remove-Item $p2 -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    if (Test-Path "$root\packer\Resources") { Remove-Item "$root\packer\Resources" -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path "$root\packer\stub") { Remove-Item "$root\packer\stub" -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path "$root\dist") { Remove-Item "$root\dist" -Recurse -Force -ErrorAction SilentlyContinue }
}

# 版本信息由 Directory.Build.props 的 GenerateCustomVersion Target 自动注入。
# 此处仅显示用于日志。
$version = "1.0.0"
$gitHash = "dev"
try {
    $gitOut = git rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitOut) {
        $gitHash = $gitOut.Trim()
    }
} catch { }
$buildTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "==> 版本: $version  git: $gitHash  build: $buildTime" -ForegroundColor Cyan
Write-Host "    （版本号由 MSBuild Target 自动注入，此处仅显示）" -ForegroundColor DarkGray

# ---- 编译 stub_gui（GUI 模式，WinExe + WinForms + DPI aware manifest）----
Write-Host "==> 编译 stub_gui..." -ForegroundColor Cyan
dotnet build stub -c $config -p:Platform=AnyCPU
if ($LASTEXITCODE -ne 0) { throw "stub_gui build failed" }

# ---- 编译 stub_console（Console 模式，Exe + 控制台密码输入）----
Write-Host "==> 编译 stub_console..." -ForegroundColor Cyan
dotnet build stub.console -c $config -p:Platform=AnyCPU
if ($LASTEXITCODE -ne 0) { throw "stub_console build failed" }

# ---- 编译 stub_test（测试用，内置密码 test1234，跳过密码输入 UI）----
Write-Host "==> 编译 stub_test..." -ForegroundColor Cyan
dotnet build stub.test -c $config -p:Platform=AnyCPU
if ($LASTEXITCODE -ne 0) { throw "stub_test build failed" }

# ---- 编译 WinLock（in-place + reflective 加壳器，MSVC x64 + x86）----
# 产物由 packer/build.ps1 统一汇集到 packer/dist/，本脚本只负责拷贝整个 dist/ 目录过来
# 命名约定（packer/build.ps1 已规范化）：
#   builder_inplace.exe           - inplace 加壳器
#   stub_inplace_x64.bin          - inplace x64 stub 二进制
#   stub_inplace_x64.exe          - inplace x64 stub exe
#   stub_inplace_x86.bin          - inplace x86 stub 二进制
#   stub_inplace_x86.exe          - inplace x86 stub exe（builder 读 .reloc 用）
#   builder_reflective.exe        - reflective 加壳器
#   stub_reflective_x64.exe       - reflective x64 stub
#   stub_reflective_x86.exe       - reflective x86 stub
if (-not $SkipWinLock) {
    if (-not (Test-Path $winlockDir)) {
        Write-Host "==> 跳过 WinLock（找不到源码目录: $winlockDir）" -ForegroundColor Yellow
    } else {
        Write-Host "==> 编译 WinLock（调用 packer/build.ps1, MSVC x64 + x86）..." -ForegroundColor Cyan
        $winlockBuildArgs = @()
        if ($Release) { $winlockBuildArgs += "-Release" }
        if ($Clean)    { $winlockBuildArgs += "-Clean" }
        & "$winlockDir\build.ps1" @winlockBuildArgs
        if ($LASTEXITCODE -ne 0) { throw "WinLock build failed (packer/build.ps1)" }
        Write-Host "==> WinLock 编译完成" -ForegroundColor Green
    }
} else {
    Write-Host "==> 跳过 WinLock 编译（-SkipWinLock）" -ForegroundColor DarkGray
}

# ---- 汇集所有 stub 到 dotnet/packer/stub/（packer csproj 会拷到输出目录）----
$stubOutDir = "$root\packer\stub"
if (-not (Test-Path $stubOutDir)) { New-Item -ItemType Directory -Path $stubOutDir -Force | Out-Null }
Write-Host "==> 汇集 stub 到 $stubOutDir ..." -ForegroundColor Cyan

# 1. dotnet 三个 stub exe（tempfile 模式）
$dotnetStubs = @(
    @{ Src = "$root\stub\bin\$config\stub_gui.exe";     Dst = "stub_gui.exe" },
    @{ Src = "$root\stub.console\bin\$config\stub_console.exe"; Dst = "stub_console.exe" },
    @{ Src = "$root\stub.test\bin\$config\stub_test.exe";      Dst = "stub_test.exe" }
)
foreach ($s in $dotnetStubs) {
    if (Test-Path $s.Src) {
        Copy-Item $s.Src (Join-Path $stubOutDir $s.Dst) -Force
        Write-Host "    + $($s.Dst)" -ForegroundColor DarkGray
    } else {
        Write-Host "    [警告] 缺失: $($s.Src)" -ForegroundColor Yellow
    }
}

# 2. WinLock 产物（从 packer/dist/ 拷贝整个目录过来）
#    packer/build.ps1 已统一汇集到 dist/，本脚本不再分散拷贝
if (-not $SkipWinLock) {
    $winlockDistDir = "$winlockDir\dist"
    if (Test-Path $winlockDistDir) {
        # 拷贝 dist/ 下所有文件（builder_inplace.exe / stub_inplace_*.bin / stub_inplace_*.exe
        # / builder_reflective.exe / stub_reflective_*.exe）
        Get-ChildItem $winlockDistDir -File | ForEach-Object {
            Copy-Item $_.FullName (Join-Path $stubOutDir $_.Name) -Force
            Write-Host "    + $($_.Name)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "    [警告] packer/dist/ 不存在: $winlockDistDir（packer/build.ps1 失败？）" -ForegroundColor Yellow
    }
}

# 3. 生成 5 个 .meta.json 文件（packer 通过它们识别 stub 类型）
# 注意：stub_inplace_*.bin 不需要独立 meta.json，它们被 builder_inplace.exe.meta.json
# 的 components 字段引用，packer 通过 builder 的 meta 间接验证它们的存在。
$metaFiles = @(
    @{
        Path = "$stubOutDir\stub_gui.exe.meta.json"
        Json = @{
            name = "applocker-gui"
            kind = "tempfile"
            subsystem = "gui"
            description = "AppLocker GUI stub (tempfile mode, password dialog)"
            version = $version
        }
    },
    @{
        Path = "$stubOutDir\stub_console.exe.meta.json"
        Json = @{
            name = "applocker-console"
            kind = "tempfile"
            subsystem = "console"
            description = "AppLocker Console stub (tempfile mode, stdin password)"
            version = $version
        }
    },
    @{
        Path = "$stubOutDir\stub_test.exe.meta.json"
        Json = @{
            name = "applocker-test"
            kind = "tempfile"
            subsystem = "test"
            description = "AppLocker Test stub (hardcoded password test1234, for testing only)"
            version = $version
        }
    },
    @{
        Path = "$stubOutDir\builder_inplace.exe.meta.json"
        Json = @{
            name = "winlock"
            kind = "inplace-builder"
            subsystem = "gui"
            description = "WinLock in-place packer (GUI dialog, no plaintext tempfile, XTEA + SHA-256)"
            version = "2.0.0"
            # components 文件名与分发文件名一致（packer/dist/ 已统一新命名）
            # builder_inplace.exe 运行时 --stub-dir 指向此目录，按 stub_inplace_xXX.bin 搜索
            components = @{
                stub_x64 = "stub_inplace_x64.bin"
                stub_x86 = "stub_inplace_x86.bin"
            }
            supported_machines = @("amd64", "i386")
        }
    },
    @{
        Path = "$stubOutDir\builder_reflective.exe.meta.json"
        Json = @{
            name = "winlock-reflective"
            kind = "reflective-builder"
            subsystem = "gui"
            description = "WinLock reflective packer (memory load, supports x86/x64/.NET, plaintext v1)"
            version = "1.0.0"
            # components 文件名与分发文件名一致
            # builder_reflective.exe 运行时 --stub 指向此目录的 stub_reflective_xXX.exe
            components = @{
                stub_x64 = "stub_reflective_x64.exe"
                stub_x86 = "stub_reflective_x86.exe"
            }
            supported_machines = @("amd64", "i386")
        }
    }
)
foreach ($m in $metaFiles) {
    $m.Json | ConvertTo-Json -Depth 5 | Set-Content -Path $m.Path -Encoding UTF8
    Write-Host "    + $(Split-Path -Leaf $m.Path)" -ForegroundColor DarkGray
}

# ---- 编译 packer（会自动拷贝 stub/ 到输出目录 + Costura 嵌入依赖 DLL）----
Write-Host "==> 编译 packer（Costura 嵌入依赖 + 拷贝 stub/ 到输出）..." -ForegroundColor Cyan
# 显式指定 -p:Platform=AnyCPU：.NET 10 SDK 默认 Platform=x64，会把产物输出到 bin\x64\Release\，
# 而本脚本后面基于 bin\$(Configuration)\ 查找产物（与 .NET 6/7/8 行为一致）
dotnet build packer -c $config -p:Platform=AnyCPU
if ($LASTEXITCODE -ne 0) { throw "packer build failed" }

# ---- 验证 packer 输出目录的 stub/ 子目录 ----
$packerOutStub = "$root\packer\bin\$config\stub"
if (Test-Path $packerOutStub) {
    Write-Host "==> packer 输出 stub/ 目录内容:" -ForegroundColor Cyan
    Get-ChildItem $packerOutStub | Format-Table Name, Length
} else {
    Write-Host "==> [警告] packer 输出目录未生成 stub/ 子目录: $packerOutStub" -ForegroundColor Yellow
}

if ($Release) {
    # dist 放在 applocker 项目根目录（与 dotnet/、packer/ 平级），
    # 便于两个子项目的产物统一汇集；同时兼容旧的 dotnet/dist 路径（测试脚本会自动回退查找）
    $distDir = "$applockerRoot\dist"
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
    # 清空 dist 避免残留旧文件
    Get-ChildItem $distDir -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    # Costura 已将所有依赖 DLL 嵌入 exe，只需复制 WinAppLocker.exe + exe.config
    # exe.config 不能内嵌，WinForms 高 DPI 配置必须在 CLR 初始化前从外部 config 读取
    Copy-Item "$root\packer\bin\$config\WinAppLocker.exe" "$distDir\WinAppLocker.exe" -Force
    Copy-Item "$root\packer\bin\$config\WinAppLocker.exe.config" "$distDir\WinAppLocker.exe.config" -Force
    # 拷贝整个 stub/ 目录（WinLock 模式运行 packer 时需要）
    if (Test-Path "$root\packer\bin\$config\stub") {
        Copy-Item "$root\packer\bin\$config\stub" "$distDir\stub" -Recurse -Force
    }

    Write-Host "==> dist/ 准备就绪（packer exe + .config + stub/ 目录）" -ForegroundColor Green
    Write-Host "    路径: $distDir" -ForegroundColor DarkGray
    Get-ChildItem $distDir | Format-Table Name, Length
    if (Test-Path "$distDir\stub") {
        Write-Host "==> dist/stub/ 内容:" -ForegroundColor Cyan
        Get-ChildItem $distDir\stub | Format-Table Name, Length
    }
} else {
    Write-Host "==> packer/bin/$config/WinAppLocker.exe 准备就绪" -ForegroundColor Green
    Get-ChildItem "$root\packer\bin\$config" -Filter "WinAppLocker*" | Format-Table Name, Length
}

} finally {
    # 恢复调用方当前目录（Set-Location 会污染调用方 cwd，Push-Location + Pop-Location 配对）
    Pop-Location
}
