# WinAppLocker .NET 构建脚本
# 用法：
#   .\build.ps1              # Debug 构建（不拷到 dist）
#   .\build.ps1 -Release     # Release 构建，输出 dist/WinAppLocker.exe（单文件）
#   .\build.ps1 -Clean       # 清理后构建
param(
    [switch]$Release,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

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
dotnet build stub -c $config
if ($LASTEXITCODE -ne 0) { throw "stub_gui build failed" }

# ---- 编译 stub_console（Console 模式，Exe + 控制台密码输入）----
Write-Host "==> 编译 stub_console..." -ForegroundColor Cyan
dotnet build stub.console -c $config
if ($LASTEXITCODE -ne 0) { throw "stub_console build failed" }

# ---- 编译 stub_test（测试用，内置密码 test1234，跳过密码输入 UI）----
Write-Host "==> 编译 stub_test..." -ForegroundColor Cyan
dotnet build stub.test -c $config
if ($LASTEXITCODE -ne 0) { throw "stub_test build failed" }

# ---- 编译 packer（会自动嵌入 stub_gui/console/test + Costura 嵌入依赖 DLL）----
Write-Host "==> 编译 packer（Costura 嵌入依赖）..." -ForegroundColor Cyan
dotnet build packer -c $config
if ($LASTEXITCODE -ne 0) { throw "packer build failed" }

if ($Release) {
    New-Item -ItemType Directory -Path "$root\dist" -Force | Out-Null
    # 清空 dist 避免残留旧文件
    Get-ChildItem "$root\dist" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    # Costura 已将所有依赖 DLL 嵌入 exe，只需复制 WinAppLocker.exe + exe.config
    # exe.config 不能内嵌，WinForms 高 DPI 配置必须在 CLR 初始化前从外部 config 读取
    Copy-Item "$root\packer\bin\$config\WinAppLocker.exe" "$root\dist\WinAppLocker.exe" -Force
    Copy-Item "$root\packer\bin\$config\WinAppLocker.exe.config" "$root\dist\WinAppLocker.exe.config" -Force

    Write-Host "==> dist/WinAppLocker.exe 准备就绪（单文件 exe + .config）" -ForegroundColor Green
    Get-ChildItem "$root\dist" | Format-Table Name, Length
} else {
    Write-Host "==> packer/bin/$config/WinAppLocker.exe 准备就绪" -ForegroundColor Green
    Get-ChildItem "$root\packer\bin\$config" -Filter "WinAppLocker*" | Format-Table Name, Length
}
