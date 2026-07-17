# 监视 packer 源码变化，自动重新编译并启动 WinAppLocker。
#
# 用法:
#   .\watch.ps1              # Debug 模式（默认）
#   .\watch.ps1 -Release     # Release 模式
#   .\watch.ps1 -Clear       # 每次重启前清屏
#
# 首次运行前请先执行一次 .\rebuild.ps1 以保证 stub 已编译。
# 修改 stub 不会触发重编（只监视 packer 源码）；改 stub 请用 .\rebuild.ps1。

param(
    [switch]$Release,
    [switch]$Clear
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$profile_flag = if ($Release) { "--release" } else { "" }
$profile_name = if ($Release) { "release" } else { "debug" }

# 检查 stub 是否已构建（include_bytes! 需要 target/<profile>/stub_gui.exe 存在）
$stubGui = "$root\target\$profile_name\stub_gui.exe"
$stubConsole = "$root\target\$profile_name\stub_console.exe"
if (-not (Test-Path $stubGui) -or -not (Test-Path $stubConsole)) {
    Write-Host "[watch] stub 未构建，先执行 .\rebuild.ps1 初始化..." -ForegroundColor Yellow
    & .\rebuild.ps1
    if ($LASTEXITCODE -ne 0) { throw "rebuild failed" }
}

# 构造 cargo run 命令
$cmd = @("run", "-p", "exelock-packer", "--bin", "WinAppLocker")
if ($Release) { $cmd += "--release" }

# 构造 cargo watch 参数
$watchArgs = @("-x", ($cmd -join " "))

# 只监视 packer 源码 + assets，避免 stub 改动触发不必要的重编
$watchArgs += @("-w", "packer\src", "-w", "packer\assets", "-w", "packer\Cargo.toml")

if ($Clear) {
    $watchArgs += @("-C")
}

# 忽略 target 目录（cargo watch 默认会忽略，但显式声明更保险）
$watchArgs += @("-i", "target")

Write-Host "[watch] starting cargo watch..." -ForegroundColor Cyan
Write-Host "[watch] command: cargo watch $($watchArgs -join ' ')" -ForegroundColor DarkGray
Write-Host "[watch] 修改 packer\src\ 下的文件会自动重启程序" -ForegroundColor DarkGray
Write-Host "[watch] 按 Ctrl+C 退出 watch" -ForegroundColor DarkGray
Write-Host ""

& cargo watch @watchArgs
