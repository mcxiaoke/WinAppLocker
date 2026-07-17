# 重新编译 stub + packer（stub 通过 include_bytes! 嵌入 packer）。
#
# 顺序很重要：必须先编译 stub，packer 的 build.rs 才能把 stub 拷到 OUT_DIR。
#
# 用法:
#   .\rebuild.ps1           # Debug 构建（开发调试）
#   .\rebuild.ps1 -Release  # Release 构建（发布，输出到 dist/）

param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$targetDir = if ($Release) { "release" } else { "debug" }

# 1. 编译 stub（stub_gui.exe / stub_console.exe / stub_test.exe）
$stubArgs = @("build", "-p", "exelock-stub")
if ($Release) { $stubArgs += "--release" }

Write-Host "==> cargo $($stubArgs -join ' ')" -ForegroundColor Cyan
& cargo @stubArgs
if ($LASTEXITCODE -ne 0) { throw "stub build failed" }

# 2. 编译 packer（build.rs 会自动把 stub 从 target/<profile>/ 拷到 OUT_DIR）
$packerArgs = @("build", "-p", "exelock-packer")
if ($Release) { $packerArgs += "--release" }

Write-Host "==> cargo $($packerArgs -join ' ')" -ForegroundColor Cyan
& cargo @packerArgs
if ($LASTEXITCODE -ne 0) { throw "packer build failed" }

$stubSrc = "$root\target\$targetDir"

if ($Release) {
    # 发布：单一 WinAppLocker.exe（stub 已嵌入）
    Write-Host "==> assembling dist/" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path "$root\dist" -Force | Out-Null
    Copy-Item "$stubSrc\WinAppLocker.exe" "$root\dist\WinAppLocker.exe" -Force

    Write-Host "==> done. dist contents:" -ForegroundColor Green
    Get-ChildItem "$root\dist" -Recurse | Select-Object @{N='Path';E={$_.FullName.Replace("$root\dist\","")}}, @{N='SizeKB';E={[math]::Round($_.Length/1KB,0)}}
} else {
    Write-Host "==> done. target\$targetDir\WinAppLocker.exe" -ForegroundColor Green
}
