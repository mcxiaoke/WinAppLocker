# test_locked.ps1 - 自动打包并测试加密后的EXE
# 用法: .\test_locked.ps1 [-Target <exe路径>] [-Wait <秒>] [-Debug]
#
# 示例:
#   .\test_locked.ps1                                       # 测试所有内置样例
#   .\test_locked.ps1 -Target "C:\path\to\chrome.exe"      # 测试指定EXE
#   .\test_locked.ps1 -Debug                                # 启用调试日志
#   .\test_locked.ps1 -Wait 5                               # 等5秒后检查进程

param(
    [string]$Target = "",
    [int]$Wait = 5,
    [switch]$Debug
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$stubPath = "target\release\stub_test.exe"
$packerPath = "target\release\examples\pack_test.exe"
$tempDir = "temp"

if ($Debug) { $env:EXELOCK_DEBUG = "1" }
if (Test-Path "$env:TEMP\exelock_debug.log") { Remove-Item "$env:TEMP\exelock_debug.log" -Force }

function Build-All {
    Write-Host "[build] compiling stub_test..." -ForegroundColor Cyan
    $out = & cargo build --release -p exelock-stub --bin stub_test 2>&1
    $out | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "stub_test build failed" }

    Write-Host "[build] compiling pack_test..." -ForegroundColor Cyan
    $out = & cargo build --release -p exelock-packer --example pack_test 2>&1
    $out | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { throw "pack_test build failed" }
}

function Lock-Exe {
    param([string]$Src, [string]$Dst)
    $env:STUB_TEST_PATH = (Resolve-Path $stubPath).Path
    & $packerPath $Src $Dst 2>&1 | ForEach-Object { Write-Host "  [pack] $_" }
    if ($LASTEXITCODE -ne 0) { throw "pack failed for $Src" }
}

function Test-Locked {
    param(
        [string]$LockedExe,
        [string]$WorkDir,
        [string]$ProcName,
        [int]$WaitSec,
        [string[]]$ExtraArgs = @()
    )

    Write-Host "[test] launching $LockedExe (wait=${WaitSec}s, workdir=$WorkDir)..." -ForegroundColor Yellow

    Get-Process $ProcName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    # 清理残留的el_临时进程
    Get-Process -Name "el_*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    $startArgs = @{
        FilePath = $LockedExe
        WorkingDirectory = $WorkDir
        PassThru = $true
    }
    if ($ExtraArgs -and $ExtraArgs.Count -gt 0) {
        $startArgs['ArgumentList'] = $ExtraArgs
    }
    $p = Start-Process @startArgs
    $stubPid = $p.Id

    Start-Sleep -Seconds $WaitSec

    # 检测子进程：stub进程还在运行，说明子进程还活着
    $stubAlive = Get-Process -Id $stubPid -ErrorAction SilentlyContinue
    # 也检查是否有el_开头的临时进程
    $tempProcs = Get-Process -Name "el_*" -ErrorAction SilentlyContinue
    # 也检查目标进程名（万一它加载后改名了）
    $targetProcs = Get-Process -Name $ProcName -ErrorAction SilentlyContinue

    if ($stubAlive -or $tempProcs -or $targetProcs) {
        $desc = @()
        if ($stubAlive) { $desc += "stub(pid=$stubPid) alive" }
        if ($tempProcs) { $desc += "el_* procs: $(($tempProcs | ForEach-Object { $_.Id }) -join ',')" }
        if ($targetProcs) { $desc += "$ProcName procs: $(($targetProcs | ForEach-Object { $_.Id }) -join ',')" }
        Write-Host "[PASS] $ProcName running ($($desc -join '; ')), killing..." -ForegroundColor Green
        # 先杀子进程（el_* 和 target），让 stub 的 WaitForSingleObject 返回，
        # stub 会自动清理临时文件后退出。给 stub 1 秒时间完成清理。
        if ($tempProcs) { $tempProcs | Stop-Process -Force }
        if ($targetProcs) { $targetProcs | Stop-Process -Force }
        Start-Sleep -Milliseconds 1000
        # 如果 stub 还活着（清理卡住），再强制杀
        $stubStillAlive = Get-Process -Id $stubPid -ErrorAction SilentlyContinue
        if ($stubStillAlive) {
            Write-Host "  stub still alive after 1s, force killing..." -ForegroundColor DarkYellow
            Stop-Process -Id $stubPid -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 300
        }
        return $true
    } else {
        $exitCode = "?"
        try { $exitCode = $p.ExitCode } catch {}
        Write-Host "[FAIL] $ProcName not running after ${WaitSec}s (stub pid=$stubPid exit=$exitCode)" -ForegroundColor Red
        if (Test-Path "$env:TEMP\exelock_debug.log") {
            Write-Host "--- debug log (last 20 lines) ---" -ForegroundColor DarkGray
            Get-Content "$env:TEMP\exelock_debug.log" -Tail 20
        }
        return $false
    }
}

Build-All

if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory $tempDir | Out-Null }

$pass = 0
$fail = 0
$total = 0

# 内置样例测试
$samples = @(
    @{ src = "tests\samples\hellogui.exe";   dst = "$tempDir\hellogui_locked.exe";    name = "hellogui";   wd = $tempDir },
    @{ src = "tests\samples\DontSleep.exe";  dst = "$tempDir\DontSleep_locked.exe";   name = "DontSleep";  wd = $tempDir },
    @{ src = "tests\samples\notepad3.exe";   dst = "$tempDir\notepad3_locked.exe";    name = "notepad3";   wd = $tempDir }
)

foreach ($s in $samples) {
    if (-not (Test-Path $s.src)) { Write-Host "[skip] $($s.src) not found"; continue }
    $total++
    Write-Host "`n=== Test: $($s.name) ===" -ForegroundColor Cyan
    Lock-Exe $s.src $s.dst
    if (Test-Locked -LockedExe $s.dst -WorkDir $s.wd -ProcName $s.name -WaitSec $Wait) {
        $pass++
    } else {
        $fail++
    }
}

# 指定目标测试
if ($Target) {
    $total++
    $dst = "$tempDir\target_locked.exe"
    $name = [System.IO.Path]::GetFileNameWithoutExtension($Target)
    $wd = Split-Path -Parent (Resolve-Path $Target)
    Write-Host "`n=== Test: $name ($Target) ===" -ForegroundColor Cyan
    Lock-Exe $Target $dst
    if (Test-Locked -LockedExe $dst -WorkDir $wd -ProcName $name -WaitSec $Wait -ExtraArgs @("--no-first-run","--disable-features=RendererCodeIntegrity")) {
        $pass++
    } else {
        $fail++
    }
}

# 清理临时文件
Remove-Item "$tempDir\el_*.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "$tempDir\*_locked.exe" -Force -ErrorAction SilentlyContinue

Write-Host "`n========================================"
Write-Host "Results: $pass/$total passed" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
if ($Debug -and (Test-Path "$env:TEMP\exelock_debug.log")) {
    Write-Host "Debug log: $env:TEMP\exelock_debug.log" -ForegroundColor DarkGray
}
