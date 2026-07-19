<#
.SYNOPSIS
  批量测试反射式加壳：对每个 x64 样本加壳并运行验证。
.DESCRIPTION
  阶段 2 验证脚本：测试 reloc 补全后各样本的兼容性。
  只测 x64 样本（阶段 2 loader 仍只支持 x64）。
  每个样本：加壳 -> 启动 -> 等待 -> 检查窗口/输出 -> 清理。
#>

param(
    [int]$WaitSec = 4
)

$ErrorActionPreference = "Continue"

$Builder = "C:\Home\Projects\applocker\packer\builder\builder_reflective.exe"
$Stub    = "C:\Home\Projects\applocker\packer\reflective\loader_x64.exe"
$OutDir  = "C:\Home\Projects\applocker\packer\test\reflective_batch"
$SampleDir = "C:\Home\Projects\applocker\temp\samples"

# 只测 x64 样本
$Samples = @(
    @{ Name = "Notepad4.exe";     Type = "GUI"; NeedWindow = $true;  WindowMatch = "Notepad4" },
    @{ Name = "DontSleep.exe";    Type = "GUI"; NeedWindow = $true;  WindowMatch = "DontSleep" },
    @{ Name = "helloguix64.exe";  Type = "GUI"; NeedWindow = $true;  WindowMatch = "HelloGUI" },
    @{ Name = "hellocli.exe";     Type = "CUI"; NeedOutput = $true;  OutputMatch = "Hello" },
    @{ Name = "hellomingw.exe";   Type = "CUI"; NeedOutput = $true;  OutputMatch = "Hello" },
    @{ Name = "helloucrt.exe";    Type = "CUI"; NeedOutput = $true;  OutputMatch = "Hello" },
    @{ Name = "ddccli.exe";       Type = "CUI"; NeedOutput = $false },  # 可能无输出，只要不 crash 就行
    @{ Name = "sha256sum.exe";    Type = "CUI"; NeedOutput = $false }   # 无参数会报 usage
)

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# 清理旧进程
Get-Process -Name "Notepad4*","DontSleep*","hellogui*","hellocli*","hellomingw*","helloucrt*","ddccli*","sha256sum*" -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

$results = @()

foreach ($s in $Samples) {
    $inPath = Join-Path $SampleDir $s.Name
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($s.Name)
    $outPath = Join-Path $OutDir ($baseName + '_reflective.exe')
    $logPath = $outPath -replace '\.exe$', '_loader.log'

    Write-Host ""
    Write-Host "=== Testing: $($s.Name) ===" -ForegroundColor Cyan

    # 检查样本
    if (-not (Test-Path $inPath)) {
        Write-Host "  [SKIP] Sample not found: $inPath" -ForegroundColor Yellow
        $results += @{ Name = $s.Name; Result = "SKIP"; Reason = "sample not found" }
        continue
    }

    # 加壳
    Write-Host "  [*] Packing..."
    $packOut = & $Builder $inPath $outPath --stub $Stub 2>&1
    if (-not (Test-Path $outPath)) {
        Write-Host "  [FAIL] Pack failed" -ForegroundColor Red
        $results += @{ Name = $s.Name; Result = "FAIL"; Reason = "pack failed" }
        continue
    }
    Write-Host "  [+] Packed OK"

    # 运行
    Remove-Item $logPath -ErrorAction SilentlyContinue
    Write-Host "  [*] Running (wait $WaitSec sec)..."

    if ($s.Type -eq "GUI") {
        # GUI 程序：启动后检查窗口
        $proc = Start-Process -FilePath $outPath -PassThru -WindowStyle Normal
        Start-Sleep -Seconds $WaitSec

        $alive = -not $proc.HasExited
        $windowFound = $false
        if ($s.WindowMatch) {
            $winProcs = Get-Process | Where-Object {
                $_.MainWindowTitle -match $s.WindowMatch -or $_.ProcessName -match $s.WindowMatch
            }
            $windowFound = $null -ne $winProcs
        }

        # 清理
        if (-not $proc.HasExited) { taskkill /F /T /PID $proc.Id 2>&1 | Out-Null }
        Get-Process | Where-Object { $_.ProcessName -match $s.WindowMatch } |
            Stop-Process -Force -ErrorAction SilentlyContinue

        if (-not $alive) {
            Write-Host "  [FAIL] Process exited early (exit=$($proc.ExitCode))" -ForegroundColor Red
            $results += @{ Name = $s.Name; Result = "FAIL"; Reason = "early exit code=$($proc.ExitCode)" }
        } elseif ($s.NeedWindow -and -not $windowFound) {
            Write-Host "  [WARN] Process alive but no window matching '$($s.WindowMatch)'" -ForegroundColor Yellow
            $results += @{ Name = $s.Name; Result = "WARN"; Reason = "no window" }
        } else {
            Write-Host "  [PASS] Process alive, window found" -ForegroundColor Green
            $results += @{ Name = $s.Name; Result = "PASS"; Reason = "" }
        }
    } else {
        # CUI 程序：捕获 stdout
        $proc = Start-Process -FilePath $outPath -PassThru -NoNewWindow -RedirectStandardOutput "$outPath.stdout" -RedirectStandardError "$outPath.stderr"
        Start-Sleep -Seconds $WaitSec

        if (-not $proc.HasExited) {
            taskkill /F /T /PID $proc.Id 2>&1 | Out-Null
        }

        $stdout = Get-Content "$outPath.stdout" -ErrorAction SilentlyContinue | Out-String
        $stderr = Get-Content "$outPath.stderr" -ErrorAction SilentlyContinue | Out-String

        if ($s.NeedOutput -and $stdout -notmatch $s.OutputMatch) {
            Write-Host "  [FAIL] No expected output '$($s.OutputMatch)'" -ForegroundColor Red
            Write-Host "  stdout: $stdout" -ForegroundColor Gray
            Write-Host "  stderr: $stderr" -ForegroundColor Gray
            $results += @{ Name = $s.Name; Result = "FAIL"; Reason = "no output" }
        } elseif ($s.NeedOutput) {
            Write-Host "  [PASS] Output matched '$($s.OutputMatch)'" -ForegroundColor Green
            $results += @{ Name = $s.Name; Result = "PASS"; Reason = "" }
        } else {
            # 不要求特定输出，只要加载流程没 crash
            $logContent = Get-Content $logPath -ErrorAction SilentlyContinue | Out-String
            if ($logContent -match "FATAL" -or $logContent -match "failed") {
                Write-Host "  [WARN] Log shows errors" -ForegroundColor Yellow
                $results += @{ Name = $s.Name; Result = "WARN"; Reason = "log errors" }
            } else {
                Write-Host "  [PASS] Loaded without fatal errors" -ForegroundColor Green
                $results += @{ Name = $s.Name; Result = "PASS"; Reason = "" }
            }
        }
        Remove-Item "$outPath.stdout", "$outPath.stderr" -ErrorAction SilentlyContinue
    }

    # 检查日志关键行
    if (Test-Path $logPath) {
        $logLines = Get-Content $logPath -ErrorAction SilentlyContinue
        foreach ($ln in $logLines) {
            if ($ln -match "FATAL") {
                Write-Host "  [LOG] FATAL: $ln" -ForegroundColor Red
            }
            if ($ln -match "jump_to_oep") {
                Write-Host "  [LOG] OEP reached: $ln" -ForegroundColor Green
            }
        }
    }
}

# 汇总
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "=== Batch Test Summary ===" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
$results | ForEach-Object {
    $color = switch ($_.Result) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        "SKIP" { "Gray" }
        default { "White" }
    }
    $line = "  {0,-20} {1,-6} {2}" -f $_.Name, $_.Result, $_.Reason
    Write-Host $line -ForegroundColor $color
}

$pass = ($results | Where-Object { $_.Result -eq "PASS" }).Count
$warn = ($results | Where-Object { $_.Result -eq "WARN" }).Count
$fail = ($results | Where-Object { $_.Result -eq "FAIL" }).Count
$skip = ($results | Where-Object { $_.Result -eq "SKIP" }).Count
Write-Host ""
Write-Host "Total: $($results.Count)  PASS: $pass  WARN: $warn  FAIL: $fail  SKIP: $skip"
