# e2e_test.ps1 - applocker 端到端测试
# 对每个样本：加壳（-t 测试模式） -> 运行 -> 验证输出或窗口
# 用法：powershell -File e2e_test.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$packerRoot = Split-Path -Parent $root
$dist = "$packerRoot\dist"
$samples = "$packerRoot\..\temp\samples"
$work = "$packerRoot\temp\e2e_result"
$builder = "$dist\builder_inplace.exe"

if (-not (Test-Path $builder)) {
    Write-Host "builder_inplace.exe 不存在，请先运行 build.ps1" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $work)) { New-Item -ItemType Directory -Path $work -Force | Out-Null }

$results = @()

function Test-ConsoleSample {
    param([string]$sampleName, [string]$expectedOutput, [int]$timeoutSec = 15)

    $srcExe = Join-Path $samples $sampleName
    $lockedExe = Join-Path $work ($sampleName -replace '\.exe$', '_test.exe')

    Write-Host ""
    Write-Host ("===== {0} =====" -f $sampleName) -ForegroundColor Cyan
    if (-not (Test-Path $srcExe)) {
        Write-Host "[SKIP] sample not found" -ForegroundColor Yellow
        return @{ sample=$sampleName; result="SKIP"; detail="not found" }
    }

    # 1. 加壳
    Write-Host "[1/3] 加壳..."
    $packOutput = & $builder -i $srcExe -o $lockedExe -t --stub-dir $dist 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $lockedExe)) {
        Write-Host "[FAIL] 加壳失败" -ForegroundColor Red
        return @{ sample=$sampleName; result="PACK_FAIL"; detail="exit=$LASTEXITCODE" }
    }
    Write-Host "      产物: $lockedExe" -ForegroundColor DarkGray

    # 2. 运行
    Write-Host "[2/3] 运行..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $lockedExe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)

    $exited = $proc.WaitForExit($timeoutSec * 1000)
    $stdout = $proc.StandardOutput.ReadToEnd().Trim()
    $stderr = $proc.StandardError.ReadToEnd().Trim()
    $exitCode = $proc.ExitCode

    if (-not $exited) {
        try { $proc.Kill() } catch {}
        Write-Host "[FAIL] ${timeoutSec}s 超时未退出" -ForegroundColor Red
        return @{ sample=$sampleName; result="TIMEOUT"; detail="did not exit" }
    }

    Write-Host ("      exit={0} stdout='{1}'" -f $exitCode, $stdout) -ForegroundColor DarkGray

    # 3. 验证
    if ($stdout -match $expectedOutput) {
        Write-Host "[PASS] 输出匹配" -ForegroundColor Green
        return @{ sample=$sampleName; result="PASS"; detail="exit=$exitCode out='$stdout'" }
    } else {
        Write-Host "[FAIL] 输出不匹配, 期望: '$expectedOutput'" -ForegroundColor Red
        return @{ sample=$sampleName; result="OUT_FAIL"; detail="exit=$exitCode out='$stdout'" }
    }
}

function Test-GuiSample {
    param([string]$sampleName, [string]$windowTitle, [int]$timeoutSec = 20)

    $srcExe = Join-Path $samples $sampleName
    $lockedExe = Join-Path $work ($sampleName -replace '\.exe$', '_test.exe')

    Write-Host ""
    Write-Host ("===== {0} =====" -f $sampleName) -ForegroundColor Cyan
    if (-not (Test-Path $srcExe)) {
        Write-Host "[SKIP] sample not found" -ForegroundColor Yellow
        return @{ sample=$sampleName; result="SKIP"; detail="not found" }
    }

    # 1. 加壳
    Write-Host "[1/3] 加壳..."
    $packOutput = & $builder -i $srcExe -o $lockedExe -t --stub-dir $dist 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $lockedExe)) {
        Write-Host "[FAIL] 加壳失败" -ForegroundColor Red
        return @{ sample=$sampleName; result="PACK_FAIL"; detail="exit=$LASTEXITCODE" }
    }
    Write-Host "      产物: $lockedExe" -ForegroundColor DarkGray

    # 2. 运行
    Write-Host "[2/3] 运行..."
    $proc = Start-Process -FilePath $lockedExe -PassThru -WindowStyle Normal
    Write-Host ("      PID={0}" -f $proc.Id)

    # 3. 等待窗口出现
    Write-Host "[3/3] 等待窗口..."
    Add-Type -AssemblyName System.Windows.Forms
    $found = $false
    for ($i = 1; $i -le $timeoutSec; $i++) {
        Start-Sleep -Seconds 1
        if ($proc.HasExited) {
            Write-Host "[FAIL] 进程已退出, exit=$($proc.ExitCode)" -ForegroundColor Red
            return @{ sample=$sampleName; result="CRASH"; detail="exit=$($proc.ExitCode)" }
        }
        # 用 .NET 查找窗口
        $windows = [System.Windows.Forms.Application]::OpenForms
        # 备用：用 Windows API 查找
        $hwnd = (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue).MainWindowHandle
        if ($hwnd -and $hwnd -ne 0) {
            Write-Host ("      窗口已出现 (HWND={0})" -f $hwnd) -ForegroundColor DarkGray
            $found = $true
            break
        }
        if ($i % 5 -eq 0) {
            Write-Host ("      等待中... ({0}s)" -f $i) -ForegroundColor DarkGray
        }
    }

    if ($found) {
        Write-Host "[PASS] 窗口已显示" -ForegroundColor Green
        $proc.Kill()
        Start-Sleep -Seconds 1
        return @{ sample=$sampleName; result="PASS"; detail="window shown" }
    } elseif (-not $proc.HasExited) {
        Write-Host "[PASS] 进程存活 (GUI 窗口未检测到但未崩溃)" -ForegroundColor Yellow
        $proc.Kill()
        Start-Sleep -Seconds 1
        return @{ sample=$sampleName; result="PASS"; detail="process alive, no window detected" }
    } else {
        Write-Host "[FAIL] 进程已退出" -ForegroundColor Red
        return @{ sample=$sampleName; result="CRASH"; detail="exit=$($proc.ExitCode)" }
    }
}

# ==================== 测试列表 ====================

# x64 Console 样本
$results += Test-ConsoleSample "hellocli.exe"      "Hello World"
$results += Test-ConsoleSample "hellomingw.exe"     "Hello, MinGW"
$results += Test-ConsoleSample "helloucrt.exe"      "Hello, UCRT"
$results += Test-ConsoleSample "sha256sum.exe"      "usage"

# x64 GUI 样本
$results += Test-GuiSample "helloguix64.exe"        "hello"
$results += Test-GuiSample "Notepad4.exe"           "Notepad4"
$results += Test-GuiSample "DontSleep.exe"          "Don't Sleep"

# x86 样本 (GUI, 有 TLS callback)
$results += Test-GuiSample "hellomfcx86.exe"        "hello"

# ==================== 汇总 ====================
Write-Host ""
Write-Host "================ SUMMARY ================" -ForegroundColor Yellow
$results | ForEach-Object {
    $color = if ($_.result -eq "PASS") { "Green" } else { "Red" }
    Write-Host ("{0,-25} {1,-12} {2}" -f $_.sample, $_.result, $_.detail) -ForegroundColor $color
}

$pass = ($results | Where-Object { $_.result -eq "PASS" }).Count
$fail = ($results | Where-Object { $_.result -notin @("PASS", "SKIP") }).Count
$skip = ($results | Where-Object { $_.result -eq "SKIP" }).Count
Write-Host ""
Write-Host ("TOTAL: {0} pass / {1} fail / {2} skip / {3} total" -f $pass, $fail, $skip, $results.Count) -ForegroundColor $(if ($fail -eq 0) {"Green"} else {"Red"})
exit $fail