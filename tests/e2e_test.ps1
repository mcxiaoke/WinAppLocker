# e2e_test.ps1 - winlock 端到端测试
# 对每个样本：加壳 -> 启动 -> 输入密码 -> 验证程序正常运行
# 用法：powershell -File e2e_test.ps1

$ErrorActionPreference = "Stop"
$root = "f:\Temp\pe\winlock"
$samples = "f:\Temp\pe\samples"
$work = "$root\test"
$builder = "$root\builder\builder.exe"
$password = "test123"

# 创建工作目录
if (-not (Test-Path $work)) { New-Item -ItemType Directory -Path $work | Out-Null }

# 测试结果表
$results = @()

function Test-OneSample {
    param([string]$sampleName, [string]$expectedOutput, [int]$timeoutSec = 15)

    $srcExe = Join-Path $samples $sampleName
    $lockedExe = Join-Path $work ($sampleName -replace '\.exe$', '_locked.exe')

    Write-Host ""
    Write-Host ("===== {0} =====" -f $sampleName) -ForegroundColor Cyan

    # 1. 加壳
    Write-Host "[1/4] Packing..."
    $env:Path = "C:\Home\Develop\w64devkit\bin;$env:Path"
    Push-Location $root
    try {
        & $builder $srcExe $lockedExe $password 2>&1 | Select-String -Pattern "\[(\+|-|\*)\]" | ForEach-Object { Write-Host "     $_" }
    } finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $lockedExe)) {
        Write-Host "[FAIL] pack failed" -ForegroundColor Red
        return @{ sample=$sampleName; result="PACK_FAIL"; detail="builder exit $LASTEXITCODE" }
    }
    Write-Host "[OK] packed -> $lockedExe" -ForegroundColor Green

    # 2. 启动加壳程序
    Write-Host "[2/4] Launching..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $lockedExe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    Write-Host ("     PID={0}" -f $proc.Id)

    # 3. 输入密码
    Write-Host "[3/4] Sending password..."
    Start-Sleep -Milliseconds 500
    & powershell -ExecutionPolicy Bypass -File "$root\tools\input_password.ps1" -Password $password -Timeout 8 2>&1 | ForEach-Object {
        Write-Host "     $_"
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[FAIL] password input failed (exit $LASTEXITCODE)" -ForegroundColor Red
        try { $proc.Kill() } catch {}
        return @{ sample=$sampleName; result="PWD_FAIL"; detail="input_password exit $LASTEXITCODE" }
    }
    Write-Host "[OK] password sent" -ForegroundColor Green

    # 4. 等待程序退出，验证输出
    Write-Host "[4/4] Waiting for output (timeout ${timeoutSec}s)..."
    $ exited = $proc.WaitForExit($timeoutSec * 1000)
    if (-not $exited) {
        Write-Host "[FAIL] process did not exit within ${timeoutSec}s" -ForegroundColor Red
        try { $proc.Kill() } catch {}
        return @{ sample=$sampleName; result="TIMEOUT"; detail="did not exit" }
    }

    $stdout = $proc.StandardOutput.ReadToEnd()
    $exitCode = $proc.ExitCode
    Write-Host ("     exit code: {0}" -f $exitCode)
    Write-Host ("     stdout:    '{0}'" -f $stdout.Trim())

    if ($expectedOutput -and $stdout -match $expectedOutput) {
        Write-Host "[PASS] output matches expected" -ForegroundColor Green
        return @{ sample=$sampleName; result="PASS"; detail="exit=$exitCode out='$($stdout.Trim() -replace "`r?`n", "|")'" }
    } elseif (-not $expectedOutput -and $exitCode -eq 0) {
        Write-Host "[PASS] exit code 0 (no output check)" -ForegroundColor Green
        return @{ sample=$sampleName; result="PASS"; detail="exit=0" }
    } else {
        Write-Host "[FAIL] output mismatch" -ForegroundColor Red
        return @{ sample=$sampleName; result="OUT_FAIL"; detail="exit=$exitCode out='$($stdout.Trim() -replace "`r?`n", "|")'" }
    }
}

# --- 测试每个 CLI 样本 ---
# hellocli: "Hello World!"
# hellomingw: "Hello, MinGW!"
# helloucrt: "Hello, UCRT!"
$results += Test-OneSample "hellocli.exe" "Hello World" 15
$results += Test-OneSample "hellomingw.exe" "Hello, MinGW" 15
$results += Test-OneSample "helloucrt.exe" "Hello, UCRT" 15

# --- 汇总 ---
Write-Host ""
Write-Host "================ SUMMARY ================" -ForegroundColor Yellow
$results | ForEach-Object {
    $color = if ($_.result -eq "PASS") { "Green" } else { "Red" }
    Write-Host ("{0,-20} {1,-12} {2}" -f $_.sample, $_.result, $_.detail) -ForegroundColor $color
}

$pass = ($results | Where-Object { $_.result -eq "PASS" }).Count
$fail = ($results | Where-Object { $_.result -ne "PASS" }).Count
Write-Host ""
Write-Host ("TOTAL: {0} pass / {1} fail / {2} total" -f $pass, $fail, $results.Count) -ForegroundColor $(if ($fail -eq 0) {"Green"} else {"Red"})
exit $fail
