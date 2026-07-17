# WinAppLocker .NET 自动化测试脚本
# 使用 stub_test（内置密码 test1234），无需密码输入 UI，可全自动测试 GUI 和 CLI 程序。
#
# 用法：
#   .\test.ps1                 # 默认完整 round-trip 测试（含 hellogui）
#   .\test.ps1 -Samples "a.exe,b.exe"
#   .\test.ps1 -Info           # 对每个样本打包后用 --info 检查打包结果
#   .\test.ps1 -WaitGui <秒>   # GUI 程序等待 N 秒后检查进程再杀掉（默认 3）
param(
    [string]$Samples,
    [switch]$Info,
    [int]$WaitGui = 3
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$packer = "$root\dist\WinAppLocker.exe"
if (-not (Test-Path $packer)) {
    $packer = "$root\packer\bin\Release\WinAppLocker.exe"
    if (-not (Test-Path $packer)) {
        $packer = "$root\packer\bin\Debug\WinAppLocker.exe"
        if (-not (Test-Path $packer)) {
            throw "找不到 packer exe，请先运行 .\build.ps1 -Release"
        }
    }
}
Write-Host "==> packer: $packer" -ForegroundColor Cyan

# 显示 packer 版本
& $packer --version
Write-Host ""

$samplesDir = Resolve-Path "$root\..\tests\samples"

# 默认测试样本：CLI 程序可直接验证 stdout；GUI 程序验证进程启动
if ($Samples) {
    $sampleList = $Samples -split ','
} else {
    # CLI 程序（可通过 stdout 验证）
    $cliSamples = @('hellocli.exe', 'hellomingw.exe', 'helloucrt.exe', 'sha512sum.exe')
    # GUI 程序（通过进程存活验证）
    $guiSamples = @('hellogui.exe')
    $sampleList = $cliSamples + $guiSamples
}

$workDir = "$root\..\test_dotnet_work"
if (Test-Path $workDir) {
    Get-ChildItem $workDir -Filter "*.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
} else {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
}

# stub_test 内置密码 test1234，必须用相同密码打包
$password = "test1234"
$failCount = 0
$passCount = 0

function Is-GuiExe {
    param([string]$path)
    # 简单启发式：根据文件名判断（hellogui=GUI, hello*=CLI）
    return $path -match 'gui' -or $path -match 'DontSleep' -or $path -match 'notepad3'
}

foreach ($sample in $sampleList) {
    $src = Join-Path $samplesDir.Path $sample
    if (-not (Test-Path $src)) {
        Write-Host "[SKIP] $sample (not found)" -ForegroundColor Yellow
        continue
    }

    Write-Host "`n=== Test: $sample ===" -ForegroundColor Cyan

    # 复制原 exe 到 work 目录
    $workSrc = Join-Path $workDir $sample
    Copy-Item $src $workSrc -Force

    $lockedPath = Join-Path $workDir ($sample -replace '\.exe$', '_test_locked.exe')

    # 清理可能的残留临时文件
    Get-ChildItem $workDir -Filter "el_*.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

    # 1. 加密（使用 stub_test，密码 test1234）
    Write-Host "  [1] Pack with --stub Test..." -NoNewline
    $outLog = "$env:TEMP\wal_pack_out.txt"
    $errLog = "$env:TEMP\wal_pack_err.txt"
    $proc = Start-Process -FilePath $packer -ArgumentList "--pack","-i",$workSrc,"-o",$lockedPath,"-p",$password,"--stub","Test" -RedirectStandardOutput $outLog -RedirectStandardError $errLog -PassThru -Wait -NoNewWindow
    if ($proc.ExitCode -ne 0 -or -not (Test-Path $lockedPath)) {
        Write-Host " FAIL (pack exit=$($proc.ExitCode))" -ForegroundColor Red
        Get-Content $errLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
        $failCount++
        continue
    }
    $lockedSize = (Get-Item $lockedPath).Length
    Write-Host " OK ($lockedSize bytes)" -ForegroundColor Green

    # 1b. 可选：用 --info 检查打包结果
    if ($Info) {
        Write-Host "  [1b] --info 检查..." -NoNewline
        $infoOut = "$env:TEMP\wal_info_out.txt"
        $proc = Start-Process -FilePath $packer -ArgumentList "--info",$lockedPath -RedirectStandardOutput $infoOut -RedirectStandardError "$env:TEMP\wal_info_err.txt" -PassThru -Wait -NoNewWindow
        $infoContent = Get-Content $infoOut -Raw -ErrorAction SilentlyContinue
        if ($proc.ExitCode -eq 0 -and $infoContent -match "合法的 WinAppLocker") {
            Write-Host " OK (合法加密 EXE)" -ForegroundColor Green
        } else {
            Write-Host " FAIL (exit=$($proc.ExitCode))" -ForegroundColor Red
            $failCount++
            continue
        }
    }

    # 2. 运行（stub_test 自动用内置密码解密，无需输入）
    $isGui = Is-GuiExe $sample
    if ($isGui) {
        # GUI 程序：启动后等待几秒检查进程是否存活
        Write-Host "  [2] Run (GUI, wait ${WaitGui}s)..." -NoNewline
        $proc = Start-Process -FilePath $lockedPath -PassThru
        $stubPid = $proc.Id
        Start-Sleep -Seconds $WaitGui

        # 检查 stub 进程或 el_* 临时进程是否存活
        $stubAlive = Get-Process -Id $stubPid -ErrorAction SilentlyContinue
        $tempProcs = Get-Process -Name "el_*" -ErrorAction SilentlyContinue
        if ($stubAlive -or $tempProcs) {
            Write-Host " OK (进程运行中)" -ForegroundColor Green
            $passCount++
            # 清理：杀子进程让 stub 退出，再杀 stub
            if ($tempProcs) { $tempProcs | Stop-Process -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Milliseconds 500
            if (Get-Process -Id $stubPid -ErrorAction SilentlyContinue) {
                Stop-Process -Id $stubPid -Force -ErrorAction SilentlyContinue
            }
        } else {
            $exitCode = "?"
            try { $exitCode = $proc.ExitCode } catch {}
            Write-Host " FAIL (进程未存活, exit=$exitCode)" -ForegroundColor Red
            $failCount++
        }
    } else {
        # CLI 程序：等待完成并检查 stdout
        Write-Host "  [2] Run (CLI)..." -NoNewline
        $outFile = "$env:TEMP\wal_run_out.txt"
        $errFile = "$env:TEMP\wal_run_err.txt"
        $proc = Start-Process -FilePath $lockedPath -RedirectStandardOutput $outFile -RedirectStandardError $errFile -PassThru -Wait -NoNewWindow
        $exitCode = $proc.ExitCode
        $stdoutContent = Get-Content $outFile -Raw -ErrorAction SilentlyContinue
        if ($exitCode -eq 0) {
            $firstLine = ($stdoutContent -split "`n" | Where-Object { $_ -ne "" } | Select-Object -Last 1).Trim()
            Write-Host " OK (exit=0, output: '$firstLine')" -ForegroundColor Green
            $passCount++
        } else {
            Write-Host " FAIL (exit=$exitCode)" -ForegroundColor Red
            Get-Content $errFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
            $failCount++
        }
    }

    # 3. 验证临时文件清理
    Start-Sleep -Milliseconds 300
    $remnants = Get-ChildItem $workDir -Filter "el_*.exe" -ErrorAction SilentlyContinue
    if ($remnants) {
        Write-Host "  [!] WARN: temp files remaining: $($remnants.Name -join ', ')" -ForegroundColor Yellow
        $remnants | Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# 清理测试残留
Get-ChildItem $workDir -Filter "el_*.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "`n==> 完成: $passCount 通过, $failCount 失败" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Red' })
exit $failCount
