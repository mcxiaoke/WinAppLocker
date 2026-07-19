# WinAppLocker .NET 自动化测试脚本
# 支持两种模式：
#   1. 临时文件模式（默认）：用 stub_test（内置密码 test1234）做 round-trip 测试
#   2. WinLock in-place 模式（-WinLock）：用 winlock_builder.exe -t 测试模式，
#      密码硬编码为 "test123"，stub 跳过弹框直接解密 .text 节
#
# 用法：
#   .\tests\auto_test.ps1                 # 默认：所有样本走临时文件模式
#   .\tests\auto_test.ps1 -WinLock        # 所有样本走 WinLock 模式（不支持 .NET / Console / DLL）
#   .\tests\auto_test.ps1 -Samples "a.exe,b.exe"
#   .\tests\auto_test.ps1 -Info           # 对每个样本打包后用 --info 检查打包结果
#   .\tests\auto_test.ps1 -WaitGui <秒>   # GUI 程序等待 N 秒后检查进程再杀掉（默认 3）
param(
    [string]$Samples,
    [switch]$WinLock,
    [switch]$Info,
    [int]$WaitGui = 3
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Write-Host "==> Root: $root" -ForegroundColor Green
Write-Host "==> Mode: $(if ($WinLock) { 'WinLock (in-place)' } else { 'Tempfile (stub_test)' })" -ForegroundColor Cyan

# Push-Location 而非 Set-Location：脚本退出（正常/异常）时用 finally 恢复调用方 cwd
Push-Location $root
try {

$packer = "$root\dist\WinAppLocker.exe"
if (-not (Test-Path $packer)) {
    # build.ps1 -Release 已把 dist 移到 applocker 根目录（与 dotnet/ 平级）
    $packer = "$root\..\dist\WinAppLocker.exe"
    if (-not (Test-Path $packer)) {
        $packer = "$root\packer\bin\Release\WinAppLocker.exe"
        if (-not (Test-Path $packer)) {
            $packer = "$root\packer\bin\Debug\WinAppLocker.exe"
            if (-not (Test-Path $packer)) {
                throw "找不到 packer exe，请先运行 .\build.ps1 -Release"
            }
        }
    }
}
Write-Host "==> packer: $packer" -ForegroundColor Cyan

# 显示 packer 版本
& $packer --version
Write-Host ""

# 样本目录：项目根目录下的 temp/samples（参考 AGENTS.md，测试样本放 temp 目录）
$samplesDir = Resolve-Path "$root\..\temp\samples"

# 默认测试样本：
#   - CLI 程序：hellocli / hellomingw / helloucrt / sha256sum（可通过 stdout 验证）
#   - GUI 程序：helloguix64 / helloguix86 / hellowinforms（通过进程存活验证）
# hellowinforms 是 .NET WinForms，WinLock 模式不支持（会被 packer 拒绝并报错）
if ($Samples) {
    $sampleList = $Samples -split ','
} else {
    $cliSamples = @('hellocli.exe', 'hellomingw.exe', 'helloucrt.exe', 'sha256sum.exe')
    $guiSamples = @('helloguix64.exe', 'helloguix86.exe', 'hellowinforms.exe')
    $sampleList = $cliSamples + $guiSamples
}

$workDir = "$root\temp\test_dotnet_work"
if (Test-Path $workDir) {
    Get-ChildItem $workDir -Filter "*.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
} else {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
}

# 密码：
#   临时文件模式用 stub_test，内置密码 "test1234"
#   WinLock 模式用 builder -t，内置密码 "test123"
$password = if ($WinLock) { "test123" } else { "test1234" }
$failCount = 0
$passCount = 0
$skipCount = 0

# 空文件作为子进程 stdin 输入：避免 sha256sum 等从 stdin 读取的程序在交互式 pwsh 下
# 继承 TTY 而卡住（Start-Process -NoNewWindow 会让子进程共享当前控制台）
$nullIn = "$env:TEMP\wal_null_in.txt"
"" | Set-Content $nullIn -NoNewline -Encoding ASCII

function Is-GuiExe {
    param([string]$path)
    # 用 packer --pe-info 读子系统判断，比文件名启发式更可靠
    # （hellowinforms.exe 是 .NET WinForms GUI 但文件名不含 "gui"）
    # Subsystem: 2=WindowsGui, 3=WindowsConsole
    $infoOut = "$env:TEMP\wal_peinfo.txt"
    $proc = Start-Process -FilePath $packer -ArgumentList "--pe-info",$path -RedirectStandardInput $nullIn -RedirectStandardOutput $infoOut -RedirectStandardError "$env:TEMP\wal_peinfo_err.txt" -PassThru -Wait -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        # pe-info 失败时退回文件名启发式
        return $path -match 'gui' -or $path -match 'DontSleep' -or $path -match 'notepad' -or $path -match 'Notepad'
    }
    $content = Get-Content $infoOut -Raw -ErrorAction SilentlyContinue
    if ($content -match "子系统\s*\(Subsystem\):\s*(\d+)") {
        return $Matches[1] -eq '2'
    }
    return $false
}

foreach ($sample in $sampleList) {
    $src = Join-Path $samplesDir.Path $sample
    if (-not (Test-Path $src)) {
        Write-Host "[SKIP] $sample (not found)" -ForegroundColor Yellow
        $skipCount++
        continue
    }

    $modeTag = if ($WinLock) { " [WinLock]" } else { "" }
    Write-Host "`n=== Test: $sample$modeTag ===" -ForegroundColor Cyan

    # 复制原 exe 到 work 目录（hellowinforms.exe.config 一起拷，否则 .NET 程序启动失败）
    $workSrc = Join-Path $workDir $sample
    Copy-Item $src $workSrc -Force
    $srcConfig = [System.IO.Path]::ChangeExtension($src, '.exe.config')
    if (Test-Path $srcConfig) {
        Copy-Item $srcConfig ([System.IO.Path]::ChangeExtension($workSrc, '.exe.config')) -Force
    }

    # 输出文件命名：临时文件模式 _test_locked.exe，WinLock 模式 _wl_locked.exe
    $lockedSuffix = if ($WinLock) { '_wl_locked.exe' } else { '_test_locked.exe' }
    $lockedPath = Join-Path $workDir ($sample -replace '\.exe$', $lockedSuffix)

    # 清理可能的残留临时文件
    Get-ChildItem $workDir -Filter "_*_ori.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

    # 1. 加密
    if ($WinLock) {
        Write-Host "  [1] Pack with --stub-name winlock --test..." -NoNewline
        # --test 让 builder 用 -t 测试模式：stub 跳过弹框，密码硬编码 test123
        $packArgs = @("--pack","-i",$workSrc,"-o",$lockedPath,"-p",$password,"--stub-name","winlock","--test")
    } else {
        Write-Host "  [1] Pack with --stub Test..." -NoNewline
        $packArgs = @("--pack","-i",$workSrc,"-o",$lockedPath,"-p",$password,"--stub","Test")
    }
    $outLog = "$env:TEMP\wal_pack_out.txt"
    $errLog = "$env:TEMP\wal_pack_err.txt"
    $proc = Start-Process -FilePath $packer -ArgumentList $packArgs -RedirectStandardInput $nullIn -RedirectStandardOutput $outLog -RedirectStandardError $errLog -PassThru -Wait -NoNewWindow
    if ($proc.ExitCode -ne 0 -or -not (Test-Path $lockedPath)) {
        # WinLock 模式下某些样本预期不支持：
        #   - Console 程序（hellocli/hellomingw/helloucrt/sha256sum）→ "WinLock 模式当前仅支持 GUI 程序"
        #   - .NET 程序（hellowinforms）→ "WinLock 模式不支持 .NET CLR 托管 PE"
        # 这些是预期失败，标 SKIP 而不是 FAIL
        $errContent = Get-Content $errLog -Raw -ErrorAction SilentlyContinue
        if ($WinLock -and ($errContent -match "WinLock 模式当前仅支持 GUI" -or $errContent -match "WinLock 模式不支持 .NET")) {
            $reason = if ($errContent -match "不支持 .NET") { "不支持 .NET" } else { "仅支持 GUI" }
            Write-Host " SKIP (WinLock $reason)" -ForegroundColor Yellow
            $skipCount++
        } else {
            Write-Host " FAIL (pack exit=$($proc.ExitCode))" -ForegroundColor Red
            Get-Content $errLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
            $failCount++
        }
        continue
    }
    $lockedSize = (Get-Item $lockedPath).Length
    Write-Host " OK ($lockedSize bytes)" -ForegroundColor Green

    # 1b. 可选：用 --info 检查打包结果（仅临时文件模式，WinLock 无 payload header）
    if ($Info -and -not $WinLock) {
        Write-Host "  [1b] --info 检查..." -NoNewline
        $infoOut = "$env:TEMP\wal_info_out.txt"
        $proc = Start-Process -FilePath $packer -ArgumentList "--info",$lockedPath -RedirectStandardInput $nullIn -RedirectStandardOutput $infoOut -RedirectStandardError "$env:TEMP\wal_info_err.txt" -PassThru -Wait -NoNewWindow
        $infoContent = Get-Content $infoOut -Raw -ErrorAction SilentlyContinue
        if ($proc.ExitCode -eq 0 -and $infoContent -match "合法的 WinAppLocker") {
            Write-Host " OK (合法加密 EXE)" -ForegroundColor Green
        } else {
            Write-Host " FAIL (exit=$($proc.ExitCode))" -ForegroundColor Red
            $failCount++
            continue
        }
    }

    # 2. 运行（WinLock 模式加壳后是 in-place，直接运行原程序逻辑；
    #    临时文件模式 stub_test 自动用内置密码解密）
    # 注意：必须传完整路径（$src），不能只传文件名（$sample），
    # 否则 --pe-info 找不到文件会走 fallback 启发式，hellowinforms 这种不含 'gui' 的会误判为 CLI
    $isGui = Is-GuiExe $src
    if ($isGui) {
        # GUI 程序：启动后等待几秒检查进程是否存活
        Write-Host "  [2] Run (GUI, wait ${WaitGui}s)..." -NoNewline
        $proc = Start-Process -FilePath $lockedPath -PassThru
        $stubPid = $proc.Id
        Start-Sleep -Seconds $WaitGui

        # 检查 stub 进程或临时子进程是否存活
        # 临时文件模式：stub_test 启动原 exe 作为子进程，临时文件命名规则（见 StubEntry.cs:122）
        #   xxx.exe → _xxx_ori.exe（例如 helloguix64_test_locked.exe → _helloguix64_test_locked_ori.exe）
        # WinLock 模式：加壳后 exe 本身就是原程序，无子进程，检查 stubPid 存活即可
        $stubAlive = Get-Process -Id $stubPid -ErrorAction SilentlyContinue
        $tempProcs = @()
        if (-not $WinLock) {
            $oriName = "_" + ($sample -replace '\.exe$', '') + "_test_locked_ori"
            $tempProcs += Get-Process -Name "$oriName" -ErrorAction SilentlyContinue
            # 兜底：匹配所有 _*_ori 进程（避免其它测试残留）
            $tempProcs += Get-Process -Name "_*_ori" -ErrorAction SilentlyContinue
            $tempProcs = $tempProcs | Sort-Object Id -Unique
        }

        if ($stubAlive -or $tempProcs) {
            Write-Host " OK (进程运行中)" -ForegroundColor Green
            $passCount++
            # 清理：先杀子进程（原 exe）让 stub 退出，再杀 stub
            # 顺序很重要：stub 在 WaitForExit 子进程，子进程死了 stub 才会退出
            # WinLock 模式无子进程，直接杀 stubPid
            if ($tempProcs) {
                $tempProcs | ForEach-Object {
                    Write-Host "    [kill] $($_.Name) (pid=$($_.Id))" -ForegroundColor DarkGray
                    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                }
            }
            Start-Sleep -Milliseconds 500
            if (Get-Process -Id $stubPid -ErrorAction SilentlyContinue) {
                Write-Host "    [kill] stub (pid=$stubPid)" -ForegroundColor DarkGray
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
        # 关键：必须重定向 stdin 到空文件，否则像 sha256sum 这种不带参数会从 stdin 读取的程序
        # 在交互式 pwsh 下会继承 TTY 等待输入，导致测试卡住
        $proc = Start-Process -FilePath $lockedPath -RedirectStandardInput $nullIn -RedirectStandardOutput $outFile -RedirectStandardError $errFile -PassThru -Wait -NoNewWindow
        $exitCode = $proc.ExitCode
        $stdoutContent = Get-Content $outFile -Raw -ErrorAction SilentlyContinue
        if ($exitCode -eq 0) {
            # stdout 可能为空（GUI 程序意外走到 CLI 分支时不输出到 stdout）
            if ($stdoutContent) {
                $firstLine = ($stdoutContent -split "`n" | Where-Object { $_ -ne "" } | Select-Object -Last 1).Trim()
                Write-Host " OK (exit=0, output: '$firstLine')" -ForegroundColor Green
            } else {
                Write-Host " OK (exit=0, no stdout)" -ForegroundColor Green
            }
            $passCount++
        } else {
            Write-Host " FAIL (exit=$exitCode)" -ForegroundColor Red
            Get-Content $errFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
            $failCount++
        }
    }

    # 3. 验证临时文件清理（仅临时文件模式有 _*_ori.exe 临时文件）
    if (-not $WinLock) {
        Start-Sleep -Milliseconds 300
        $remnants = Get-ChildItem $workDir -Filter "_*_ori.exe" -ErrorAction SilentlyContinue
        if ($remnants) {
            Write-Host "  [!] WARN: temp files remaining: $($remnants.Name -join ', ')" -ForegroundColor Yellow
            $remnants | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
}

# 清理测试残留
Get-ChildItem $workDir -Filter "_*_ori.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "`n==> 完成: $passCount 通过, $failCount 失败, $skipCount 跳过" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Red' })

} finally {
    # 恢复调用方当前目录（Set-Location 会污染调用方 cwd）
    Pop-Location
}

# 在 try/finally 外 exit，确保 finally 已执行完毕
exit $failCount
