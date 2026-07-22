# auto_e2e_test.ps1 - applocker 综合端到端测试
# 覆盖矩阵：inplace × reflective × 无密码(-t) × 自动输入密码(-p)
# 用法：powershell -File auto_e2e_test.ps1
#       powershell -File auto_e2e_test.ps1 -SkipReflective  # 只测 inplace
#       powershell -File auto_e2e_test.ps1 -SkipInplace     # 只测 reflective
#       powershell -File auto_e2e_test.ps1 -IncludeTestMode # 同时测 -t 模式（默认跳过）
#       powershell -File auto_e2e_test.ps1 -SkipPassword    # 只测 -t 模式
#       powershell -File auto_e2e_test.ps1 -ExternalSamples C:\path\to\bigapps
#                                                         # 追加外部样本目录

param(
    [switch]$SkipInplace,
    [switch]$SkipReflective,
    # 默认跳过 test 模式（-t）：自动输入密码已稳定，password 模式覆盖更全
    # 显式用 -IncludeTestMode 开启 test 模式测试
    [switch]$IncludeTestMode,
    [switch]$SkipPassword,
    [int]$GuiTimeoutSec = 12,
    [string]$ExternalSamples = ""  # 外部样本目录（如 temp\bigapps），自动扫描子目录中的 .exe
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$packerRoot = Split-Path -Parent $root
$dist = "$packerRoot\dist"
$samples = "$packerRoot\..\temp\samples"
$work = "$packerRoot\temp\auto_e2e_result"
$inplaceBuilder = "$dist\builder_inplace.exe"
$reflectiveBuilder = "$dist\builder_reflective.exe"

# 日志文件：同时输出到控制台和日志文件（Start-Transcript 捕获所有 Write-Host 输出）
$logFile = "$work\auto_e2e_test.log"
if (-not (Test-Path $work)) { New-Item -ItemType Directory -Path $work -Force | Out-Null }
Start-Transcript -Path $logFile -Force | Out-Null

# 密码对话框标题（inplace 和 reflective 通用）
$PwdDialogTitle = "WinLock - Password Required"

# Python 路径（用于调用 inspect_stub.py / check_stub_freshness.py）
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $pythonExe) { $pythonExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source }

if (-not (Test-Path $inplaceBuilder)) {
    Write-Host "builder_inplace.exe 不存在，请先运行 build.ps1" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $reflectiveBuilder)) {
    Write-Host "builder_reflective.exe 不存在，请先运行 build.ps1" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $work)) { New-Item -ItemType Directory -Path $work -Force | Out-Null }

# ---- stub source_crc 新鲜度校验（改动 9，审查 A10）----
# 在 e2e 测试开始前，校验 dist/stub_*.bin 的 stub_source_crc 是否与当前源码一致
# warn-only 模式：不匹配只警告，不 fail（避免源码小改动强制 rebuild 才能跑 e2e）
function Check-StubFreshness {
    param([string]$StubDir, [string]$WinlockRoot)
    if (-not $pythonExe) {
        Write-Host "[stub] SKIP: Python 不在 PATH，跳过 source_crc 校验" -ForegroundColor Yellow
        return
    }
    $script = Join-Path $WinlockRoot "cmake\check_stub_freshness.py"
    if (-not (Test-Path $script)) {
        Write-Host "[stub] SKIP: $script 不存在" -ForegroundColor Yellow
        return
    }
    Write-Host "==== stub source_crc 新鲜度校验 ====" -ForegroundColor Cyan
    & $pythonExe $script --stub-dir $StubDir --winlock-root $WinlockRoot
}

Check-StubFreshness -StubDir $dist -WinlockRoot $packerRoot

# 自动输入密码所需的 Win32 API 封装类（与 input_password.ps1 等价，但不依赖该脚本）
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

public static class AutoE2E {
    public delegate bool EnumTopProc(IntPtr hwnd, IntPtr lParam);
    public delegate bool EnumChildProc(IntPtr parent, IntPtr lParam);

    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumTopProc cb, IntPtr lp);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent, EnumChildProc cb, IntPtr lp);
    [DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, string s);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    public const uint WM_SETTEXT = 0x000C;
    public const uint BM_CLICK   = 0x00F5;

    public static IntPtr FindTopByTitle(string title) {
        IntPtr found = IntPtr.Zero;
        EnumTopProc cb = (h, lp) => {
            int len = GetWindowTextLength(h);
            if (len != title.Length) return true;
            StringBuilder txt = new StringBuilder(len + 2);
            GetWindowText(h, txt, len + 2);
            if (txt.ToString() == title) { found = h; return false; }
            return true;
        };
        EnumWindows(cb, IntPtr.Zero);
        return found;
    }

    public static IntPtr FindChild(IntPtr parent, string className, string text) {
        IntPtr found = IntPtr.Zero;
        EnumChildProc cb = (h, lp) => {
            StringBuilder cls = new StringBuilder(64);
            GetClassName(h, cls, 64);
            int len = GetWindowTextLength(h);
            StringBuilder txt = new StringBuilder(len + 2);
            GetWindowText(h, txt, len + 2);
            bool classMatch = (className == null) || (cls.ToString() == className);
            bool textMatch  = (text == null) || (txt.ToString() == text);
            if (classMatch && textMatch) { found = h; return false; }
            return true;
        };
        EnumChildWindows(parent, cb, IntPtr.Zero);
        return found;
    }

    // 收集指定 PID 进程树的所有可见窗口（排除密码框）
    public static List<string> VisibleWindowsOfPID(uint pid, string excludeTitle) {
        List<string> result = new List<string>();
        EnumTopProc cb = (h, lp) => {
            if (!IsWindowVisible(h)) return true;
            int len = GetWindowTextLength(h);
            if (len <= 0) return true;
            StringBuilder txt = new StringBuilder(len + 2);
            GetWindowText(h, txt, len + 2);
            string title = txt.ToString();
            if (excludeTitle != null && title == excludeTitle) return true;
            // 只收集属于目标 PID 的窗口
            uint wpid;
            GetWindowThreadProcessId(h, out wpid);
            if (wpid == pid) {
                StringBuilder cls = new StringBuilder(64);
                GetClassName(h, cls, 64);
                result.Add(string.Format("cls={0} txt='{1}'", cls, title));
            }
            return true;
        };
        EnumWindows(cb, IntPtr.Zero);
        return result;
    }
}
"@

# 获取进程及其所有子进程的 PID 列表
function Get-DescendantPids($rootPid) {
    $pids = @($rootPid)
    $queue = @($rootPid)
    while ($queue.Count -gt 0) {
        $cur = $queue[0]
        $queue = $queue[1..($queue.Count - 1)]
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$cur" -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty ProcessId
        foreach ($c in $children) {
            if ($pids -notcontains $c) {
                $pids += $c
                $queue += $c
            }
        }
    }
    return $pids
}

function Stop-AppTree($rootPid) {
    if (-not $rootPid) { return }
    $all = Get-DescendantPids $rootPid
    $rev = $all[-1..-($all.Count)]
    foreach ($p in $rev) {
        try { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue } catch {}
    }
}

# 自动输入密码到密码框
function Send-PasswordToDialog {
    param([string]$Password, [int]$TimeoutSec = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $hwnd = [IntPtr]::Zero
    while ((Get-Date) -lt $deadline) {
        $hwnd = [AutoE2E]::FindTopByTitle($PwdDialogTitle)
        if ($hwnd -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 200
    }
    if ($hwnd -eq [IntPtr]::Zero) { return $false }

    # 找 Edit 框
    $edit = [IntPtr]::Zero
    $deadline2 = (Get-Date).AddSeconds(3)
    while ((Get-Date) -lt $deadline2) {
        $edit = [AutoE2E]::FindChild($hwnd, "Edit", $null)
        if ($edit -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($edit -eq [IntPtr]::Zero) { return $false }

    [AutoE2E]::SendMessage($edit, [AutoE2E]::WM_SETTEXT, [IntPtr]::Zero, $Password) | Out-Null

    # 找 OK 按钮
    $ok = [IntPtr]::Zero
    $deadline3 = (Get-Date).AddSeconds(3)
    while ((Get-Date) -lt $deadline3) {
        $ok = [AutoE2E]::FindChild($hwnd, "Button", "OK")
        if ($ok -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($ok -eq [IntPtr]::Zero) { return $false }

    [AutoE2E]::SendMessage($ok, [AutoE2E]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    return $true
}

# 测试矩阵定义：每个样本的预期行为
# Type: CUI (console) / GUI
# TestMode: -t 模式下预期 stdout / 窗口
# PasswordMode: -p 模式下预期 stdout / 窗口
$testSamples = @(
    @{ Name="hellomingw.exe";   Type="CUI"; TestExpect="Hello, MinGW"; PwdExpect="Hello, MinGW" },
    @{ Name="hellomingw32.exe";    Type="CUI"; TestExpect="Hello, MINGW32!";  PwdExpect="Hello, MINGW32!" },
    @{ Name="helloucrt.exe";    Type="CUI"; TestExpect="Hello, UCRT";  PwdExpect="Hello, UCRT" },
    @{ Name="helloclivsx86.exe";    Type="CUI"; TestExpect="Hello VSx86!";  PwdExpect="Hello VSx86!" },
    @{ Name="helloclivsx64.exe";    Type="CUI"; TestExpect="Hello VSx64!";  PwdExpect="Hello VSx64!" },

    @{ Name="helloguix86.exe";  Type="GUI"; TestExpect="window";       PwdExpect="window" },
    @{ Name="helloguix64.exe";  Type="GUI"; TestExpect="window";       PwdExpect="window" },
    @{ Name="hellomfcx86.exe";  Type="GUI"; TestExpect="window";       PwdExpect="window" },
    @{ Name="hellomfcx64.exe";  Type="GUI"; TestExpect="window";       PwdExpect="window" },
    @{ Name="Notepad4.exe";     Type="GUI"; TestExpect="window";       PwdExpect="window" },
    @{ Name="DontSleep.exe";    Type="GUI"; TestExpect="window";       PwdExpect="window" }
)

# ---- 追加外部样本（-ExternalSamples）----
# 扫描指定目录下每个子目录中的主 .exe（每个子目录视为一个应用）
# 外部样本默认 Type=GUI，TestExpect/PwdExpect="window"（只要窗口出现即可）
# 通过 SamplePath 指定完整路径（不依赖 $samples 目录）
# 外部样本因有 DLL/资源依赖，加壳产物必须放在原 exe 同目录（IsExternal=$true）
if ($ExternalSamples -and (Test-Path $ExternalSamples)) {
    Write-Host "==== 扫描外部样本目录: $ExternalSamples ====" -ForegroundColor Cyan
    # 用 -ExternalSamples 时跳过内置 samples（避免重复测试，聚焦外部样本）
    $testSamples = @()
    Get-ChildItem -Path $ExternalSamples -Directory | ForEach-Object {
        $appDir = $_.FullName
        $appName = $_.Name
        # 找目录下的 .exe（排除明显的辅助 exe 如 vlc-cache-gen.exe, KCrashReporter 等）
        $exes = Get-ChildItem -Path $appDir -Filter "*.exe" -File -ErrorAction SilentlyContinue
        if ($exes.Count -eq 0) { return }
        # 过滤辅助 exe 和测试产物：
        #   辅助 exe：tmp|cache/crash/report/updater/uninstall/helper/setup/texconv/exiftool/twain/gup
        #   测试产物：_locked/_refl/_inplace/_password 后缀（之前的加壳产物）
        #   关联工具：Associate（如 XnViewMP 的文件关联设置工具）
        $mainExes = $exes | Where-Object {
            $n = $_.BaseName.ToLower()
            -not ($n -match 'tmp|cache|crash|report|updater|uninstall|helper|setup|texconv|exiftool|twain|gup') -and
            -not ($n -match '_locked$|_refl$|_inplace$|_password$|_test$') -and
            -not ($n -match '^associate')
        }
        # 优先选择与目录名匹配的 exe（如 vlc-x64 目录 -> vlc.exe）
        # 用 -like 通配符匹配，避免正则量词错误（如 notepad++ 的 + 号）
        $targetExe = $mainExes | Where-Object {
            $_.BaseName -like "*$appName*" -or $appName -like "*$($_.BaseName)*"
        } | Select-Object -First 1
        if (-not $targetExe) { $targetExe = $mainExes | Select-Object -First 1 }
        if (-not $targetExe) { $targetExe = $exes | Select-Object -First 1 }
        if ($targetExe) {
            $testSamples += @{
                Name       = "$appName/$($targetExe.Name)"
                Type       = "GUI"
                TestExpect = "window"
                PwdExpect  = "window"
                SamplePath = $targetExe.FullName  # 完整路径，Pack-Sample 优先用此字段
                IsExternal = $true                 # 外部样本：加壳产物放原目录
            }
            Write-Host "  + $appName -> $($targetExe.Name)" -ForegroundColor DarkGray
        }
    }
}

$results = @()

function Pack-Sample {
    param(
        [string]$Mode,      # "inplace" 或 "reflective"
        [string]$SampleName,
        [string]$OutPath,
        [string]$Password,  # $null 表示 -t 测试模式
        [switch]$TestMode,
        [string]$SamplePath = ""  # 外部样本完整路径（优先于 $samples/$SampleName）
    )
    # 外部样本用 SamplePath，内置样本用 $samples/$SampleName
    if ($SamplePath) {
        $srcExe = $SamplePath
    } else {
        $srcExe = Join-Path $samples $SampleName
    }
    if (-not (Test-Path $srcExe)) { return @{ ok=$false; rc=-1; out="sample not found: $srcExe" } }

    # 清理旧输出文件：上次测试可能残留进程占用 exe 文件
    # 先杀同名进程，再删除文件，避免 "Permission denied" 导致 PACK_FAIL
    if (Test-Path $OutPath) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutPath)
        Get-Process -Name $baseName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 200
        try { Remove-Item -Force $OutPath -ErrorAction Stop } catch { Start-Sleep -Milliseconds 500; Remove-Item -Force $OutPath -ErrorAction SilentlyContinue }
    }

    # builder 必须在 dist/ 目录运行（找 stub）
    $origWD = (Get-Location).Path
    try {
        Set-Location $dist
        if ($Mode -eq "inplace") {
            $packArgs = @("-i", $srcExe, "-o", $OutPath)
            if ($TestMode) { $packArgs += @("-t") }
            elseif ($Password) { $packArgs += @("-p", $Password) }
            $packOut = & $inplaceBuilder @packArgs 2>&1
        } else {
            # reflective: 位置参数 input output
            $packArgs = @($srcExe, $OutPath)
            if ($TestMode) { $packArgs += @("-t") }
            elseif ($Password) { $packArgs += @("-p", $Password) }
            $packOut = & $reflectiveBuilder @packArgs 2>&1
        }
        $rc = $LASTEXITCODE
    } finally {
        Set-Location $origWD
    }
    return @{ ok=($rc -eq 0 -and (Test-Path $OutPath)); rc=$rc; out=($packOut -join "`n") }
}

# ---- 端到端 identity 校验（改动 9，审查 A7）----
# 加壳后用 inspect_stub.py 读 packed.exe 的 .text2 节里的 stub_data_t，
# 与 dist/stub_*.bin 的 identity 对比，确认加壳产物用的是预期的 stub
# 只对 inplace 模式生效（reflective 产物无 .text2 节）
# warn-only：不一致只警告，不 fail（避免 inspect_stub.py 解析失败阻断 e2e）
function Verify-PackedIdentity {
    param(
        [string]$PackedExe,
        [string]$Mode
    )
    if ($Mode -ne "inplace") { return $true }
    if (-not $pythonExe) { return $true }

    $inspectScript = Join-Path $packerRoot "cmake\inspect_stub.py"
    if (-not (Test-Path $inspectScript)) { return $true }

    # 先读 packed.exe 的 identity（从 .text2 节），用其中的 stub_arch 选对应的 stub.bin
    # 不再用文件名猜架构：hellomingw32.exe 等样本名不含 x86 但实际是 x86 程序
    $packedInfo = & $pythonExe $inspectScript $PackedExe --format=json --winlock-root $packerRoot 2>$null | ConvertFrom-Json
    if (-not $packedInfo) {
        # inspect_stub.py 失败（如 PE 解析失败），不阻断测试
        return $true
    }
    # stub_arch: 1=x86, 2=x64（config.h STUB_ARCH_X86/X64）
    $sampleArch = if ($packedInfo.stub_arch -eq 1) { "x86" } else { "x64" }
    $stubBin = Join-Path $dist "stub_inplace_$sampleArch.bin"
    if (-not (Test-Path $stubBin)) { return $true }

    # 读 stub.bin 的 identity
    $stubInfo = & $pythonExe $inspectScript $stubBin --format=json --winlock-root $packerRoot 2>$null | ConvertFrom-Json
    if (-not $stubInfo) {
        return $true
    }

    # 对比关键字段（不含 stub_size：builder 在 .text2 末尾追加 callbacks 数组会扩展节大小）
    $fieldsToCompare = @("stub_arch", "stub_toolchain", "stub_bin_ver",
                         "stub_build_time", "stub_source_crc", "stub_githash")
    $allMatch = $true
    foreach ($field in $fieldsToCompare) {
        $s = $stubInfo.$field
        $p = $packedInfo.$field
        if ($s -ne $p) {
            Write-Host "      [WARN] identity mismatch: $field stub=$s packed=$p" -ForegroundColor Yellow
            $allMatch = $false
        }
    }
    if ($allMatch) {
        Write-Host "      [identity OK] packed.exe .text2 节与 stub.bin 身份一致" -ForegroundColor DarkGray
    }
    return $allMatch
}

function Test-One {
    param(
        [string]$Mode,         # "inplace" / "reflective"
        [string]$PasswordMode, # "test" (-t) / "password" (-p)
        [hashtable]$Sample
    )

    $sampleName = $Sample.Name
    $tag = "${Mode}_${PasswordMode}"
    # 外部样本 Name 可能含斜杠（如 "vlc-x64/vlc.exe"），清理成文件名安全的字符串
    $safeName = $sampleName -replace '[\\/]', '_'
    $outName = $safeName -replace '\.exe$', "_${tag}.exe"
    # 外部样本：加壳产物放原 exe 同目录（访问 DLL/资源依赖）
    # 内置样本：统一放 $work 目录
    if ($Sample.IsExternal -and $Sample.SamplePath) {
        $srcDir = Split-Path -Parent $Sample.SamplePath
        $outPath = Join-Path $srcDir $outName
    } else {
        $outPath = Join-Path $work $outName
    }
    # 注意：不能用 $pwd，它是 PowerShell 自动变量（当前工作目录）
    $testPwd = "hello123"

    Write-Host ""
    Write-Host ("===== [{0}] {1} / {2} =====" -f $tag, $sampleName, $PasswordMode) -ForegroundColor Cyan

    if ($PasswordMode -eq "test" -and $Sample.SkipTestMode) {
        Write-Host "[SKIP] 样本标记跳过 test 模式: $($Sample.Note)" -ForegroundColor Yellow
        return @{ tag=$tag; sample=$sampleName; result="SKIP"; detail=$Sample.Note }
    }
    if ($PasswordMode -eq "password" -and $Sample.SkipPassword) {
        Write-Host "[SKIP] 样本标记跳过 password 模式: $($Sample.Note)" -ForegroundColor Yellow
        return @{ tag=$tag; sample=$sampleName; result="SKIP"; detail=$Sample.Note }
    }

    # 1. 加壳
    Write-Host "[1/3] 加壳 ($Mode, $PasswordMode)..."
    $isTest = ($PasswordMode -eq "test")
    $pack = Pack-Sample -Mode $Mode -SampleName $sampleName -OutPath $outPath -Password $testPwd -TestMode:$isTest -SamplePath $Sample.SamplePath
    if (-not $pack.ok) {
        # 打印详细失败原因：pack.out 可能是 "sample not found" 或 builder 的 stderr/stdout
        # 不再只显示 rc，避免 "文件找不到" 被误报为 "加壳失败"
        $reason = $pack.out
        if (-not $reason) { $reason = "rc=$($pack.rc) (无输出)" }
        Write-Host "[FAIL] 加壳失败: $reason" -ForegroundColor Red
        return @{ tag=$tag; sample=$sampleName; result="PACK_FAIL"; detail=$reason }
    }
    Write-Host "      产物: $outPath ($((Get-Item $outPath).Length) bytes)" -ForegroundColor DarkGray

    # 端到端 identity 校验（改动 9，审查 A7）
    # 只对 inplace 模式：用 inspect_stub.py 读 packed.exe 的 .text2 节，与 stub.bin 对比
    Verify-PackedIdentity -PackedExe $outPath -Mode $Mode | Out-Null

    # 2. 运行
    Write-Host "[2/3] 运行..."
    if ($Sample.Type -eq "CUI") {
        # 控制台程序：捕获 stdout
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $outPath
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)

        if ($PasswordMode -eq "password") {
            # GUI 密码框，需要自动输入
            Start-Sleep -Milliseconds 300
            $sent = Send-PasswordToDialog -Password $testPwd -TimeoutSec 10
            if (-not $sent) {
                Write-Host "[WARN] 密码框未找到或未发送成功" -ForegroundColor Yellow
            }
        }

        $exited = $proc.WaitForExit(15000)
        if (-not $exited) {
            try { $proc.Kill() } catch {}
            Write-Host "[FAIL] 15s 超时未退出" -ForegroundColor Red
            return @{ tag=$tag; sample=$sampleName; result="TIMEOUT"; detail="did not exit" }
        }
        $stdout = $proc.StandardOutput.ReadToEnd().Trim()
        $exitCode = $proc.ExitCode
        Write-Host ("      exit={0} stdout='{1}'" -f $exitCode, $stdout) -ForegroundColor DarkGray

        # 3. 验证
        $expect = if ($PasswordMode -eq "test") { $Sample.TestExpect } else { $Sample.PwdExpect }
        if ([string]::IsNullOrEmpty($expect)) {
            # 不检查输出，只要不崩溃
            if ($exitCode -eq 0) {
                Write-Host "[PASS] exit=0" -ForegroundColor Green
                return @{ tag=$tag; sample=$sampleName; result="PASS"; detail="exit=$exitCode" }
            } else {
                # 打印 stdout（可能含崩溃前的输出）便于诊断
                Write-Host "[FAIL] exit=$exitCode stdout='$stdout'" -ForegroundColor Red
                return @{ tag=$tag; sample=$sampleName; result="CRASH"; detail="exit=$exitCode out='$stdout'" }
            }
        } elseif ($stdout -match $expect) {
            Write-Host "[PASS] 输出匹配" -ForegroundColor Green
            return @{ tag=$tag; sample=$sampleName; result="PASS"; detail="exit=$exitCode out='$stdout'" }
        } else {
            Write-Host "[FAIL] 输出不匹配, 期望: '$expect' 实际: '$stdout'" -ForegroundColor Red
            return @{ tag=$tag; sample=$sampleName; result="OUT_FAIL"; detail="exit=$exitCode out='$stdout'" }
        }
    } else {
        # GUI 程序：等待主窗口出现
        # 用 AutoE2E.VisibleWindowsOfPID 直接查窗口（轻量，单次 EnumWindows）
        # 比 Get-Process.MainWindowHandle 更准更快，且能区分密码框与主窗口
        $proc = Start-Process -FilePath $outPath -PassThru -WindowStyle Normal
        $rootPid = $proc.Id
        Write-Host ("      PID={0}" -f $rootPid)

        # try/finally 保证无论测试结果如何都清理进程树
        # 否则一个 GUI 样本卡住会拖死整个测试矩阵
        $found = $false
        $exitEarly = $false
        $earlyExitCode = 0
        $errTitle = $false
        try {
            if ($PasswordMode -eq "password") {
                # 自动输入密码（异步：密码框可能稍后才出现）
                Start-Sleep -Milliseconds 2000
                $sent = Send-PasswordToDialog -Password $testPwd -TimeoutSec 8
                if (-not $sent) {
                    Write-Host "[WARN] 密码框未找到或未发送成功" -ForegroundColor Yellow
                }
            }

            Start-Sleep -Milliseconds 1000
            # 等待主窗口出现：500ms 一次轮询，比 1s 更快
            # 用 AutoE2E.VisibleWindowsOfPID 直接查可见顶级窗口（排除密码框）
            $deadline = (Get-Date).AddSeconds($GuiTimeoutSec)
            while ((Get-Date) -lt $deadline) {
                if ($proc.HasExited) {
                    $earlyExitCode = $proc.ExitCode
                    $exitEarly = $true
                    Write-Host "[FAIL] 进程已退出, exit=$earlyExitCode" -ForegroundColor Red
                    break
                }
                $wins = [AutoE2E]::VisibleWindowsOfPID([uint32]$rootPid, $PwdDialogTitle)
                if ($wins.Count -gt 0) {
                    # 完整打印所有可见窗口标题，方便调试
                    foreach ($w in $wins) {
                        Write-Host ("      窗口: {0}" -f $w) -ForegroundColor DarkGray
                    }
                    $winInfo = $wins[0]
                    # 错误窗口关键字匹配（中英文）：
                    #   error/fault/fail/crash/exception/abort（英文）
                    #   错误/失败/崩溃/异常（中文）
                    #   could not be started（.NET 框架错误对话框）
                    # 不区分大小写
                    if ($winInfo -match 'error|fault|fail|crash|exception|abort|could not|错误|失败|崩溃|异常') {
                        $errTitle = $true
                        break
                    } else {
                        $found = $true
                        break
                    }
                }
                Start-Sleep -Milliseconds 500
            }
        } finally {
            # 无论结果如何，都主动结束整个进程树（GUI 程序不会自己退出）
            # taskkill /F /T 递归杀子进程；不等待，直接继续
            if (-not $proc.HasExited) {
                taskkill /F /T /PID $rootPid 2>&1 | Out-Null
            }
        }

        if ($found) {
            Write-Host "[PASS] 窗口已显示" -ForegroundColor Green
            return @{ tag=$tag; sample=$sampleName; result="PASS"; detail="window shown" }
        } elseif ($errTitle) {
            Write-Host "[FAIL] 窗口标题包含 error" -ForegroundColor Red
            return @{ tag=$tag; sample=$sampleName; result="ERROR_WINDOW"; detail="error window" }
        } elseif ($exitEarly) {
            return @{ tag=$tag; sample=$sampleName; result="CRASH"; detail="exit=$earlyExitCode" }
        } else {
            Write-Host "[FAIL] 超时未出现窗口" -ForegroundColor Yellow
            return @{ tag=$tag; sample=$sampleName; result="NO_WINDOW"; detail="timeout, no window" }
        }
    }
}

# ==================== 测试矩阵 ====================

$modes = @()
if (-not $SkipInplace) { $modes += "inplace" }
if (-not $SkipReflective) { $modes += "reflective" }

$pwdModes = @()
# 默认跳过 test 模式（自动输入密码已稳定，password 模式覆盖更全）
# 显式 -IncludeTestMode 才测 test 模式
if ($IncludeTestMode) { $pwdModes += "test" }
if (-not $SkipPassword) { $pwdModes += "password" }

foreach ($mode in $modes) {
    foreach ($pm in $pwdModes) {
        Write-Host ""
        Write-Host ("################## {0} / {1} ##################" -f $mode, $pm) -ForegroundColor Magenta
        foreach ($s in $testSamples) {
            $r = Test-One -Mode $mode -PasswordMode $pm -Sample $s
            $results += $r
        }
    }
}

# ==================== 汇总 ====================
Write-Host ""
Write-Host ("测试文件: {0}" -f $PSCommandPath) -ForegroundColor DarkGray
Write-Host ""
Write-Host "================ SUMMARY ================" -ForegroundColor Yellow
$results | ForEach-Object {
    $color = if ($_.result -eq "PASS") { "Green" } elseif ($_.result -eq "SKIP") { "DarkGray" } else { "Red" }
    Write-Host ("{0,-20} {1,-15} {2,-12} {3}" -f $_.tag, $_.sample, $_.result, $_.detail) -ForegroundColor $color
}

$pass = @($results | Where-Object { $_.result -eq "PASS" }).Count
$skip = @($results | Where-Object { $_.result -eq "SKIP" }).Count
$fail = @($results | Where-Object { $_.result -ne "PASS" -and $_.result -ne "SKIP" }).Count
Write-Host ""
Write-Host ("TOTAL: {0} pass / {1} fail / {2} skip / {3} total" -f $pass, $fail, $skip, $results.Count) -ForegroundColor $(if ($fail -eq 0) {"Green"} else {"Red"})
Write-Host "日志文件: $logFile" -ForegroundColor DarkGray
Stop-Transcript | Out-Null
exit $fail
