# test_apps_batch.ps1 - 批量加壳测试：加壳 + 启动 + 自动输入密码 + 检查主程序是否启动
# 改进：等待时间加长 + 枚举子进程窗口

$ErrorActionPreference = "Continue"
$builder = "F:\Temp\pe\winlock\builder\builder.exe"
$password = "test"

$samples = @(
    @{ Name="avidemux";  Exe="C:\Home\Apps\Avidemux\avidemux.exe" },
    @{ Name="Doubao";     Exe="C:\Home\Apps\Doubao\Doubao.exe" },
    @{ Name="HeidiSQL";   Exe="C:\Home\Apps\HeidiSQL\heidisql.exe" },
    @{ Name="MPC-BE";     Exe="C:\Home\Apps\MPC-BE\mpc-be64.exe" },
    @{ Name="NTLite";     Exe="C:\Home\Apps\NTLite\NTLite.exe" },
    @{ Name="Quark";      Exe="C:\Home\Apps\Quark\quark.exe" },
    @{ Name="Shotcut";    Exe="C:\Home\Apps\Shotcut\shotcut.exe" },
    @{ Name="Wireshark";  Exe="C:\Home\Apps\Wireshark\Wireshark.exe" },
    @{ Name="XnViewMP";   Exe="C:\Home\Apps\XnViewMP\xnviewmp.exe" },
    @{ Name="totalcmd";   Exe="C:\Home\Apps\totalcmd\tcrun64.exe" }
)

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class WLTest {
    public delegate bool EnumTopProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumTopProc cb, IntPtr lp);
    [DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);

    public static List<string> VisibleWindowsOfPID(uint pid) {
        List<string> result = new List<string>();
        EnumTopProc cb = (h, lp) => {
            uint wpid;
            GetWindowThreadProcessId(h, out wpid);
            if (wpid == pid && IsWindowVisible(h)) {
                int len = GetWindowTextLength(h);
                StringBuilder txt = new StringBuilder(Math.Max(64, len + 2));
                GetWindowText(h, txt, txt.Capacity);
                StringBuilder cls = new StringBuilder(64);
                GetClassName(h, cls, 64);
                if (txt.ToString() != "" || cls.ToString() != "") {
                    result.Add(string.Format("cls={0} txt='{1}'", cls, txt));
                }
            }
            return true;
        };
        EnumWindows(cb, IntPtr.Zero);
        return result;
    }

    // 枚举所有可见窗口（不按 PID 过滤），返回 pid -> List<string>
    public static Dictionary<uint, List<string>> AllVisibleWindows() {
        Dictionary<uint, List<string>> map = new Dictionary<uint, List<string>>();
        EnumTopProc cb = (h, lp) => {
            if (!IsWindowVisible(h)) return true;
            int len = GetWindowTextLength(h);
            StringBuilder txt = new StringBuilder(Math.Max(64, len + 2));
            GetWindowText(h, txt, txt.Capacity);
            StringBuilder cls = new StringBuilder(64);
            GetClassName(h, cls, 64);
            if (txt.ToString() == "" && cls.ToString() == "") return true;
            if (txt.ToString() == "WinLock - Password Required") return true;
            uint pid;
            GetWindowThreadProcessId(h, out pid);
            if (!map.ContainsKey(pid)) map[pid] = new List<string>();
            map[pid].Add(string.Format("cls={0} txt='{1}'", cls, txt));
            return true;
        };
        EnumWindows(cb, IntPtr.Zero);
        return map;
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
    # 反向杀（子进程先杀）
    $rev = $all[-1..-($all.Count)]
    foreach ($p in $rev) {
        try { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue } catch {}
    }
}

function Stop-AppByName($name) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-AppTree $_.Id
    }
    Start-Sleep -Milliseconds 500
}

$results = @()

foreach ($s in $samples) {
    $name = $s.Name
    $exe = $s.Exe
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ("[{0}] {1}" -f $name, $exe) -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan

    if (-not (Test-Path $exe)) {
        Write-Host "[SKIP] exe not found" -ForegroundColor Yellow
        $results += [pscustomobject]@{ Name=$name; Result="SKIP"; Reason="exe not found" }
        continue
    }

    $outExe = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($exe),
                                         [System.IO.Path]::GetFileNameWithoutExtension($exe) + "_locked.exe")

    Remove-Item $outExe -ErrorAction SilentlyContinue
    Stop-AppByName ([System.IO.Path]::GetFileNameWithoutExtension($exe))

    # 1. 加壳
    Write-Host "[1] Packing..."
    $packOut = & $builder -i $exe -o $outExe -p $password 2>&1
    $packExit = $LASTEXITCODE
    if ($packExit -ne 0 -or -not (Test-Path $outExe)) {
        Write-Host "[FAIL] pack failed (exit=$packExit)" -ForegroundColor Red
        $packOut | Select-Object -Last 3 | ForEach-Object { Write-Host "    $_" }
        $results += [pscustomobject]@{ Name=$name; Result="PACK_FAIL"; Reason="exit=$packExit" }
        continue
    }
    $sizeKB = [math]::Round((Get-Item $outExe).Length / 1KB)
    Write-Host "[OK] packed: $outExe ($sizeKB KB)"

    # 2. 启动加壳后 exe（设置工作目录到 exe 所在目录，避免依赖 DLL 找不到）
    Write-Host "[2] Launching..."
    $workDir = [System.IO.Path]::GetDirectoryName($exe)
    $proc = $null
    try {
        $proc = Start-Process -FilePath $outExe -PassThru -WorkingDirectory $workDir -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] launch failed: $($_.Exception.Message)" -ForegroundColor Red
        $results += [pscustomobject]@{ Name=$name; Result="LAUNCH_FAIL"; Reason=$_.Exception.Message }
        continue
    }
    Write-Host ("[OK] PID={0}" -f $proc.Id)
    Start-Sleep -Seconds 3

    # 3. 输入密码
    Write-Host "[3] Sending password..."
    $pwOut = & powershell -ExecutionPolicy Bypass -File F:\Temp\pe\winlock\tools\input_password.ps1 -Password $password -Timeout 15 2>&1
    $pwExit = $LASTEXITCODE
    $pwOut | ForEach-Object { Write-Host "    $_" }

    if ($pwExit -ne 0) {
        Write-Host "[FAIL] password dialog or button not found (exit=$pwExit)" -ForegroundColor Red
        if (-not $proc.HasExited) { Stop-AppTree $proc.Id }
        $results += [pscustomobject]@{ Name=$name; Result="PWD_FAIL"; Reason="pw exit=$pwExit" }
        continue
    }

    # 4. 等待主程序启动（轮询 12 秒）
    Write-Host "[4] Waiting for main app window (up to 15s)..."
    $mainWindows = @()
    $rootPid = $proc.Id
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        if ($proc.HasExited) {
            Write-Host ("[FAIL] process exited with code {0}" -f $proc.ExitCode) -ForegroundColor Red
            break
        }
        # 枚举进程树的所有窗口
        $allPids = Get-DescendantPids $rootPid
        $allMap = [WLTest]::AllVisibleWindows()
        $mainWindows = @()
        foreach ($p in $allPids) {
            $uintPid = [uint32]$p
            if ($allMap.ContainsKey($uintPid)) {
                $mainWindows += $allMap[$uintPid]
            }
        }
        if ($mainWindows.Count -gt 0) {
            Start-Sleep -Seconds 1  # 让窗口稳定
            break
        }
    }

    if ($proc.HasExited) {
        $results += [pscustomobject]@{ Name=$name; Result="CRASH"; Reason="exit code $($proc.ExitCode)" }
        continue
    }

    # 再枚举一次最终状态
    $allPids = Get-DescendantPids $rootPid
    $allMap = [WLTest]::AllVisibleWindows()
    $mainWindows = @()
    foreach ($p in $allPids) {
        $uintPid = [uint32]$p
        if ($allMap.ContainsKey($uintPid)) {
            $mainWindows += $allMap[$uintPid]
        }
    }

    Write-Host ("[OK] {0} visible windows across {1} processes in tree:" -f $mainWindows.Count, $allPids.Count)
    foreach ($w in $mainWindows | Select-Object -First 3) {
        Write-Host ("    {0}" -f $w)
    }

    # 5. 杀掉整个进程树
    Stop-AppTree $rootPid
    Start-Sleep -Milliseconds 500

    if ($mainWindows.Count -gt 0) {
        Write-Host "[OK] SUCCESS - main window detected" -ForegroundColor Green
        $results += [pscustomobject]@{ Name=$name; Result="OK"; Reason="$($mainWindows.Count) windows" }
    } else {
        Write-Host "[WARN] no visible window found (may be CLI or delayed startup)" -ForegroundColor Yellow
        $results += [pscustomobject]@{ Name=$name; Result="NO_WINDOW"; Reason="process running but no window" }
    }
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
$results | Format-Table -AutoSize
