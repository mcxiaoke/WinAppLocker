# 调试 DontSleep reflective 模式，监控 FindResourceW/LoadResource/LoadStringW
$ErrorActionPreference = 'Continue'

$exe = 'C:\Home\Projects\applocker\temp\samples\DontSleep_locked_refl.exe'
$cwd = 'C:\Home\Projects\applocker\temp\samples'
$logFile = 'C:\Home\Projects\applocker\temp\cdb_dontsleep_refl.log'
if (Test-Path $logFile) { Remove-Item $logFile }

$cdb = @(
    'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe',
    'C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe',
    'C:\Home\Develop\WinDbg\x64\cdb.exe'
) | Where-Object { Test-Path $_ } | Select-Object -First 1
Write-Host "Using cdb: $cdb"

$cmdFile = 'C:\Home\Projects\applocker\temp\cdb_dontsleep_cmds.txt'
# 注意：cdb 启动后默认停在 initial breakpoint，需要 .include / -cf 让脚本运行起来
# 用 -c "g" 让它启动后立即继续，再用 bm 在初始断点处下断+ g
# 直接用 -cf 脚本里第一个 g 即可
@'
bu kernel32!FindResourceW ".printf \"[FindResourceW] hMod=%p name=%p type=%p\n\", @rcx, @rdx, @r8; gu; .printf \"  -> ret=%p\n\", @rax; g"
bu kernel32!FindResourceExW ".printf \"[FindResourceExW] hMod=%p type=%p name=%p lang=%p\n\", @rcx, @rdx, @r8, @r9; gu; .printf \"  -> ret=%p\n\", @rax; g"
bu kernel32!LoadResource ".printf \"[LoadResource] hMod=%p hRsrc=%p\n\", @rcx, @rdx; gu; .printf \"  -> ret=%p\n\", @rax; g"
bu user32!LoadStringW ".printf \"[LoadStringW] hMod=%p id=%p buf=%p n=%p\n\", @rcx, @rdx, @r8, @r9; gu; .printf \"  -> ret=%p\n\", @rax; g"
g
'@ | Set-Content -Path $cmdFile -Encoding ASCII

# 调用 cdb：-cf 跑脚本（含末尾 g 让 debuggee 继续）
# 注意 -g 让 cdb 启动时跳过 initial breakpoint 直接继续
$p = Start-Process -FilePath $cdb -ArgumentList @(
    "-g",
    "-cf `"$cmdFile`"",
    "-logo `"$logFile`"",
    "`"$exe`""
) -WorkingDirectory $cwd -PassThru -NoNewWindow

Write-Host "cdb PID=$($p.Id), waiting 3s for password dialog..."
Start-Sleep -Seconds 3

# 输入密码
$sendPwd = @'
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class W3 {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr hWnd, EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, System.Text.StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr hWnd, System.Text.StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr hWnd, uint msg, IntPtr w, string l);
    [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr hWnd, uint msg, IntPtr w, IntPtr l);
}
"@
$BM_CLICK = 0x00F5
$WM_SETTEXT = 0x000C
$dlg = [IntPtr]::Zero
$edit = [IntPtr]::Zero
$btn = [IntPtr]::Zero
$targetPid = $args[0]
[W3]::EnumWindows({
    param($h,$l)
    $pid_ = 0
    [W3]::GetWindowThreadProcessId($h, [ref]$pid_) | Out-Null
    if ($pid_ -eq $targetPid -and [W3]::IsWindowVisible($h)) {
        $sb = New-Object System.Text.StringBuilder 256
        [W3]::GetWindowTextW($h, $sb, 256) | Out-Null
        if ($sb.ToString() -match "Password") { $script:dlg = $h; }
    }
    return $true
}, [IntPtr]::Zero) | Out-Null
if ($script:dlg -eq [IntPtr]::Zero) { Write-Host "no dlg"; exit 1 }
[W3]::EnumChildWindows($script:dlg, {
    param($h,$l)
    $cn = New-Object System.Text.StringBuilder 64
    [W3]::GetClassNameW($h, $cn, 64) | Out-Null
    if ($cn.ToString() -eq "Edit") { $script:edit = $h }
    elseif ($cn.ToString() -eq "Button") {
        $sb = New-Object System.Text.StringBuilder 64
        [W3]::GetWindowTextW($h, $sb, 64) | Out-Null
        if ($sb.ToString() -eq "OK") { $script:btn = $h }
    }
    return $true
}, [IntPtr]::Zero) | Out-Null
[W3]::SendMessageW($script:edit, $WM_SETTEXT, [IntPtr]::Zero, "hello123") | Out-Null
[W3]::SendMessageW($script:btn, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
Write-Host "pwd sent"
'@
$sendPwd | Out-File -Encoding UTF8 C:\Home\Projects\applocker\temp\send_pwd3.ps1
powershell -ExecutionPolicy Bypass -File C:\Home\Projects\applocker\temp\send_pwd3.ps1 $p.Id

Write-Host "waiting 10s for error dialog..."
Start-Sleep -Seconds 10
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
Write-Host "===== cdb log ====="
if (Test-Path $logFile) {
    Get-Content $logFile | Select-String -Pattern "FindResource|LoadResource|LoadString|Language|string archive|AAAA_UNICODE" | Select-Object -First 50
}