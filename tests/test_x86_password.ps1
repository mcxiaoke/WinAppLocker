$ErrorActionPreference = "Continue"
Set-Location F:\Temp\pe\samples

Write-Host "=== Run helloguix86_locked.exe (password mode) ==="
Write-Host "Starting process, waiting 3s..."
$p = Start-Process -FilePath ".\helloguix86_locked.exe" -PassThru
Start-Sleep -Seconds 3

if ($p.HasExited) {
    Write-Host "Process exited early with code: $($p.ExitCode) (stub may have crashed)"
} else {
    Write-Host "Process running. Looking for password dialog..."
    
    Add-Type -AssemblyName UIAutomationClient
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty,
        "WinLock - Password Required")
    $dialog = $root.FindFirst(
        [System.Windows.Automation.TreeScope]::Children,
        $condition)
    
    if ($dialog) {
        Write-Host "SUCCESS: Password dialog found!"
        # 找到编辑框并输入密码
        $editCond = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Edit)
        $edit = $dialog.FindFirst(
            [System.Windows.Automation.TreeScope]::Descendants,
            $editCond)
        if ($edit) {
            $valuePattern = $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
            $valuePattern.SetValue("test")
            Write-Host "Password entered."
            
            # 找 OK 按钮并点击
            $btnCond = New-Object System.Windows.Automation.PropertyCondition(
                [System.Windows.Automation.AutomationElement]::NameProperty,
                "OK")
            $btn = $dialog.FindFirst(
                [System.Windows.Automation.TreeScope]::Descendants,
                $btnCond)
            if ($btn) {
                $invokePattern = $btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
                $invokePattern.Invoke()
                Write-Host "OK clicked."
                Start-Sleep -Seconds 3
                if ($p.HasExited) {
                    Write-Host "Process exited after OK with code: $($p.ExitCode)"
                } else {
                    Write-Host "Process still running after OK (program launched successfully)"
                    Stop-Process -Id $p.Id -Force
                }
            }
        }
    } else {
        Write-Host "No password dialog found. Killing process."
        Stop-Process -Id $p.Id -Force
    }
}
