$ErrorActionPreference = "Continue"
Set-Location F:\Temp\pe\samples

Write-Host "=== Run helloguix86_locked.exe (password mode) ==="
$p = Start-Process -FilePath ".\helloguix86_locked.exe" -PassThru
Write-Host "Started PID: $($p.Id)"

Write-Host "Waiting 2s for dialog to appear..."
Start-Sleep -Seconds 2

Write-Host "Sending password 'test'..."
& powershell -ExecutionPolicy Bypass -File F:\Temp\pe\winlock\tools\input_password.ps1 -Password test -Timeout 8

Write-Host ""
Write-Host "Waiting 4s for program to launch..."
Start-Sleep -Seconds 4

if ($p.HasExited) {
    Write-Host "Process exited with code: $($p.ExitCode)"
} else {
    Write-Host "Process still running - GUI launched successfully!"
    Stop-Process -Id $p.Id -Force
    Write-Host "Killed."
}
