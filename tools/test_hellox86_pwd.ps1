$ErrorActionPreference = "Continue"
$env:Path = "C:\Home\Develop\w64devkit\bin;$env:Path"
Set-Location F:\Temp\pe\winlock

Write-Host "=== Pack hellox86.exe (x86 + TLS_PROXY + password mode) ==="
& builder\builder.exe -i F:\Temp\pe\samples\hellox86.exe -o F:\Temp\pe\samples\hellox86_locked.exe -p test 2>&1 | Select-Object -Last 4
Write-Host "builder exit: $LASTEXITCODE"

Write-Host ""
Set-Location F:\Temp\pe\samples
Write-Host "=== Run hellox86_locked.exe ==="
$p = Start-Process -FilePath ".\hellox86_locked.exe" -PassThru
Start-Sleep -Seconds 2

Write-Host "Sending password 'test'..."
& powershell -ExecutionPolicy Bypass -File F:\Temp\pe\winlock\tools\input_password.ps1 -Password test -Timeout 8

Start-Sleep -Seconds 3
if ($p.HasExited) {
    Write-Host "Process exited with code: $($p.ExitCode)"
} else {
    Write-Host "Process still running - MessageBox shown (success). Killing..."
    Stop-Process -Id $p.Id -Force
}
