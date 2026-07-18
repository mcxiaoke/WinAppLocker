$ErrorActionPreference = "Continue"
$env:Path = "C:\Home\Develop\w64devkit\bin;$env:Path"
Set-Location F:\Temp\pe\winlock

Write-Host "=== Pack hellox86.exe (mingw32 x86, test mode) ==="
& builder\builder.exe -i F:\Temp\pe\samples\hellox86.exe -o F:\Temp\pe\samples\hellox86_locked.exe -t 2>&1 | Select-Object -Last 6
Write-Host "builder exit: $LASTEXITCODE"

Write-Host ""
Write-Host "=== Run hellox86_locked.exe ==="
$p = Start-Process -FilePath "F:\Temp\pe\samples\hellox86_locked.exe" -PassThru
Start-Sleep -Seconds 3

if ($p.HasExited) {
    Write-Host "Process exited with code: $($p.ExitCode)"
} else {
    Write-Host "Process running - MessageBox likely shown. Killing..."
    Stop-Process -Id $p.Id -Force
}
