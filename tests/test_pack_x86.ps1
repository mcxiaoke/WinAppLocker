$ErrorActionPreference = "Continue"
$env:Path = "C:\Home\Develop\w64devkit\bin;$env:Path"
Set-Location F:\Temp\pe\winlock

Write-Host "=== Pack helloguix86.exe (test mode) ==="
& builder\builder.exe -i F:\Temp\pe\samples\helloguix86.exe -o F:\Temp\pe\samples\helloguix86_locked.exe -t 2>&1
Write-Host "builder exit: $LASTEXITCODE"
