$ErrorActionPreference = "Continue"
$env:Path = "C:\Home\Develop\w64devkit\bin;$env:Path"
Set-Location F:\Temp\pe\winlock

Write-Host "=== Build builder ==="
& gcc -Wall -Wextra -O2 builder/builder.c -o builder/builder.exe -ladvapi32 2>&1
Write-Host "exit: $LASTEXITCODE"
