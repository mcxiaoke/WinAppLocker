$ErrorActionPreference = "Continue"
Set-Location F:\Temp\pe\winlock
$gcc = "C:\Home\Develop\msys64\mingw32\bin\gcc.exe"

Write-Host "=== Compile with -v ==="
$proc = Start-Process -FilePath $gcc -ArgumentList "-v -Wall -Wextra -Wno-cast-function-type -O2 -ffreestanding -fno-stack-protector -fno-pic -fno-pie -fno-asynchronous-unwind-tables -fno-exceptions -fno-ident -mno-sse -mno-sse2 -DWINLOCK_STUB -c stub/stub.c -o stub/stub_x86.o" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "F:\Temp\pe\winlock\gcc_v_out.txt" -RedirectStandardError "F:\Temp\pe\winlock\gcc_v_err.txt"
Write-Host "exit code: $($proc.ExitCode)"
Write-Host "--- stderr (last 50 lines) ---"
Get-Content "F:\Temp\pe\winlock\gcc_v_err.txt" -ErrorAction SilentlyContinue | Select-Object -Last 50
