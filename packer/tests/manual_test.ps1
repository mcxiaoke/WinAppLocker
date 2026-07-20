<#
.SYNOPSIS
    WinLock manual test script - pack samples and let user input password manually.

.DESCRIPTION
    Packs 4 GUI samples from ..\samples, then launches each packed exe and lets
    the user manually input the password in the dialog. Results and logs are
    written to winlock\temp\manual_test_<timestamp>.log.

    Packed outputs go to the SAME directory as the input sample (..\samples),
    so same-directory dependencies (e.g. Notepad4.ini) are preserved.

.PARAMETER Samples
    Sample file names to test (default: all 4).

.PARAMETER Password
    Packing password (default hello123). The script prints it so you can type it.

.PARAMETER NoRun
    Only pack, do not launch.

.EXAMPLE
    .\tests\manual_test.ps1
    .\tests\manual_test.ps1 -Samples helloguix64.exe -Password mypass
    .\tests\manual_test.ps1 -NoRun
#>
[CmdletBinding()]
param(
    [string[]]$Samples = @("helloguix64.exe","helloguix86.exe","DontSleep.exe","Notepad4.exe"),
    [string]$Password = "hello123",
    [switch]$NoRun,
    [switch]$Reflective
)

$ErrorActionPreference = 'Continue'

# ---- Paths ----
# 脚本位于 applocker/packer/tests/manual_test.ps1
# applocker 根 = packer/.. ；samples 在 applocker/temp/samples；产物在 packer/dist
$AppRoot  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # applocker\
$DistDir  = Join-Path $AppRoot "packer\dist"                          # 产物目录
$SampleDir = Join-Path $AppRoot "temp\samples"                       # 样本目录
$TEMP     = Join-Path $AppRoot "temp"                                # 日志/临时

# 按模式选 builder（默认 inplace，-Reflective 用反射式）
$BuilderName = if ($Reflective) { "builder_reflective.exe" } else { "builder_inplace.exe" }
$BUILDER = Join-Path $DistDir $BuilderName

if (-not (Test-Path $SampleDir)) {
    Write-Host "ERROR: samples dir not found: $SampleDir" -ForegroundColor Red
    exit 1
}
$SampleDir = (Resolve-Path $SampleDir).Path
if (-not (Test-Path $TEMP)) { New-Item -ItemType Directory -Path $TEMP | Out-Null }

# ---- Log ----
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile  = Join-Path $TEMP "manual_test_$timestamp.log"

function Log {
    param([string]$Msg, [string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "HH:mm:ss"), $Level, $Msg
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

# ---- Pre-checks ----
Log "===== WinLock manual test start ====="
Log "Timestamp  : $timestamp"
Log "Builder    : $BUILDER"
Log "Samples dir: $SampleDir"
Log "Temp/Log   : $TEMP"
Log "Password   : $Password  (script will print it, type it into the dialog)"
Log "Samples    : $($Samples -join ', ')"
Log ""

if (-not (Test-Path $BUILDER)) {
    Log "ERROR: builder.exe not found, run 'make' first" "ERROR"
    exit 1
}

# Check KdDebuggerEnabled (anti-debug will fire if kernel debug is on)
$ptr = [IntPtr]0x7FFE02D4
$kdDbg = [System.Runtime.InteropServices.Marshal]::ReadByte($ptr)
Log "KdDebuggerEnabled (0x7FFE02D4) = $kdDbg"
if ($kdDbg -ne 0) {
    Log "WARNING: kernel debug is ON, anti-debug will kill every packed sample!" "WARN"
    Log "         Fix with: bcdedit /set debug off  (then reboot)" "WARN"
}
Log ""

# ---- Results ----
$Results = @()

foreach ($sample in $Samples) {
    $inPath  = Join-Path $SampleDir $sample
    $outName = [System.IO.Path]::GetFileNameWithoutExtension($sample) + "_locked.exe"
    $outPath = Join-Path $SampleDir $outName

    Log "----- $sample -----"
    if (-not (Test-Path $inPath)) {
        Log "  sample not found, skip" "ERROR"
        $Results += [pscustomobject]@{ Sample=$sample; Pack="SKIP"; Run="N/A"; ExitCode="N/A"; Note="sample missing" }
        continue
    }

    # 1. Pack (use -p to set the password, NOT -t test mode)
    #    inplace:  builder_inplace.exe    -i <in> -o <out> -p <pwd>
    #    reflective: builder_reflective.exe <in> <out> -p <pwd>
    #    WorkingDirectory 设为 dist/，让 builder 能在当前目录找到 stub
    $origWD = (Get-Location).Path
    try {
        Set-Location $DistDir
        if ($Reflective) {
            Log "  packing: builder_reflective `"$inPath`" `"$outPath`" -p `"$Password`" (cwd=$DistDir)"
            $packOut = & $BUILDER $inPath $outPath -p $Password 2>&1
        } else {
            Log "  packing: builder_inplace -i `"$inPath`" -o `"$outPath`" -p `"$Password`" (cwd=$DistDir)"
            $packOut = & $BUILDER -i $inPath -o $outPath -p $Password 2>&1
        }
        $packRc = $LASTEXITCODE
    } finally {
        Set-Location $origWD
    }
    # Print key lines only
    $packOut | Where-Object { $_ -match "Security|flags|EP RVA|Run |Password|TLS|\[\+\]|\[\-\]|\[\*\]" } |
              ForEach-Object { Log "    $_" }
    if ($packRc -ne 0 -or -not (Test-Path $outPath)) {
        Log "  pack FAILED (rc=$packRc)" "ERROR"
        $Results += [pscustomobject]@{ Sample=$sample; Pack="FAIL"; Run="N/A"; ExitCode="N/A"; Note="pack rc=$packRc" }
        continue
    }
    Log "  pack OK -> $outName ($((Get-Item $outPath).Length) bytes)"

    if ($NoRun) {
        $Results += [pscustomobject]@{ Sample=$sample; Pack="OK"; Run="SKIP"; ExitCode="N/A"; Note="NoRun" }
        continue
    }

    # 2. Launch packed exe (GUI, user inputs password manually)
    Log "  launching packed sample (type password: $Password)"
    Log "  >>> press Enter to launch $outName ..."
    Read-Host | Out-Null
    $p = Start-Process -FilePath $outPath -PassThru
    Log "  launched PID=$($p.Id), waiting for exit (GUI may run a long time)"
    Log "  >>> close the app window when done testing, or press Ctrl+C in this shell"

    $waited = 0
    while (-not $p.HasExited) {
        Start-Sleep -Milliseconds 500
        $waited += 500
        if ($waited % 10000 -eq 0) {
            Log "  still running (${waited} ms) ..."
        }
    }
    $exitCode = $p.ExitCode
    Log "  exited code=$exitCode (ran ${waited} ms)"

    $note = switch ($exitCode) {
        0 { "normal exit" }
        1 { "user Cancel" }
        2 { "password error limit / stub fail" }
        default { "other ($exitCode)" }
    }
    $Results += [pscustomobject]@{ Sample=$sample; Pack="OK"; Run="OK"; ExitCode=$exitCode; Note=$note }
    Log ""
}

# ---- Summary ----
Log "===== Summary ====="
$Results | Format-Table -AutoSize | Out-String | ForEach-Object { Log $_ }
Log ""
Log "Log file: $LogFile"
Log "===== test end ====="

Write-Host ""
Write-Host "Log written to: $LogFile" -ForegroundColor Cyan
