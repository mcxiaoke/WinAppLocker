# dump_stub_data.ps1 - find and dump stub_data in a packed PE
# Usage: powershell -File dump_stub_data.ps1 <locked.exe> [offset]

param(
    [Parameter(Mandatory=$true)]
    [string]$File,

    [int]$Offset = -1
)

if (-not (Test-Path $File)) {
    Write-Host "File not found: $File" -ForegroundColor Red
    exit 1
}

$bytes = [System.IO.File]::ReadAllBytes($File)
Write-Host ("File size: 0x{0:X} ({1} bytes)" -f $bytes.Length, $bytes.Length)

# STUB_DATA_MAGIC = 0x214B434F4C4E4957 ("WINLOCK!" little-endian)
$magic = [byte[]](0x57,0x49,0x4E,0x4C,0x4F,0x43,0x4B,0x21)

$found = @()
for ($i = 0; $i -le $bytes.Length - 8; $i++) {
    $match = $true
    for ($j = 0; $j -lt 8; $j++) {
        if ($bytes[$i + $j] -ne $magic[$j]) { $match = $false; break }
    }
    if ($match) { $found += $i }
}

Write-Host ""
Write-Host ("STUB_DATA_MAGIC found at {0} locations:" -f $found.Count)
foreach ($off in $found) {
    Write-Host ("  - 0x{0:X}" -f $off)
}

if ($Offset -ge 0) {
    $dumpOff = $Offset
} elseif ($found.Count -gt 0) {
    $dumpOff = $found[-1]
} else {
    $dumpOff = -1
}

if ($dumpOff -lt 0) {
    Write-Host "No stub_data found." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host ("Dumping stub_data at offset 0x{0:X}:" -f $dumpOff) -ForegroundColor Green

$sd = $bytes[$dumpOff..($dumpOff + 248)]

# hex+ascii dump, 16 bytes per row
for ($row = 0; $row -lt 16; $row++) {
    $base = $row * 16
    $hexPart = ""
    $asciiPart = ""
    for ($col = 0; $col -lt 16; $col++) {
        $b = $sd[$base + $col]
        $hexPart += ("{0:X2} " -f $b)
        if (($b -ge 32) -and ($b -lt 127)) {
            $asciiPart += [char]$b
        } else {
            $asciiPart += "."
        }
    }
    Write-Host ("  +0x{0:X4}: {1}| {2}" -f $base, $hexPart, $asciiPart)
}

# parse stub_data fields per config.h
Write-Host ""
Write-Host "Parsed fields:" -ForegroundColor Cyan
Write-Host ("  magic        = 0x{0:X16}" -f [BitConverter]::ToUInt64($sd, 0))
Write-Host ("  version      = {0}" -f [BitConverter]::ToUInt16($sd, 8))
Write-Host ("  flags        = 0x{0:X4}" -f [BitConverter]::ToUInt16($sd, 10))
Write-Host ("  max_retries  = {0}" -f [BitConverter]::ToUInt16($sd, 12))
Write-Host ("  reserved16   = 0x{0:X4}" -f [BitConverter]::ToUInt16($sd, 14))
Write-Host ("  oep_rva      = 0x{0:X16}" -f [BitConverter]::ToUInt64($sd, 16))
Write-Host ("  text_rva     = 0x{0:X16}" -f [BitConverter]::ToUInt64($sd, 24))
Write-Host ("  text_size    = 0x{0:X16}" -f [BitConverter]::ToUInt64($sd, 32))
Write-Host ("  text_raw_size= 0x{0:X8}" -f [BitConverter]::ToUInt32($sd, 40))
Write-Host ("  text_protect = 0x{0:X8}" -f [BitConverter]::ToUInt32($sd, 44))
Write-Host ("  xtea_key[0]  = 0x{0:X8}" -f [BitConverter]::ToUInt32($sd, 48))
Write-Host ("  xtea_key[1]  = 0x{0:X8}" -f [BitConverter]::ToUInt32($sd, 52))
Write-Host ("  xtea_key[2]  = 0x{0:X8}" -f [BitConverter]::ToUInt32($sd, 56))
Write-Host ("  xtea_key[3]  = 0x{0:X8}" -f [BitConverter]::ToUInt32($sd, 60))

$saltHex = ""
for ($i = 0; $i -lt 16; $i++) { $saltHex += ("{0:X2} " -f $sd[64 + $i]) }
Write-Host ("  salt[16]     = {0}" -f $saltHex)

$hashHex = ""
for ($i = 0; $i -lt 32; $i++) { $hashHex += ("{0:X2} " -f $sd[80 + $i]) }
Write-Host ("  pwd_hash[32] = {0}" -f $hashHex)

$pwdStr = [System.Text.Encoding]::Unicode.GetString($sd, 112, 128).TrimEnd([char]0)
Write-Host ("  password     = '{0}'" -f $pwdStr)

Write-Host ("  checksum     = 0x{0:X16}" -f [BitConverter]::ToUInt64($sd, 240))
