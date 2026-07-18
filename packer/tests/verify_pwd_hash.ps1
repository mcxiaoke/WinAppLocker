# verify_pwd_hash.ps1 - verify pwd_hash = SHA-256(utf8(pwd) + salt)
# Usage: powershell -File verify_pwd_hash.ps1 <password> <salt_hex> <expected_hash_hex>

param(
    [Parameter(Mandatory=$true)]
    [string]$Password,

    [Parameter(Mandatory=$true)]
    [string]$SaltHex,

    [string]$ExpectedHashHex = ""
)

# parse salt hex (space or no space separated)
$saltHex = $SaltHex -replace '\s', ''
if ($saltHex.Length % 2 -ne 0) {
    Write-Host "Salt hex length must be even" -ForegroundColor Red
    exit 1
}
$salt = [byte[]]::new($saltHex.Length / 2)
for ($i = 0; $i -lt $salt.Length; $i++) {
    $salt[$i] = [Convert]::ToByte($saltHex.Substring($i * 2, 2), 16)
}

# utf8 encode password
$pwdUtf8 = [System.Text.Encoding]::UTF8.GetBytes($Password)

Write-Host ("Password:    '{0}'" -f $Password)
Write-Host ("UTF8 bytes:  ({0} bytes) {1}" -f $pwdUtf8.Length, (($pwdUtf8 | ForEach-Object { $_.ToString("X2") }) -join " "))
Write-Host ("Salt:        ({0} bytes) {1}" -f $salt.Length, (($salt | ForEach-Object { $_.ToString("X2") }) -join " "))

# SHA-256(pwd_utf8 + salt)
$input = New-Object byte[] ($pwdUtf8.Length + $salt.Length)
[Array]::Copy($pwdUtf8, 0, $input, 0, $pwdUtf8.Length)
[Array]::Copy($salt, 0, $input, $pwdUtf8.Length, $salt.Length)

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hash = $sha256.ComputeHash($input)
$hashHex = (($hash | ForEach-Object { $_.ToString("X2") }) -join "").ToUpper()
$hashHexSpaced = (($hash | ForEach-Object { $_.ToString("X2") }) -join " ").ToUpper()

Write-Host ("Computed:    {0}" -f $hashHexSpaced)
Write-Host ("Computed(no space): {0}" -f $hashHex)

if ($ExpectedHashHex -ne "") {
    $expHex = ($ExpectedHashHex -replace '\s', '').ToUpper()
    Write-Host ("Expected:    {0}" -f $expHex)
    if ($hashHex -eq $expHex) {
        Write-Host "MATCH!" -ForegroundColor Green
    } else {
        Write-Host "MISMATCH!" -ForegroundColor Red
    }
}
