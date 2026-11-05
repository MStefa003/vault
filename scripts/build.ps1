# Build the release binary into dist\VaultRust.exe, then delete cargo's
# build cache (target\), which is several hundred MB to over 1 GB.
#
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -KeepCache

param([switch]$KeepCache)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force dist | Out-Null
Copy-Item target\release\vaultrust.exe dist\VaultRust.exe -Force
$mb = (Get-Item dist\VaultRust.exe).Length / 1MB
Write-Host ("dist\VaultRust.exe  {0:N1} MB" -f $mb)

if (-not $KeepCache) {
    cargo clean
    Write-Host "Build cache removed."
}
