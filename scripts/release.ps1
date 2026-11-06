# Publish a new VaultRust release.
#   powershell -ExecutionPolicy Bypass -File scripts\release.ps1 0.2.0
#
# Sets the version in Cargo.toml, commits, tags v<version> and pushes. The
# Release workflow on GitHub then builds, signs and publishes it, and
# installed copies offer the update within a day (or at "Check now").

param([Parameter(Mandatory = $true)][string]$Version)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version must look like 1.2.3" }
if (git status --porcelain) { throw "Commit or stash your changes first." }
$current = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
if ([version]$Version -le [version]$current) { throw "New version $Version must be higher than $current" }

# The notes come from CHANGELOG.md: "## Unreleased" becomes this version.
$log = [IO.File]::ReadAllText((Resolve-Path CHANGELOG.md))
$m = [regex]::Match($log, "(?ms)^## Unreleased[^\n]*\n(.*?)(?=^## |\z)")
if (-not $m.Success -or -not $m.Groups[1].Value.Trim()) { throw "Write what's new under '## Unreleased' in CHANGELOG.md first." }
$date = Get-Date -Format "yyyy-MM-dd"
$log = $log.Remove($m.Index, $m.Length).Insert($m.Index, "## Unreleased`n`n## $Version $([char]0x2014) $date`n$($m.Groups[1].Value)")
[IO.File]::WriteAllText((Resolve-Path CHANGELOG.md), $log, (New-Object Text.UTF8Encoding $false))

$toml = Get-Content Cargo.toml -Raw
$toml = $toml -replace "(?m)^version = `"$([regex]::Escape($current))`"", "version = `"$Version`""
[IO.File]::WriteAllText((Resolve-Path Cargo.toml), $toml)
cargo update --workspace --offline | Out-Null

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "Release v$Version"
git tag "v$Version"
git push origin HEAD "v$Version"
Write-Host "Pushed v$Version. Follow the build at https://github.com/MStefa003/vault/actions" -ForegroundColor Green
