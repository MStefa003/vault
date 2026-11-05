# Full quality and supply-chain gate for VaultRust.
#   powershell -ExecutionPolicy Bypass -File scripts\audit.ps1
# Requires: cargo-audit, cargo-deny (cargo install cargo-audit cargo-deny --locked)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

function Step($name, [scriptblock]$cmd) {
    Write-Host "`n==> $name" -ForegroundColor Cyan
    & $cmd
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $name" -ForegroundColor Red; exit 1 }
}

Step "cargo fmt --check" { cargo fmt --all -- --check }
Step "cargo clippy (deny warnings)" { cargo clippy --all-targets -- -D warnings }
Step "cargo test" { cargo test }
Step "cargo deny check" { cargo deny check }
Step "cargo audit" { cargo audit }

# Network isolation: list every crate compiled into the Windows binary and
# fail on anything that looks like networking. `url` and `webbrowser` are
# expected (pulled in by egui-winit for hyperlinks; neither opens sockets,
# and VaultRust strips every open-URL command each frame).
Step "network crate scan" {
    $crates = cargo tree -e normal --target x86_64-pc-windows-msvc --prefix none --format "{p}" |
        ForEach-Object { ($_ -split ' ')[0] } | Sort-Object -Unique
    $pattern = '^(reqwest|hyper.*|h2|h3|ureq|curl.*|isahc|surf|attohttpc|minreq|http|http-body.*|tower.*|rustls.*|native-tls|openssl.*|socket2|mio|tokio.*|async-std|smol|.*dns.*|tungstenite|quinn.*|sentry.*|opentelemetry.*|self_update)$'
    $hits = $crates | Where-Object { $_ -match $pattern }
    Write-Host "$($crates.Count) crates in the shipped Windows dependency graph."
    if ($hits) { Write-Host "Networking crates found: $($hits -join ', ')" -ForegroundColor Red; $global:LASTEXITCODE = 1 }
    else { Write-Host "No networking crates found."; $global:LASTEXITCODE = 0 }
}

Write-Host "`nAll checks passed." -ForegroundColor Green
