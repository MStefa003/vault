# VaultRust

A strictly local, offline password safe for Windows, written entirely in Rust.

* **One encrypted file.** Your vault is a single `.vault` file stored wherever
  you choose. No database, no cloud, no account, no telemetry, no network code.
* **Modern cryptography.** Argon2id key derivation, XChaCha20-Poly1305
  authenticated encryption, a random 256-bit vault key, OS-provided randomness
  and memory wiping on lock. See [docs/SECURITY.md](docs/SECURITY.md).
* **Native UI.** egui/eframe; no web view, HTML or JavaScript.

## Features

* Logins, email accounts, secure notes, credit cards, identities, API keys,
  servers, databases, Wi-Fi networks and fully custom items with your own
  fields
* Password generator (length, character sets, ambiguous-character exclusion,
  custom characters) and passphrase generator, with entropy estimates
* Security center: weak, reused and old passwords
* Automatic lock after inactivity, manual lock (Ctrl+L), lock on minimize
* Window hidden from screenshots and screen sharing while unlocked; revealed
  secrets re-masked automatically; growing delay after wrong passwords
* Never silently overwrites changes made to the vault file by another window
  or program
* Keyboard shortcuts: Ctrl+F search, Ctrl+N new item, Ctrl+S save, Esc cancel;
  right-click an item to copy its username or password
* Concealed fields with explicit reveal; copy with automatic clipboard clearing
  (excluded from Windows clipboard history and cloud sync)
* Create, open, rename and move vaults; verified encrypted backups and restore
* Import from CSV (Chrome, Edge, Firefox, Bitwarden, LastPass, 1Password,
  KeePass, …) and Bitwarden JSON; plaintext CSV export behind explicit warnings
* Crash-safe atomic saves; never overwrites a file without confirmation

## Build and run

Requires a Rust toolchain (1.90 or newer) with the MSVC target and the Visual
Studio C++ build tools.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
.\dist\VaultRust.exe
```

This builds the release executable (about 5 MB), copies it to `dist\` and
then deletes cargo's build cache in `target\`, which otherwise takes 0.5–1 GB.
Pass `-KeepCache` to keep it for faster rebuilds.

The release build is a GUI-only executable (no console window). Moving the
vault to another computer is just copying the `.vault` file; VaultRust itself
is a single `.exe` with no installer.

To try the UI with fictional sample data:

```powershell
cargo run --release --example demo_vault -- "$env:TEMP\Demo.vault" "demo master password"
```

## Backups are your responsibility

VaultRust never uploads or syncs anything, so it cannot recover your data for
you. Use **Settings → Create encrypted backup** regularly and keep copies on a
separate drive. There is no master password recovery: if you forget it, the
vault cannot be opened.

## Testing and auditing

```powershell
cargo test                                             # unit, integration and headless UI tests
powershell -ExecutionPolicy Bypass -File scripts\audit.ps1   # fmt, clippy, test, deny, audit, network scan
```

The tests cover vault creation, correct/incorrect passwords, encryption
round-trips, tamper detection (every header byte, sampled payload bytes,
truncation, payload swapping), interrupted writes, backup verification and
restore, master password changes (payload unchanged), nonce uniqueness,
persistence of every field type, automatic locking, zeroization, and
inspection of the raw vault file for plaintext leaks. Headless UI tests
(`egui_kittest`) render every screen and exercise unlocking, locking and
creating items.

To render every screen to PNG for visual review:

```powershell
$env:VAULTRUST_SCREENSHOT_DIR = "$env:TEMP\vaultrust-shots"
cargo test --lib render_screenshots -- --ignored
```

## Project layout

```text
src/
  crypto.rs         Argon2id, XChaCha20-Poly1305, CSPRNG, key wrapping
  format.rs         versioned binary file format, bounded parser, AAD
  storage.rs        atomic writes, no-overwrite moves, temp-file cleanup
  vault.rs          create / open / save / change password / backup / restore
  model.rs          entry types and fields (zeroized on drop)
  generator.rs      password + passphrase generation (wordlist.txt)
  analysis.rs       strength estimation, weak/reused/old detection
  import_export.rs  CSV / JSON import, plaintext CSV export
  session.rs        inactivity auto-lock timer
  clipboard.rs      copy with clearing and Windows history exclusion
  recent.rs         recently opened vault paths
  ui/               egui screens (welcome, create, unlock, dashboard, items,
                    generator, security center, settings, modals)
tests/              end-to-end vault file tests
docs/SECURITY.md    cryptographic design and limitations
deny.toml           dependency policy (advisories, licences, network bans)
```

## Limitations

VaultRust cannot protect an unlocked vault on a compromised computer, cannot
guarantee that secrets never linger in memory, and cannot securely delete files
on SSDs. Read [docs/SECURITY.md](docs/SECURITY.md) before relying on it.
