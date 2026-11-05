# VaultRust security design

This document describes how VaultRust protects data, why each decision was
made, and — just as importantly — what it does **not** protect against.

## Threat model

VaultRust is designed to protect the contents of a vault file against an
attacker who obtains a copy of that file (stolen laptop, copied USB stick,
leaked backup, cloud folder the user put it in), and against undetected
modification of the file.

It **cannot** protect against an attacker who controls the computer while the
vault is unlocked or while the master password is typed: malware, keyloggers,
screen recorders, malicious drivers or a compromised operating system can read
anything the user can.

## Key hierarchy

```text
master password ──Argon2id(salt, m, t, p)──▶ KEK (256-bit)
KEK ──XChaCha20-Poly1305 decrypt──▶ vault key (random 256-bit)
vault key ──XChaCha20-Poly1305 decrypt──▶ vault payload
```

* The **vault key** is generated once from the OS CSPRNG when the vault is
  created and never changes. All contents are encrypted with it.
* The **key-encryption key (KEK)** is derived from the master password and is
  only used to wrap (encrypt) the vault key.
* **Changing the master password** derives a new KEK with a new random salt and
  re-wraps the same vault key. The encrypted payload is not touched (this is
  verified byte-for-byte in `tests/vault_integration.rs`).
* The master password is never stored, logged or written anywhere.

## Algorithms

| Purpose | Choice | Crate |
|---|---|---|
| Password KDF | Argon2id v1.3 | `argon2` (RustCrypto) |
| Authenticated encryption | XChaCha20-Poly1305 | `chacha20poly1305` (RustCrypto) |
| Randomness | OS CSPRNG (`ProcessPrng` / `BCryptGenRandom` on Windows) | `rand_core::OsRng` → `getrandom` |
| Secret memory wiping | `Zeroize` / `ZeroizeOnDrop` | `zeroize` |
| Secret containers | `SecretBox`, `SecretString` | `secrecy` |
| Payload encoding | postcard (compact, non-self-describing serde format) | `postcard` |

**Why Argon2id.** It is memory-hard, which makes GPU/ASIC guessing of the
master password expensive. Defaults (`KdfParams::STANDARD`) are 64 MiB, 3
passes, 4 lanes — above the OWASP 2024 minimum (19 MiB, t=2, p=1). Users can
choose 256 MiB or 1 GiB when creating a vault or changing the password. The
parameters are stored in the header so they can be raised later.

**Why XChaCha20-Poly1305.** It is an AEAD (confidentiality + integrity in one
primitive), constant-time in software, and its 192-bit nonce makes random
nonces safe: the collision probability stays negligible (≈2⁻⁹⁶ after 2⁴⁸
encryptions), so no nonce counter has to be persisted and file copies or
restored backups cannot cause nonce reuse through a stale counter.

**Nonces.** A fresh random nonce is generated for every encryption: each save
of the payload and each key wrap. Tests assert uniqueness across 100 000
generated nonces, across 50 consecutive saves and across password changes.

## File format (version 1)

A vault is a single file. All integers are little-endian.

```text
offset size  field
     0    8  magic "VAULTRS\x1A"
     8    2  format version (1)
    10    1  KDF algorithm id    (1 = Argon2id v1.3)
    11    1  AEAD algorithm id   (1 = XChaCha20-Poly1305)
    12   16  vault id (random)
    28    4  Argon2 memory cost (KiB)
    32    4  Argon2 time cost
    36    4  Argon2 parallelism
    40   32  salt
    72   24  key-wrap nonce
    96   48  wrapped vault key (32 bytes + 16-byte tag)
   144   24  payload nonce
   168    8  payload length N
   176    N  payload ciphertext + 16-byte tag
```

**Associated data (AAD).**

* Key wrap: `"VaultRust/key-wrap/v1" ‖ bytes[0..72]`. This binds the wrapped
  key to the magic, version, algorithm ids, vault id, KDF parameters and salt.
  Changing any of them (e.g. downgrading the Argon2 cost) makes unwrapping
  fail.
* Payload: `"VaultRust/payload/v1" ‖ magic ‖ version ‖ algorithm ids ‖ vault id`.
  This binds the ciphertext to its vault, so the payload of one vault cannot be
  swapped into another (tested). It deliberately excludes the password-wrapping
  fields so that a password change only rewrites the header.

**Parsing is bounded and fails closed.** The header is fixed-size and read with
bounds-checked slices. Argon2 parameters are range-checked *before* any key
derivation (memory cost 8 MiB–2 GiB, so a crafted file cannot force a huge
allocation). The payload length must exactly match the file size and is capped
at 256 MiB. A failed tag check returns an error; there is no plaintext
fallback. Every truncation of a valid file and a bit flip in every header byte
are tested to be rejected.

**Payload.** `u32 length ‖ postcard(VaultData) ‖ zero padding` to a multiple of
4 KiB, so the file size only reveals the approximate amount of data. Everything
— titles, usernames, URLs, notes, field labels, settings, the vault name — is
inside the encrypted payload. A test writes distinctive marker strings into
every kind of field and checks they appear neither as UTF-8 nor UTF-16 in the
vault file or its backup.

**Wrong password vs. tampering.** If unwrapping fails, the password is wrong or
the header was modified; these are deliberately indistinguishable. If the key
unwraps but the payload fails authentication, the payload was corrupted or
tampered with, and VaultRust reports exactly that.

## Storage

* **Atomic writes.** Every save writes to a temporary file in the same
  directory, flushes it to disk (`sync_all`) and atomically renames it over the
  vault. A crash or power loss leaves either the old or the new complete file.
  Temporary files contain only ciphertext; stale ones from an interrupted write
  are removed the next time the vault is opened. Tested by injecting a failure
  half-way through a write.
* **No silent overwrites.** Creating a vault, writing a backup, restoring a
  backup and moving the vault refuse to replace an existing file unless the user
  explicitly confirms in VaultRust's own dialog (moving never overwrites).
* **No plaintext side files.** No temporary, cache, log or config file contains
  vault data. The only file VaultRust writes outside the vault is
  `%APPDATA%\VaultRust\recent.txt`, a list of recently opened vault *paths*
  (clearable from Settings). All preferences live inside the encrypted vault.
* **Backups** are exact copies of the encrypted vault file. After writing, the
  backup is read back, decrypted with the in-memory key and compared with the
  open vault. Restoring decrypts and authenticates the backup with its password
  before anything is written. A backup keeps the master password that was in
  effect when it was made.

* **Conflict detection.** Before every save, password change or move,
  VaultRust checks that the file on disk is byte-for-byte what this session last
  read or wrote. If another VaultRust window, a sync tool or a restore changed
  (or deleted) it, nothing is written; the user chooses between reloading and
  explicitly overwriting. Tested with two sessions on one file.
* **Payload schema versioning.** postcard is not self-describing, so every past
  payload layout is kept and upgraded on load (schemas 1 and 2 → 3 are
  tested). Vaults
  written by a newer VaultRust are refused rather than misread.

## Memory handling — best effort, not a guarantee

* The vault key and KEK live in `SecretBox` and are wiped on drop.
* All decrypted entries (`VaultData`, `Entry`, `Field`) derive `ZeroizeOnDrop`.
  Locking drops the whole unlocked state, wiping these buffers.
* Serialization writes into a pre-sized zeroizing buffer that never
  reallocates; decryption happens in place in a zeroizing buffer.
* Password input buffers are pre-allocated `Zeroizing<String>`s and are wiped
  after use.
* On lock VaultRust also clears egui's per-widget memory (text-edit undo
  history).

**Limitations.** Rust and the OS do not give full control over memory. Copies of
secrets can survive in: freed allocations from string growth while typing, the
UI toolkit's text layout caches and GPU buffers for text that was displayed,
serde/JSON parser temporaries during import, the page file (swap) and the
hibernation file. VaultRust does not lock memory pages or disable crash dumps.
Treat a machine you do not trust as unable to protect an unlocked vault.

## Clipboard

Copied secrets are placed on the clipboard with Windows' exclusion formats so
that they are not recorded in Clipboard History (Win+V) or synced by Cloud
Clipboard. They are cleared after a configurable delay (default 30 s), on lock
and on exit — but only if the clipboard still holds the value VaultRust put
there. Any program running on the machine can still read the clipboard while
the secret is on it, and third-party clipboard managers may ignore the
exclusion flags.

## Locking

* Automatic lock after a configurable inactivity period (1–240 minutes,
  default 5). Activity means keyboard, mouse or scroll input in the window.
* Manual lock (button or Ctrl+L) and optional lock-on-minimize.
* Revealed secrets are masked again automatically (default 30 s).
* After three wrong master passwords the unlock screen imposes a growing delay
  (1 s doubling to 30 s). This only slows guessing at an unattended VaultRust
  window; an attacker with a copy of the file is slowed by Argon2id instead.
* Both the timer logic and the UI-level locking are covered by tests.

## Screen capture

While a vault is unlocked, VaultRust asks Windows to exclude its window from
screenshots, screen recording and screen sharing (`SetWindowDisplayAffinity`
with `WDA_EXCLUDEFROMCAPTURE`; on systems older than Windows 10 2004 the
window is captured as black). It can be turned off in Settings. This stops
accidental exposure (screen sharing, screenshot tools); it is not a defence
against malware with high privileges or a camera.

This is the only `unsafe` code in VaultRust: one Win32 call in
`src/os_protect.rs`. Everything else is compiled under `deny(unsafe_code)`.

## Network isolation

VaultRust contains no network code and needs no network connection.

* No HTTP client, TLS, sockets, DNS, async runtime, telemetry, crash reporter
  or self-updater is present in the dependency graph. `deny.toml` bans these
  crates and `cargo deny check` enforces it; `scripts/audit.ps1` additionally
  scans the exact list of crates compiled into the Windows binary.
* `eframe` unconditionally depends on `webbrowser` (to open clicked hyperlinks
  by launching the system browser) and `url`. Neither opens sockets. VaultRust
  never creates hyperlinks and removes every open-URL command from egui's output
  each frame, so it never launches a browser.
* Fonts are read from the local Windows font directory or egui's bundled
  fonts — never downloaded.
* Windows Cloud Clipboard sync is opted out for copied secrets (see above).

## Import and export

* Import (CSV from Chrome/Edge/Firefox/Bitwarden/LastPass/1Password/KeePass and
  similar, Bitwarden unencrypted JSON, generic JSON arrays) is always user
  initiated. The file is read into a zeroizing buffer and parsed in memory;
  nothing derived from it is written to disk except inside the encrypted vault.
  The user is reminded to delete the plaintext source file themselves.
* The only plaintext export is a CSV export behind a prominent warning, a
  checkbox and typing `EXPORT`. VaultRust never creates exports automatically
  and never uploads anything.

## Deletion

VaultRust does not claim secure deletion. On SSDs (wear levelling) and modern
file systems (journaling, snapshots, shadow copies, cloud sync folders),
overwriting or deleting a file does not guarantee the old data is gone. The
best protection for old vault copies is a strong master password.

## Other known limitations

* **Unicode normalization.** The master password is used as typed (UTF-8
  bytes). Visually identical passwords entered with different Unicode
  normalization (e.g. composed vs. decomposed accents) will not match.
* **Concurrent use.** Two windows editing the same vault cannot silently
  overwrite each other (see conflict detection), but the user must choose which
  version to keep; changes are not merged.
* **Strength estimates** are heuristic (character pool, patterns, common
  passwords, dictionary words). They are guidance, not a guarantee.
* **Dependency advisory.** `ttf-parser` (used by egui to parse fonts) is
  marked unmaintained (RUSTSEC-2026-0192). It is not a known vulnerability and
  only parses trusted local fonts; it is listed as an accepted exception in
  `deny.toml` until an egui upgrade removes it.

## Verification

```powershell
powershell -ExecutionPolicy Bypass -File scripts\audit.ps1
```

runs `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`,
`cargo deny check`, `cargo audit` and the network-crate scan.
