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
* **Unicode normalisation.** The password is converted to Normalization Form C
  before key derivation, so the same visible text typed with composed or
  decomposed accents (which differ by keyboard layout and input method)
  produces the same key. Vaults created before this used the raw bytes; if
  the NFC attempt fails and the typed password was not already NFC, the raw
  form is tried as well (one extra Argon2 run, only in that case).

### Windows Hello (optional)

Windows Hello keeps an RSA key pair for VaultRust in the TPM; the private key
cannot be exported and each use needs the user's fingerprint, face or PIN.
Turning Hello on (which first asks for the master password) has Hello sign
`SHA-256("VaultRust/hello-challenge/v1" ‖ vault id ‖ random salt)` twice. The
two signatures must be identical (RSA PKCS#1 v1.5 is deterministic), and
SHA-256 of the signature becomes a key that encrypts, with XChaCha20-Poly1305,
a copy of the vault key and the key-file digest (if the vault uses one). The
result is stored in `%APPDATA%\VaultRust\hello\<vault id>.bin`.

* Without this computer's TPM and the user's Hello gesture the file cannot be
  decrypted; copying it elsewhere is useless.
* Hello is only offered after the vault was unlocked with its master password
  since VaultRust started, so a stolen, powered-off laptop still needs the
  password.
* Anyone who can pass Windows Hello on this account (for example someone who
  knows the Windows PIN) can unlock the vault while VaultRust is running and
  has been unlocked once. Leave Hello off if that is a concern.
* Changing the master password does not change the vault key, so Hello keeps
  working; turning Hello off deletes the file.

### Key files (optional)

A vault can additionally require a key file. Its SHA-256 digest is passed to
Argon2id as the *secret* input (`K`), so neither the password nor the file
alone derives the KEK. VaultRust can create a 64-byte random key file; any
existing file up to 16 MiB can also be used. Whether a key file is needed is
recorded as KDF algorithm id 2 in the header, which the key-wrap AAD covers,
so stripping the requirement makes unwrapping fail (tested). Adding, changing
or removing the key file only rewraps the vault key, like a password change.
While unlocked, the key file's digest stays in memory next to the vault key,
so re-confirming the master password does not need the file again.

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
    10    1  KDF algorithm id    (1 = Argon2id v1.3, 2 = Argon2id v1.3 + key file)
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
* Payload: `"VaultRust/payload/v1" ‖ magic ‖ version ‖ 0x01 ‖ 0x01 ‖ vault id`.
  This binds the ciphertext to its vault, so the payload of one vault cannot be
  swapped into another (tested). It deliberately excludes the password-wrapping
  fields so that a password or key-file change only rewrites the header; the
  KDF id in it is therefore always the constant 1.

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
  vault data. Outside the vault VaultRust writes only, under
  `%APPDATA%\VaultRust\`: `recent.txt` (recently opened vault *paths*,
  clearable from Settings), `prefs.txt` (theme and close-button choice, which
  must be known before unlocking) and, if Windows Hello is on, the encrypted
  `hello\<vault id>.bin` described above. Every vault setting lives inside
  the encrypted vault. "Start with Windows" adds one value, `VaultRust`, to
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` holding the program's
  path; turning it off deletes it.
* **QR scanning** takes one screenshot of all monitors only when the user
  clicks a scan button. It stays in memory, is converted to greyscale, searched
  for a QR code and wiped; it is never written to disk. Only an `otpauth://`
  link is used; any other QR code is ignored. While screen-capture protection
  is on, VaultRust's own window is not in the screenshot.
* **Attachments** are stored inside the encrypted payload like every other
  field and are covered by the same authentication. Saving one to disk ("Save
  to a file…") writes an ordinary, unencrypted file wherever the user chooses;
  VaultRust says so and records it in the activity log. File names are cleaned
  of path separators before being offered in the save dialog.
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
* **Automatic backups.** Before a save, if the newest automatic backup is more
  than an hour old, the vault file as it was on disk is copied to
  `<vault file>.backups\<name>-auto-<UTC time>.vault`; the newest 10 are kept
  (configurable, 0 turns it off). When the user chooses to overwrite a version
  changed by another window or program, that other version is always kept
  first. These are exact copies of the encrypted file, verified identical to
  what was on disk, and keep the password and key file in effect when made.
  A failed automatic backup never blocks a save; the user is told.
* **Payload schema versioning.** postcard is not self-describing, so every past
  payload layout is kept and upgraded on load (schemas 1 to 5 → 6 are
  tested). Vaults written by a newer VaultRust are refused rather than
  misread.

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

* **Crash reports.** At start-up VaultRust asks Windows Error Reporting to
  leave the heap out of crash reports (`WER_FAULT_REPORTING_FLAG_NOHEAP`) and
  suppresses the crash dialog. A full dump configured by an administrator
  (`LocalDumps`) or a debugger is not prevented.
* **DLL loading.** At start-up the current directory is removed from the DLL
  search path (`SetDllDirectoryW("")`) and the image-load mitigation policy is
  set: no DLLs from network shares or low-integrity locations, and Windows'
  System32 copy wins over a same-named DLL next to the program. This defeats
  DLL planting, e.g. a malicious `version.dll` in the Downloads folder the
  installer was run from.
* **One running copy.** A named mutex (per user session) keeps VaultRust to a
  single process, so two copies can't fight over the same vault; starting it
  again only signals the running copy to show its window.

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
* Lock when Windows locks (on by default): about once a second VaultRust checks
  whether the interactive desktop can be opened (`OpenInputDesktop`). That
  fails while the session is locked, on the sign-in screen after sleep (when
  Windows requires sign-in on wake, the default) and after switching user. It
  also fails while a UAC prompt is on the secure desktop; locking then too is
  deliberate.
* Sensitive actions — the plaintext export, turning off screen-capture
  protection and turning on Windows Hello — ask for the master password again
  (a full Argon2 check).
* With "Keep running in the notification area" on (it is off by default),
  closing the window locks the vault before hiding it: a hidden window may
  receive no frames, so the inactivity timer could not be relied on to lock
  it later.
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

All `unsafe` code in VaultRust is in `src/os_protect.rs`: this call, the
session-lock check, the crash-report flags, the global hotkeys
(`RegisterHotKey` plus a message loop on its own thread; a press only brings
the window forward and opens quick open or the auto-type picker — nothing is
read, copied or typed until the user acts) and auto-type's `SendInput`. Everything else is compiled under `deny(unsafe_code)`.

## Network use: updates only

Vault data never touches the network. The one network feature is the update
check (`src/update.rs`), which can be turned off in Settings.

* **What is contacted.** Once a day (and when the user clicks "Check now")
  VaultRust asks `api.github.com` for the latest release of
  `MStefa003/vault`. If the user then chooses "Update and restart", it
  downloads `VaultRust.exe` and `VaultRust.exe.sig` from that release
  (GitHub redirects downloads to its file servers). Nothing else is sent
  besides what any HTTPS request carries: the IP address and a `VaultRust/x.y.z`
  user agent. No identifiers, no vault data, no usage data.
* **How.** Windows' WinHTTP, HTTPS only (TLS 1.2 or newer, Windows' own
  certificate validation), redirects never downgraded to plain HTTP, size
  limits on every response. No networking crate is bundled: `deny.toml` still
  bans HTTP clients, TLS libraries, async runtimes and self-update crates, and
  `scripts/audit.ps1` scans the shipped dependency graph for them.
* **Signed releases.** The release workflow signs
  `"VaultRust release v1\n" ‖ version ‖ "\n" ‖ SHA-256(program)` with an
  Ed25519 key kept as a GitHub Actions secret (and offline by the maintainer).
  The public key is compiled into VaultRust. An update is installed only if
  the signature verifies **and** the version is newer than the running one, so
  a compromised GitHub account, a replaced release file or a man in the middle
  cannot install a modified program or roll back to an older one. Losing the
  signing key would mean future updates must be installed by hand.
* **Installing.** The new program is written next to the old one, the running
  program is renamed to `VaultRust.old.exe` (deleted on the next start) and the
  new one takes its place; if any step fails the old program is put back.
  The vault is locked (and saved) before VaultRust restarts.
* If VaultRust is installed somewhere it cannot write (e.g. Program Files),
  installing fails safely and the user is asked to download the release.
* `eframe` unconditionally depends on `webbrowser` (to open clicked hyperlinks
  by launching the system browser) and `url`. Neither opens sockets. VaultRust
  never creates hyperlinks and removes every open-URL command from egui's output
  each frame, so it never launches a browser.
* Fonts are read from the local Windows font directory or egui's bundled
  fonts — never downloaded.
* Windows Cloud Clipboard sync is opted out for copied secrets (see above).
* The breached-password check reads a local file the user downloaded
  themselves; see below.

## Breached-password check

If the user chooses a local copy of the Have I Been Pwned SHA-1 list, the SHA-1
of each stored password is looked up by binary search in that file (it is
never loaded whole). Only hashes are compared; nothing leaves the computer.
The list's path is stored inside the encrypted vault. The check runs in the
background whenever passwords change.

## Activity log

The vault records unlocks (and whether Windows Hello was used), exports,
imports, backups, restores, item password changes, master-password or
key-file changes, items deleted for good, and protections switched off — with
times and item titles or file names. It is part of the encrypted payload (at
most 500 events), so only someone who can unlock the vault can read it, and
it can't be used to monitor the vault from outside. An unlock event makes the
vault "changed", so it is saved when the vault locks.

## One-time codes and history

* One-time-code secrets are stored like any other concealed field; only the
  current code is displayed. Codes are computed locally (RFC 6238, tested
  against its published vectors).
* Password history keeps up to 10 replaced passwords per item, and the Trash
  keeps deleted items for 30 days. Both live inside the encrypted payload, but
  they do mean an old password remains in the vault until it ages out or the
  user deletes it from the Trash.

## Auto-type

Pressing Ctrl+Shift+L records which window was in front (its handle and
title), brings VaultRust forward and shows a picker headed with that window's
title. Items whose website or title matches the window title are listed
first, but window titles are chosen by web pages and can imitate any site, so
nothing is typed until the user picks an item. VaultRust then activates the
recorded window and sends the keystrokes with `SendInput` as Unicode
characters, so they arrive correctly on any keyboard layout.

* Before every keystroke the foreground window is checked; if anything else
  took focus (a pop-up, the user clicking elsewhere), typing stops at once so
  the rest of the password does not go to the wrong window.
* Typing waits until Ctrl, Shift, Alt and Windows keys are released.
* The `INPUT` structures that carried characters are overwritten after use;
  the typed strings are zeroized when the typing thread finishes.
* Simulated keystrokes are visible to anything that can observe keyboard input
  on the machine (keyloggers, hooks), just as real typing is. Windows does not
  let a normal process type into an application running as administrator;
  VaultRust reports that instead of failing silently.
* The shortcut is not Ctrl+Alt+…, because on many keyboard layouts Ctrl+Alt is
  AltGr and a system-wide shortcut on it would break typing characters.

## Import and export

* Import (KeePass `.kdbx` 3.1 and 4.x, CSV from Chrome/Edge/Firefox/Bitwarden/
  LastPass/1Password/KeePass and similar, Bitwarden unencrypted JSON, generic
  JSON arrays) is always user initiated. The file is read into a zeroizing
  buffer and parsed in memory; nothing derived from it is written to disk
  except inside the encrypted vault. The user is reminded to delete plaintext
  source files themselves.
* KeePass databases are decrypted with the password the user enters (AES-256 or
  ChaCha20; AES-KDF, Argon2d or Argon2id; Salsa20 or ChaCha20 protected
  values). Header HMACs and block checksums are verified; key-derivation cost
  and decompressed size are capped so a crafted file cannot hang the app or
  exhaust memory. Key-file-protected and Twofish databases are refused.
* The only plaintext export is a CSV export behind a prominent warning, a
  checkbox and typing `EXPORT`. VaultRust never creates exports automatically
  and never uploads anything.

## Deletion

VaultRust does not claim secure deletion. On SSDs (wear levelling) and modern
file systems (journaling, snapshots, shadow copies, cloud sync folders),
overwriting or deleting a file does not guarantee the old data is gone. The
best protection for old vault copies is a strong master password.

## Other known limitations

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
`cargo deny check`, `cargo audit` and the network-crate scan. CI runs it on
every push, plus fuzzing of the vault parser, payload decoder, CSV/JSON/KeePass
importers and TOTP parser (`fuzz/`).
