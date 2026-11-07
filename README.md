# VaultRust

A local password safe for Windows, written entirely in Rust.

**Download:** get `VaultRust-Setup-x.y.z.exe` from the
[latest release](https://github.com/MStefa003/vault/releases/latest) and run
it. It installs for your Windows account only (no administrator rights), adds
VaultRust to the Start menu, and can be removed from Settings → Apps. Windows
may show "Windows protected your PC" because the installer isn't
code-signed yet: choose **More info → Run anyway**.

* **One encrypted file.** Your vault is a single `.vault` file stored wherever
  you choose. No database, no cloud, no account, no telemetry. Your vault never
  leaves your computer; the only network use is an optional daily check for
  signed updates on GitHub (and downloading the Firefox add-on from there
  when you click "Add to Firefox").
* **Modern cryptography.** Argon2id key derivation, XChaCha20-Poly1305
  authenticated encryption, a random 256-bit vault key, OS-provided randomness
  and memory wiping on lock. See [docs/SECURITY.md](docs/SECURITY.md).
* **Native UI.** egui/eframe; no web view, HTML or JavaScript.

## Features

* Logins, email accounts, secure notes, credit cards, identities, API keys,
  servers, databases, Wi-Fi networks and fully custom items with your own
  fields
* **One-time codes (TOTP)**: paste a site's 2FA setup key or `otpauth://`
  link and VaultRust shows the current code with a countdown — offline
* **Tags**, sorting (name, recently used, modified, created) and fuzzy search
  (`gml` finds Gmail) over titles, tags, usernames and websites
* **Change many items at once**: Ctrl+click, Shift+click or Ctrl+A to select
  several items, then tag, favorite or move them to the Trash together (one
  Undo brings them all back)
* **Item icons**: every item gets a coloured letter tile; pick an icon and
  colour of your own from the tile next to its title
* **Password rules per site**: for sites that limit length or symbols, set
  the rules once under the password field (“Set password rules for this
  site”) and generated passwords for that site and its subdomains follow
  them. Saved rules are listed on the Generator page
* **Duplicate finder**: the Security page lists items for the same account
  (same website and username) and keeps the newest with one click
* **English and Greek (Ελληνικά)**: follows the Windows display language, or pick
  one in Settings → App → Language (also on the start and unlock screens)
* **Password history**: replaced passwords are kept (last 10 per item)
* **Trash**: deleted items can be restored for 30 days, or straight away with
  Undo (or Ctrl+Z) in the notification that appears
* **Scan two-step codes**: while setting up 2FA on a site, click "Scan 2FA
  code" — VaultRust reads the QR code from your screen and adds the code to
  the matching login (or starts a new one named after the site). No setup key
  to copy
* **Less typing**: items without a title are named after their website, and
  the usernames and emails you use most are one click away
* **Welcome tour**: six short cards the first time you open a vault (replay it
  from Settings)
* **Automatic updates**: VaultRust checks
  [GitHub](https://github.com/MStefa003/vault/releases) twice a day and shows
  a notification when a new version is out, with what's new and a button to
  install it. Releases are signed, and an update is only installed if its
  signature checks out. Turn the check off in Settings. After an update it
  shows what changed; Settings → App → What's new lists every version
* **Attachments**: keep recovery codes, key files or document scans inside an
  item, encrypted with the rest of the vault (up to 10 MB per file, 50 MB per
  vault)
* **Start with Windows** (optional): VaultRust opens minimized, locked, when
  you sign in, or waits in the notification area
* **Auto-type**: click into a login form in any browser or app and press
  Ctrl+Shift+L; pick the item (ones matching the window come first) and
  VaultRust types username, Tab, password, Enter. Shift+Enter types only the
  password, Ctrl+Enter the one-time code. Items can have their own sequence,
  e.g. `{USERNAME}{ENTER}{DELAY 1500}{PASSWORD}{ENTER}` for two-page logins
* **Browser extension** for Chrome, Edge, Brave and Firefox, working with the app:
  logins appear in a menu when you click into a login field; it offers to
  save new logins and update changed passwords after you sign in; payment
  and address forms are filled from your cards and identities; the
  toolbar button lists the site's logins, searches the vault and generates
  passwords (following your site rules). Add it from Settings → Browser
  extension. See [Browser extension](#browser-extension) below
* **Windows Hello**: unlock with fingerprint, face or PIN (the master
  password is still needed once after VaultRust starts)
* **Expiry reminders**: give items an expiry date (API keys, work passwords);
  expired cards are detected from their printed date. Both appear under
  Needs attention
* **Activity log**: unlocks, exports, imports, backups and password changes,
  recorded inside the encrypted vault
* **Light and dark themes**, following Windows by default
* **Notification-area icon** with open / quick open / lock / quit; optionally
  (Settings) closing the window locks the vault and keeps VaultRust running
  there, with quick open and auto-type ready
* **Quick open**: Ctrl+K in the app, or Ctrl+Shift+Space from anywhere in
  Windows; Enter copies the password, Shift+Enter the username, Ctrl+Enter
  the one-time code
* Password generator (length, character sets, ambiguous-character exclusion,
  custom characters) and passphrase generator, with entropy estimates
* Security center: weak, reused and old passwords, plus an **offline
  breached-password check** against a local Have I Been Pwned list
* Automatic lock after inactivity, manual lock (Ctrl+L), lock on minimize and
  **lock when Windows locks** (Win+L, sleep with sign-in, switching user)
* Optional **key file** as a second factor
* Master passwords are Unicode-normalised, so accented passwords always match
* Window hidden from screenshots and screen sharing while unlocked; revealed
  secrets re-masked automatically; growing delay after wrong passwords; the
  master password is asked again before exporting or turning protection off
* Never silently overwrites changes made to the vault file by another window
  or program
* Keyboard shortcuts: Ctrl+F search, Ctrl+N new item, Ctrl+S save, Esc cancel;
  right-click an item to copy its username, password or one-time code
* Concealed fields with explicit reveal; copy with automatic clipboard clearing
  (excluded from Windows clipboard history and cloud sync)
* Create, open, rename and move vaults; verified encrypted backups and restore;
  **automatic hourly backups** (last 10 kept, next to the vault)
* Import **KeePass databases (.kdbx 3.1 / 4.x)**, CSV (Chrome, Edge, Firefox,
  Bitwarden, LastPass, 1Password, KeePass, …) and Bitwarden JSON; items already
  in the vault are skipped, and changed passwords can update the existing item;
  plaintext CSV export behind explicit warnings
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
you. It keeps automatic encrypted copies in `<vault file>.backups` next to the
vault; these protect against mistakes, not against losing the drive. Use
**Back up** regularly and keep copies on a separate drive. There is no master
password recovery: if you forget it (or lose the key file, if you use one),
the vault cannot be opened.

## Offline breached-password check

VaultRust never goes online, so it checks against a list you download
yourself: get the SHA-1 Pwned Passwords list as a single file ordered by hash
(for example with the official Have I Been Pwned `PwnedPasswordsDownloader`)
and choose it under **Settings → Breached-password check**. The file is
searched in place with a few dozen small reads per password, so the full
~40 GB list works.

## Testing and auditing

```powershell
cargo test                                             # unit, integration and headless UI tests
powershell -ExecutionPolicy Bypass -File scripts\audit.ps1   # fmt, clippy, test, deny, audit, network scan
powershell -ExecutionPolicy Bypass -File scripts\release.ps1 0.2.0   # publish a release (docs/RELEASING.md)
cargo +nightly fuzz run kdbx                           # fuzzing (cargo-fuzz; targets in fuzz/)
```

GitHub Actions (`.github/workflows/ci.yml`) runs the audit script and a
release build on Windows, the headless core library on Linux, and a short
fuzzing pass over every target on each push and pull request.

The tests cover vault creation, correct/incorrect passwords, encryption
round-trips, tamper detection (every header byte, sampled payload bytes,
truncation, payload swapping), interrupted writes, backup verification and
restore, master password changes (payload unchanged), nonce uniqueness,
persistence of every field type, automatic locking, zeroization, and
inspection of the raw vault file (and its automatic backups) for plaintext
leaks. Key files, Unicode normalisation, automatic backups, the trash,
password history and upgrades from every earlier payload schema are covered
too. TOTP is checked against the RFC 6238 test vectors, and KeePass import
against databases written by an independent implementation (pykeepass,
`tests/fixtures/kdbx`). Headless UI tests
(`egui_kittest`) render every screen and exercise unlocking, locking and
creating items.

To render every screen to PNG for visual review:

```powershell
$env:VAULTRUST_SCREENSHOT_DIR = "$env:TEMP\vaultrust-shots"
cargo test --lib render_screenshots -- --ignored
```

## Browser extension

### Adding it to a browser

The extension isn't in the browsers' stores; VaultRust adds it:

1. In VaultRust, open **Settings → Browser extension** and turn on **Fill in
   and save logins in your browser**.
2. Click **Add to Chrome** (or Edge, Brave). VaultRust opens the browser on
   a page with the steps, shows the extension's folder selected in File
   Explorer and puts `chrome://extensions` (`edge://`, `brave://`) on the
   clipboard.
3. Paste that into the address bar, turn on **Developer mode** and drag the
   folder onto the page (or click **Load unpacked** and choose it).
4. Pin VaultRust from the puzzle-piece menu, click its button and choose
   **Connect to VaultRust**. VaultRust asks whether to allow the browser and
   shows a six-digit code; allow it if the extension shows the same code.

**Firefox** is simpler: **Add to Firefox** downloads the add-on (signed by
Mozilla, from this project's GitHub releases) and opens it in Firefox, which
asks whether to add it. Then pin it and connect as in step 4. It updates
itself with each release. Firefox 140 or newer is needed.

Browsers don't let programs install extensions from outside their stores by
themselves (only company-managed PCs can), so the last steps are the user's.
Once published in the Chrome Web Store or Edge Add-ons, the buttons can open
the store page instead. Every release also has the extension as a zip
(for submitting it to a store later).

### Using it

* **In login fields**: a VaultRust icon appears in username and password
  fields; when the site has logins, the menu opens by itself. Pick one to
  fill it in. On sign-up and change-password forms the menu offers a
  generated password (following the site's password rules).
* **Saving**: after you sign in with a login VaultRust doesn't have, a bar
  asks whether to save it (or, for a known account with a new password,
  whether to update it). "Never for this site" stops asking there.
* **In payment and address forms**: the icon appears in card number,
  expiry, security code, name and address fields; pick a card or identity
  from the menu to fill in the whole form (drop-downs for the expiry month,
  year and country too). Card details are only filled into `https` pages.
* **The toolbar button** shows how many logins the site has. Its popup has
  four tabs: *This site* (fill, or copy username / password / code),
  *Vault* (search everything), *Cards & IDs* (fill a form, or copy a card's
  number or security code) and *Generator*. It can also lock VaultRust.
* **Alt+Shift+L** fills in the most recently used login for the site.
* After a login with a two-step code is filled in, VaultRust copies the
  current code, ready for the next page.

Copying from the extension is done by VaultRust itself: the clipboard is
cleared after the vault's timeout and kept out of clipboard history.

### How it works

The browser starts `VaultRust.exe` as its helper, which passes each request
over a named pipe (open only to your Windows account) to the running app.
The app answers only browsers you approved and only while a vault is
unlocked. A page can only have logins filled in whose website matches it
(subdomains included; never an `https` login on an `http` page). See
[docs/SECURITY.md](docs/SECURITY.md#browser-extension). Firefox isn't
supported yet.

## Project layout

```text
src/
  crypto.rs         Argon2id, XChaCha20-Poly1305, CSPRNG, key wrapping, key files
  format.rs         versioned binary file format, bounded parser, AAD
  storage.rs        atomic writes, no-overwrite moves, temp-file cleanup,
                    rotating automatic backups
  vault.rs          create / open / save / change password or key file /
                    backup / restore, Unicode normalisation
  model.rs          entries, fields, tags, history, trash (zeroized on drop)
  generator.rs      password + passphrase generation (wordlist.txt)
  analysis.rs       strength estimation, weak/reused/old detection
  breach.rs         offline lookup in a sorted Have I Been Pwned SHA-1 list
  totp.rs           RFC 6238 one-time codes, otpauth:// parsing
  autotype.rs       window matching and keystroke sequences for auto-type
  autofill.rs       card and address details for web forms
  browser.rs        browser extension: messages, site matching, pairing,
                    the helper the browser starts, browser registration
  hello.rs          Windows Hello quick unlock (TPM-backed key credential)
  i18n.rs, i18n/    interface language: English text as keys, Greek table
  prefs.rs          app-level theme / close-button preferences
  kdbx.rs           KeePass 3.1 / 4.x import
  encoding.rs       Base32 / Base64 / percent decoding
  import_export.rs  CSV / JSON import, plaintext CSV export
  session.rs        inactivity auto-lock timer
  clipboard.rs      copy with clearing and Windows history exclusion
  os_protect.rs     all unsafe code: capture exclusion, session-lock
                    detection, crash-report hardening, global hotkeys,
                    auto-type keystrokes, the browser extension's pipe
  recent.rs         recently opened vault paths
  ui/               egui screens (welcome, create, unlock, dashboard, items,
                    trash, generator, security center, settings, modals)
browser-extension/  the Chrome / Edge / Brave extension (built into the
                    program and written out from Settings)
tests/              end-to-end vault tests, KeePass fixtures, robustness
fuzz/               cargo-fuzz targets for every parser of untrusted input
docs/SECURITY.md    cryptographic design and limitations
deny.toml           dependency policy (advisories, licences, network bans)
```

## Limitations

VaultRust cannot protect an unlocked vault on a compromised computer, cannot
guarantee that secrets never linger in memory, and cannot securely delete files
on SSDs. Read [docs/SECURITY.md](docs/SECURITY.md) before relying on it.
