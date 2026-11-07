# Changelog

What changed in each release of VaultRust. The section for a version is
also its release notes on GitHub and what the app shows under "What's new",
so keep entries short, plain and written for the people using VaultRust.

`scripts\release.ps1` turns the "Unreleased" heading into the new version's
heading.

## Unreleased

## 0.7.0 — 2026-11-07

- The browser extension now works in Firefox too: Settings → Browser extension → Add to Firefox, then click "Add" when Firefox asks.
- The welcome tour now shows you around: a spotlight glides to each button it talks about (New item, search, Scan 2FA code, Security, Lock vault, Settings) with a card beside it. Replay it from Settings → App.

## 0.6.0 — 2026-11-07

- The browser extension fills in payment and address forms: click into a card number or address field and pick a card or identity from the VaultRust menu, or use the new "Cards & IDs" tab in its popup. Card details are only filled into secure (https) pages.
- New identities have separate City, State / region, Postal code and Country fields; addresses written on several lines are still understood.
- VaultRust tells you when a new version is out with a notification you can install from, checks twice a day (and again an hour later if you were offline), and keeps checking while it stays open.
- After an update, a notification shows what's new. Settings → App → What's new lists the changes in every version.

## 0.5.0 — 2026-11-07

- The browser extension now works much like Bitwarden's: logins appear in a menu when you click into a login field, it offers to save new logins and update changed passwords after you sign in, and its button shows how many logins the site has. The popup can search the whole vault, copy usernames, passwords and codes (copied by VaultRust, so the clipboard is still cleared), generate passwords following your site rules and lock VaultRust.
- Sign-up forms get a generated password from the menu in the password field.
- Settings → Browser extension has "Add to Chrome / Edge / Brave" buttons that open the browser and walk you through adding the extension.

## 0.4.0 — 2026-11-07

- Browser extension for Chrome, Edge and Brave: click the VaultRust button in the toolbar (or press Alt+Shift+L) to fill in the login for the site you're on. Turn it on in Settings → Browser extension, which shows how to add it. Each browser is approved once in VaultRust, and it only gets the logins for the site in the tab while the vault is unlocked.

## 0.3.0 — 2026-11-06

- Select several items with Ctrl+click, Shift+click or Ctrl+A, then favorite, tag or move them to the Trash together. One Undo brings them all back.
- Pick an icon and colour for any item from the tile next to its title.
- Password rules per website: for sites that limit length or symbols, set the rules once ("Set password rules for this site" under the password) and generated passwords for that site follow them.
- The Security page finds possible duplicates (same website and username) and keeps the newest with one click.
- VaultRust now speaks Greek (Ελληνικά). It follows the Windows display language; change it in Settings → App → Language.
- Vaults saved by this version can't be opened by VaultRust 0.2.3 or older.

## 0.2.3 — 2026-11-06

- A short welcome tour the first time you open a vault (replay it from Settings).
- Starting VaultRust again brings the running copy forward instead of opening a second one.
- Hardened against DLL planting (files dropped next to the program, e.g. in Downloads).
- Clearer screens for an empty vault and empty lists.

## 0.2.2 — 2026-11-06

- Redesigned overview for a new, empty vault.

## 0.2.1 — 2026-11-06

- A Windows installer (no administrator rights needed) with Start menu entry and uninstaller.
- The program now has its own icon.

## 0.2.0 — 2026-11-06

- First public release: encrypted local vault, one-time codes, 2FA QR scanning, auto-type, quick open, Windows Hello, attachments, backups, import from KeePass, browsers, Bitwarden and more, and signed automatic updates.
