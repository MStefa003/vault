# Releasing VaultRust

Installed copies of VaultRust check
[GitHub releases](https://github.com/MStefa003/vault/releases) twice a day and
show a notification offering the update. Releases must be **signed**; an unsigned or wrongly signed
release is ignored by the app.

## One-time setup: the signing key

The signing key was created with

```text
cargo run --no-default-features --features release-tools --bin vaultrust-sign -- generate %USERPROFILE%\.vaultrust\release-signing-key.txt
```

and its public half is compiled into `src/update.rs` (`PUBLIC_KEY`).

1. Open `%USERPROFILE%\.vaultrust\release-signing-key.txt` and copy its
   contents (one line of 64 hex characters).
2. On GitHub: **Settings → Secrets and variables → Actions → New repository
   secret**. Name: `VAULTRUST_SIGNING_KEY`, value: the copied line.
3. Keep a backup of the key file somewhere safe and offline (e.g. inside your
   VaultRust vault as an attachment). **Never commit it.** If it is lost, a new
   key means users must install the next version by hand; if it leaks, anyone
   could sign updates, so rotate it the same way.

## One-time setup: signing the Firefox add-on

Firefox only installs add-ons signed by Mozilla, so each release has the
add-on signed as a self-distributed ("unlisted") one; it is not listed on
addons.mozilla.org, and signing is usually automatic and takes minutes.

1. Sign in at [addons.mozilla.org](https://addons.mozilla.org/developers/)
   (a free Mozilla account) and open **Tools → Manage API Keys**. Generate
   credentials.
2. Add two repository secrets as above: `AMO_JWT_ISSUER` (the "JWT issuer")
   and `AMO_JWT_SECRET` (the "JWT secret").

Without them, releases are still published but without the Firefox add-on,
and "Add to Firefox" in the app falls back to a page with manual steps
(which only work for a released add-on, or as a temporary add-on).

## Publishing a release

First write what's new under `## Unreleased` in `CHANGELOG.md`: a few
short, plain bullet points for the people using VaultRust. That section
becomes the release notes on GitHub, the points the update notification
shows (the first three) and the version's entry in the app's "What's new"
window, and the script refuses to release without it. Then run

```text
powershell -ExecutionPolicy Bypass -File scripts\release.ps1 0.2.0
```

This sets the version in `Cargo.toml`, dates the changelog section, commits,
tags `v0.2.0` and pushes. The
**Release** workflow then tests, builds and signs the program, builds the
installer with Inno Setup (`installer/vaultrust.iss`) and publishes:

* `VaultRust-Setup-0.2.0.exe` — what people download and run;
* `VaultRust.exe` and `VaultRust.exe.sig` — what installed copies update
  themselves from;
* `VaultRust-Firefox.xpi` and `firefox-updates.json` — the signed Firefox
  add-on, which "Add to Firefox" downloads, and what installed add-ons
  update from (the manifest's `update_url`);
* `SHA256SUMS.txt`.

## Windows SmartScreen

The installer and program are not Authenticode-signed (that needs a paid
code-signing certificate or a service such as Azure Trusted Signing or
SignPath). Until they are, Windows shows "Windows protected your PC" the
first time: **More info → Run anyway**. Browsers may also warn that the file
"isn't commonly downloaded". This does not affect VaultRust's own update
signature, which is checked independently.

The workflow refuses to publish if the tag doesn't match `Cargo.toml` or the
signing secret is missing. The app only installs versions newer than itself.
