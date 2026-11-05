# Releasing VaultRust

Installed copies of VaultRust check
[GitHub releases](https://github.com/MStefa003/vault/releases) once a day and
offer to update. Releases must be **signed**; an unsigned or wrongly signed
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

## Publishing a release

```text
powershell -ExecutionPolicy Bypass -File scripts\release.ps1 0.2.0
```

This sets the version in `Cargo.toml`, commits, tags `v0.2.0` and pushes. The
**Release** workflow then tests, builds, signs and publishes `VaultRust.exe`
and `VaultRust.exe.sig`. Edit the release on GitHub to write the notes users
see under "What's new".

The workflow refuses to publish if the tag doesn't match `Cargo.toml` or the
signing secret is missing. The app only installs versions newer than itself.
