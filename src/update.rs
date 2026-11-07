//! Updates from GitHub releases.
//!
//! This is the only part of VaultRust that uses the network, and it never
//! sends vault data: it asks the GitHub API for the latest release of
//! [`REPO`] and, if the user agrees, downloads the program from it.
//!
//! Every release is signed with an Ed25519 key held by the release workflow.
//! A download is installed only if its signature verifies against
//! [`PUBLIC_KEY`], built into this program, and only if its version is newer
//! than the running one, so neither a tampered download nor a replaced
//! release asset nor an old (downgrade) release can be installed.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The GitHub repository releases come from.
pub const REPO: &str = "MStefa003/vault";
/// Name of the program asset in a release.
pub const EXE_ASSET: &str = "VaultRust.exe";
/// Name of its signature asset.
pub const SIG_ASSET: &str = "VaultRust.exe.sig";
/// The release-signing public key (see docs/RELEASING.md).
pub const PUBLIC_KEY: [u8; 32] = [
    0xda, 0xd1, 0xf6, 0x22, 0x0a, 0x49, 0x63, 0x7d, 0x64, 0xb1, 0x78, 0xb0, 0x09, 0x86, 0xf4, 0x6a,
    0x2b, 0x8e, 0xca, 0x33, 0x02, 0xbb, 0xaf, 0x27, 0xc7, 0x1b, 0xf0, 0x50, 0xfd, 0x76, 0xfe, 0xa0,
];
/// Largest program download accepted.
pub const MAX_EXE_BYTES: usize = 64 * 1024 * 1024;
const MAX_API_BYTES: usize = 1024 * 1024;
const MAX_SIG_BYTES: usize = 4096;

/// The running version.
pub fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("Cargo.toml version is x.y.z")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32, pub u32);

impl Version {
    /// "1.2.3" or "v1.2.3" (a "-suffix" is ignored).
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim();
        let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
        let s = s.split(['-', '+']).next()?;
        let mut parts = s.split('.').map(|p| p.parse::<u32>().ok());
        let v = Version(
            parts.next()??,
            parts.next().unwrap_or(Some(0))?,
            parts.next().unwrap_or(Some(0))?,
        );
        parts.next().is_none().then_some(v)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    #[error("{}", crate::i18n::format(crate::i18n::tr("couldn't reach GitHub: {0}"), &[("0", .0)]))]
    Network(String),
    #[error("{}", crate::i18n::tr("GitHub's answer couldn't be read"))]
    BadResponse,
    #[error("{}", crate::i18n::format(crate::i18n::tr("the release is missing {0}"), &[("0", .0)]))]
    MissingAsset(&'static str),
    #[error(
        "{}",
        crate::i18n::tr("the download's signature is not valid — it was not installed")
    )]
    BadSignature,
    #[error("{}", crate::i18n::tr("the download is too large"))]
    TooLarge,
    #[error("{}", crate::i18n::format(crate::i18n::tr("couldn't replace the program file ({0}); download the new version from GitHub instead"), &[("0", .0)]))]
    Install(String),
    #[error("{}", crate::i18n::tr("updates are only available on Windows"))]
    Unsupported,
}

/// A release that is newer than the running program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: Version,
    /// Release notes (Markdown, as written on GitHub).
    pub notes: String,
    exe_url: String,
    sig_url: String,
}

#[derive(serde::Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(serde::Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
}

/// Read the GitHub API's "latest release" answer. `Ok(None)` if it is not
/// newer than `current` (or is a draft / pre-release).
pub fn parse_latest(json: &[u8], current: Version) -> Result<Option<Release>, UpdateError> {
    let r: ApiRelease = serde_json::from_slice(json).map_err(|_| UpdateError::BadResponse)?;
    let version = Version::parse(&r.tag_name).ok_or(UpdateError::BadResponse)?;
    if r.draft || r.prerelease || version <= current {
        return Ok(None);
    }
    let url = |name: &'static str| {
        r.assets
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.browser_download_url.clone())
            .filter(|u| u.starts_with("https://"))
            .ok_or(UpdateError::MissingAsset(name))
    };
    Ok(Some(Release {
        version,
        notes: r.body.unwrap_or_default(),
        exe_url: url(EXE_ASSET)?,
        sig_url: url(SIG_ASSET)?,
    }))
}

/// What the release key signs: a fixed context, the version (so a signed
/// old release can't be passed off as a new one) and the program's hash.
pub fn signed_message(version: Version, exe: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(exe);
    let mut m = format!("VaultRust release v1\n{version}\n").into_bytes();
    for b in hash {
        m.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    m
}

/// Check a signature file (hex text) for `exe` at `version`.
pub fn verify(
    version: Version,
    exe: &[u8],
    sig_text: &[u8],
    key: &[u8; 32],
) -> Result<(), UpdateError> {
    let text = std::str::from_utf8(sig_text).map_err(|_| UpdateError::BadSignature)?;
    let bytes = hex_decode(text.trim()).ok_or(UpdateError::BadSignature)?;
    let sig =
        ed25519_compact::Signature::from_slice(&bytes).map_err(|_| UpdateError::BadSignature)?;
    let pk = ed25519_compact::PublicKey::new(*key);
    pk.verify(signed_message(version, exe), &sig)
        .map_err(|_| UpdateError::BadSignature)
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Ask GitHub whether a newer release exists.
pub fn check() -> Result<Option<Release>, UpdateError> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    match crate::os_protect::http_get(&url, MAX_API_BYTES) {
        Ok(body) => parse_latest(&body, current_version()),
        // No release published yet.
        Err(crate::os_protect::HttpError::Status(404)) => Ok(None),
        Err(e) => Err(UpdateError::Network(e.to_string())),
    }
}

/// Download a release and verify its signature. Returns the program bytes.
pub fn download(release: &Release) -> Result<Vec<u8>, UpdateError> {
    let get = |url: &str, max: usize| {
        crate::os_protect::http_get(url, max).map_err(|e| match e {
            crate::os_protect::HttpError::TooLarge => UpdateError::TooLarge,
            e => UpdateError::Network(e.to_string()),
        })
    };
    let sig = get(&release.sig_url, MAX_SIG_BYTES)?;
    let exe = get(&release.exe_url, MAX_EXE_BYTES)?;
    verify(release.version, &exe, &sig, &PUBLIC_KEY)?;
    Ok(exe)
}

fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let stem = exe
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("VaultRust");
    exe.with_file_name(format!("{stem}.{suffix}.exe"))
}

/// Replace the program at `exe` with `new_bytes`. A running program can be
/// renamed but not overwritten on Windows, so the old file is moved aside
/// (`<name>.old.exe`, removed by [`clean_up`] on the next start) and the new
/// one takes its name. On failure the old program is put back.
pub fn install(exe: &Path, new_bytes: &[u8]) -> Result<(), UpdateError> {
    let fail = |e: std::io::Error| UpdateError::Install(e.to_string());
    let staged = sibling(exe, "new");
    let old = sibling(exe, "old");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&staged).map_err(fail)?;
        f.write_all(new_bytes).map_err(fail)?;
        f.sync_all().map_err(fail)?;
    }
    let _ = std::fs::remove_file(&old);
    if let Err(e) = std::fs::rename(exe, &old) {
        let _ = std::fs::remove_file(&staged);
        return Err(fail(e));
    }
    if let Err(e) = std::fs::rename(&staged, exe) {
        let _ = std::fs::rename(&old, exe);
        let _ = std::fs::remove_file(&staged);
        return Err(fail(e));
    }
    Ok(())
}

// --- What's new.

/// The changelog built into this program (CHANGELOG.md).
pub const CHANGELOG: &str = include_str!("../CHANGELOG.md");

/// One version's section of the changelog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changes {
    pub version: String,
    /// As written after the version ("2026-11-07"), or empty.
    pub date: String,
    pub items: Vec<String>,
}

/// Markdown emphasis and code marks taken out ("**Bold** `x`" -> "Bold x").
fn plain(s: &str) -> String {
    s.replace("**", "").replace('`', "")
}

/// The points of a version's notes: one per "- " or "* " line (with the
/// lines that continue it), or per paragraph.
pub fn note_items(notes: &str) -> Vec<String> {
    let mut items: Vec<String> = Vec::new();
    let mut open = false;
    for line in notes.lines() {
        let t = line.trim();
        if t.is_empty() {
            open = false;
        } else if let Some(b) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")) {
            items.push(plain(b.trim()));
            open = true;
        } else if open && !t.starts_with('#') {
            if let Some(last) = items.last_mut() {
                last.push(' ');
                last.push_str(&plain(t));
            }
        } else if !t.starts_with('#') {
            items.push(plain(t));
            open = true;
        }
    }
    items
}

/// The versions in a changelog written like CHANGELOG.md ("## 1.2.0 —
/// date" headings), newest first. Text before the first version and an
/// empty "Unreleased" section are left out.
pub fn parse_changelog(text: &str) -> Vec<Changes> {
    let mut out = Vec::new();
    for section in text.split("\n## ").skip(1) {
        let (head, body) = section.split_once('\n').unwrap_or((section, ""));
        let (version, date) = match head.split_once(['—', '–']) {
            Some((v, d)) => (v.trim(), d.trim()),
            None => (head.trim(), ""),
        };
        let items = note_items(body);
        if items.is_empty() {
            continue;
        }
        out.push(Changes {
            version: version.to_string(),
            date: date.to_string(),
            items,
        });
    }
    out
}

/// Remove what an earlier update left next to the program.
pub fn clean_up(exe: &Path) {
    let _ = std::fs::remove_file(sibling(exe, "old"));
    let _ = std::fs::remove_file(sibling(exe, "new"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> ed25519_compact::KeyPair {
        ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([7; 32]))
    }

    fn sign(kp: &ed25519_compact::KeyPair, v: Version, exe: &[u8]) -> Vec<u8> {
        hex_encode(kp.sk.sign(signed_message(v, exe), None).as_ref()).into_bytes()
    }

    #[test]
    fn changelogs_and_notes_are_read() {
        let log = "# Changelog\n\nIntro text.\n\n## Unreleased\n\n\
                   ## 1.1.0 — 2026-12-01\n\n- **New**: cards\n  and addresses\n- `Fix`\n\n\
                   ## 1.0.0\n\nFirst release.\n";
        let c = parse_changelog(log);
        assert_eq!(c.len(), 2);
        assert_eq!(
            (c[0].version.as_str(), c[0].date.as_str()),
            ("1.1.0", "2026-12-01")
        );
        assert_eq!(c[0].items, vec!["New: cards and addresses", "Fix"]);
        assert_eq!((c[1].version.as_str(), c[1].items.len()), ("1.0.0", 1));
        assert_eq!(
            note_items("* one\n* two\n\nthree"),
            vec!["one", "two", "three"]
        );

        // The built-in changelog has this version's notes.
        let built_in = parse_changelog(CHANGELOG);
        assert!(!built_in.is_empty());
        assert!(built_in
            .iter()
            .filter_map(|c| Version::parse(&c.version))
            .all(|v| v <= current_version()));
    }

    #[test]
    fn versions_parse_and_compare() {
        assert_eq!(Version::parse("v1.2.3"), Some(Version(1, 2, 3)));
        assert_eq!(Version::parse("0.10"), Some(Version(0, 10, 0)));
        assert_eq!(Version::parse("2.0.0-beta.1"), Some(Version(2, 0, 0)));
        assert_eq!(Version::parse("1.2.3.4"), None);
        assert_eq!(Version::parse("latest"), None);
        assert!(Version(0, 10, 0) > Version(0, 9, 9));
        assert_eq!(current_version().to_string(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn latest_release_is_read_from_the_api() {
        let json = br#"{"tag_name":"v9.1.0","body":"Faster unlock","draft":false,"prerelease":false,
            "assets":[{"name":"VaultRust.exe","browser_download_url":"https://github.com/x/VaultRust.exe"},
                      {"name":"VaultRust.exe.sig","browser_download_url":"https://github.com/x/VaultRust.exe.sig"}]}"#;
        let r = parse_latest(json, Version(1, 0, 0)).unwrap().unwrap();
        assert_eq!(r.version, Version(9, 1, 0));
        assert_eq!(r.notes, "Faster unlock");
        assert!(r.exe_url.ends_with("VaultRust.exe") && r.sig_url.ends_with(".sig"));
        // Not newer, or a pre-release: nothing to do.
        assert_eq!(parse_latest(json, Version(9, 1, 0)).unwrap(), None);
        let pre = br#"{"tag_name":"v99.0.0","prerelease":true,"assets":[]}"#;
        assert_eq!(parse_latest(pre, Version(1, 0, 0)).unwrap(), None);
        // A newer release without the signature asset is refused.
        let unsigned = br#"{"tag_name":"v99.0.0","assets":[{"name":"VaultRust.exe","browser_download_url":"https://x/y"}]}"#;
        assert_eq!(
            parse_latest(unsigned, Version(1, 0, 0)).unwrap_err(),
            UpdateError::MissingAsset(SIG_ASSET)
        );
        assert_eq!(
            parse_latest(b"<html>", Version(1, 0, 0)).unwrap_err(),
            UpdateError::BadResponse
        );
    }

    #[test]
    fn only_correctly_signed_downloads_verify() {
        let kp = keypair();
        let pk: [u8; 32] = *kp.pk;
        let exe = b"MZ fake program".to_vec();
        let v = Version(2, 0, 0);
        let sig = sign(&kp, v, &exe);
        assert_eq!(verify(v, &exe, &sig, &pk), Ok(()));
        // Tampered program, other version (downgrade / replay), other key,
        // garbage signature.
        let mut bad = exe.clone();
        bad[0] ^= 1;
        assert_eq!(verify(v, &bad, &sig, &pk), Err(UpdateError::BadSignature));
        assert_eq!(
            verify(Version(2, 0, 1), &exe, &sig, &pk),
            Err(UpdateError::BadSignature)
        );
        let other = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([8; 32]));
        assert_eq!(
            verify(v, &exe, &sig, &other.pk),
            Err(UpdateError::BadSignature)
        );
        assert_eq!(verify(v, &exe, b"zz", &pk), Err(UpdateError::BadSignature));
    }

    #[test]
    fn the_built_in_key_is_a_real_key() {
        assert_ne!(PUBLIC_KEY, [0; 32], "set PUBLIC_KEY (docs/RELEASING.md)");
    }

    #[test]
    fn install_swaps_the_program_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("VaultRust.exe");
        std::fs::write(&exe, b"old").unwrap();
        install(&exe, b"new").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(
            std::fs::read(dir.path().join("VaultRust.old.exe")).unwrap(),
            b"old"
        );
        clean_up(&exe);
        assert!(!dir.path().join("VaultRust.old.exe").exists());
        // A missing program can't be replaced, and nothing is left behind.
        let missing = dir.path().join("Gone.exe");
        assert!(install(&missing, b"x").is_err());
        assert!(!dir.path().join("Gone.new.exe").exists());
    }
}

#[cfg(all(test, windows))]
mod network_tests {
    /// Talks to the real GitHub API.
    #[test]
    #[ignore = "uses the network"]
    fn real_github_check() {
        let r = super::check();
        eprintln!("check(): {r:?}");
        assert!(r.is_ok(), "{r:?}");
        // What an older install sees: the latest release, downloaded and
        // verified with the built-in key.
        let url = format!(
            "https://api.github.com/repos/{}/releases/latest",
            super::REPO
        );
        if let Ok(json) = crate::os_protect::http_get(&url, super::MAX_API_BYTES) {
            if let Some(rel) = super::parse_latest(&json, super::Version(0, 0, 1)).unwrap() {
                let exe = super::download(&rel).expect("download and verify");
                eprintln!(
                    "v{} downloaded and verified: {} bytes",
                    rel.version,
                    exe.len()
                );
                assert!(exe.starts_with(b"MZ"));
            }
        }
        // Plain http and other schemes are refused before connecting.
        assert_eq!(
            crate::os_protect::http_get("http://github.com/", 10),
            Err(crate::os_protect::HttpError::NotHttps)
        );
    }
}
