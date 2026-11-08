//! List of recently opened vault *paths* (never contents or passwords),
//! stored in `%APPDATA%\VaultRust\recent.txt` (next to the program in
//! portable mode) so the welcome screen can offer them. The user can clear it
//! from Settings.

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::storage::{atomic_write, WriteMode};

const MAX_RECENT: usize = 8;

fn store_path() -> Option<PathBuf> {
    Some(crate::portable::settings_dir()?.join("recent.txt"))
}

/// The drive (or network share) a path is on, e.g. `E:`.
fn drive(path: &Path) -> Option<String> {
    match path.components().next() {
        Some(Component::Prefix(p)) => Some(p.as_os_str().to_string_lossy().to_uppercase()),
        _ => None,
    }
}

/// A portable copy's drive letter changes from computer to computer, so
/// vaults on its drive are stored without it (`\Passwords\My.vault`).
fn encode(path: &Path, program_dir: Option<&Path>) -> PathBuf {
    let own = program_dir.and_then(drive);
    match drive(path) {
        Some(d) if Some(&d) == own.as_ref() => path.components().skip(1).collect(),
        _ => path.to_path_buf(),
    }
}

/// The inverse of [`encode`]: put the program's drive back.
fn decode(stored: &str, program_dir: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(stored);
    let prefix = program_dir.and_then(|d| d.components().next());
    match prefix {
        Some(p @ Component::Prefix(_)) if path.has_root() && drive(&path).is_none() => {
            Path::new(p.as_os_str()).join(&path)
        }
        _ => path,
    }
}

#[derive(Debug, Default, Clone)]
pub struct RecentVaults {
    pub paths: Vec<PathBuf>,
    persist: bool,
}

impl RecentVaults {
    pub fn load() -> Self {
        let Some(p) = store_path() else {
            return Self::default();
        };
        let paths = fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| decode(l, crate::portable::program_dir()))
            .take(MAX_RECENT)
            .collect();
        RecentVaults {
            paths,
            persist: true,
        }
    }

    /// A list that is never written to disk (used by tests).
    pub fn in_memory() -> Self {
        RecentVaults::default()
    }

    pub fn push(&mut self, path: &Path) {
        let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let path = strip_verbatim(path);
        self.paths.retain(|p| p != &path);
        self.paths.insert(0, path);
        self.paths.truncate(MAX_RECENT);
        self.save();
    }

    pub fn remove(&mut self, path: &Path) {
        self.paths.retain(|p| p != path);
        self.save();
    }

    pub fn clear(&mut self) {
        self.paths.clear();
        self.save();
    }

    fn save(&self) {
        if !self.persist {
            return;
        }
        let Some(p) = store_path() else { return };
        if let Some(dir) = p.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let body: String = self
            .paths
            .iter()
            .map(|p| format!("{}\n", encode(p, crate::portable::program_dir()).display()))
            .collect();
        let _ = atomic_write(&p, body.as_bytes(), WriteMode::Replace);
    }
}

/// `canonicalize` on Windows yields `\\?\C:\...`; show the familiar form.
fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => PathBuf::from(rest),
        _ => p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_mode_stores_paths_as_they_are() {
        let p = Path::new("/home/ann/My.vault");
        assert_eq!(encode(p, None), p);
        assert_eq!(decode("/home/ann/My.vault", None), p);
    }

    #[cfg(windows)]
    #[test]
    fn portable_mode_drops_its_own_drive_letter() {
        let program = Some(Path::new(r"E:\VaultRust"));
        let on_stick = encode(Path::new(r"E:\Passwords\My.vault"), program);
        assert_eq!(on_stick, Path::new(r"\Passwords\My.vault"));
        // On another computer the stick is F:.
        let there = Some(Path::new(r"F:\VaultRust"));
        assert_eq!(
            decode(&on_stick.display().to_string(), there),
            Path::new(r"F:\Passwords\My.vault")
        );
        // Vaults on other drives keep theirs.
        let other = Path::new(r"C:\Users\ann\My.vault");
        assert_eq!(encode(other, program), other);
        assert_eq!(decode(r"C:\Users\ann\My.vault", there), other);
    }
}
