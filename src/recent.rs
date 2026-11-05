//! List of recently opened vault *paths* (never contents or passwords),
//! stored in `%APPDATA%\VaultRust\recent.txt` so the welcome screen can offer
//! them. The user can clear it from Settings.

use std::fs;
use std::path::{Path, PathBuf};

use crate::storage::{atomic_write, WriteMode};

const MAX_RECENT: usize = 8;

fn store_path() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(PathBuf::from)?;
    Some(base.join("VaultRust").join("recent.txt"))
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
            .map(PathBuf::from)
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
            .map(|p| format!("{}\n", p.display()))
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
