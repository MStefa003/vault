//! App-level preferences that must be known before any vault is unlocked:
//! the colour theme and what the window's close button does. Stored in
//! `%APPDATA%\VaultRust\prefs.txt` as `key=value` lines. Nothing here is
//! secret; everything vault-specific stays inside the encrypted vault.

use std::fs;
use std::path::PathBuf;

use crate::storage::{atomic_write, WriteMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemePref {
    /// Follow the Windows light / dark setting.
    #[default]
    System,
    Light,
    Dark,
}

impl ThemePref {
    pub const ALL: [ThemePref; 3] = [ThemePref::System, ThemePref::Light, ThemePref::Dark];

    pub fn label(self) -> &'static str {
        match self {
            ThemePref::System => "System",
            ThemePref::Light => "Light",
            ThemePref::Dark => "Dark",
        }
    }

    fn key(self) -> &'static str {
        match self {
            ThemePref::System => "system",
            ThemePref::Light => "light",
            ThemePref::Dark => "dark",
        }
    }

    /// Whether to draw dark, given what Windows reports (`None` = unknown).
    pub fn is_dark(self, system_dark: Option<bool>) -> bool {
        match self {
            ThemePref::System => system_dark.unwrap_or(true),
            ThemePref::Light => false,
            ThemePref::Dark => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPrefs {
    pub theme: ThemePref,
    /// Closing the window locks the vault and keeps VaultRust in the
    /// notification area instead of quitting.
    pub close_to_tray: bool,
    /// Ask GitHub once a day whether a newer release exists.
    pub check_updates: bool,
    /// When that was last done (unix seconds).
    pub last_update_check: i64,
    persist: bool,
}

impl Default for AppPrefs {
    fn default() -> Self {
        AppPrefs {
            theme: ThemePref::System,
            close_to_tray: false,
            check_updates: true,
            last_update_check: 0,
            persist: false,
        }
    }
}

fn store_path() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(PathBuf::from)?;
    Some(base.join("VaultRust").join("prefs.txt"))
}

impl AppPrefs {
    pub fn load() -> Self {
        let mut prefs = Self::parse(
            &store_path()
                .and_then(|p| fs::read_to_string(p).ok())
                .unwrap_or_default(),
        );
        prefs.persist = true;
        prefs
    }

    /// Preferences that are never written to disk (used by tests).
    pub fn in_memory() -> Self {
        AppPrefs::default()
    }

    fn parse(text: &str) -> Self {
        let mut prefs = AppPrefs::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match (k.trim(), v.trim()) {
                ("theme", v) => {
                    if let Some(t) = ThemePref::ALL.into_iter().find(|t| t.key() == v) {
                        prefs.theme = t;
                    }
                }
                // Stored under a new key: the old `close_to_tray` defaulted
                // to on, and closing the window should quit unless asked.
                ("keep_in_tray", v) => prefs.close_to_tray = v == "true",
                ("check_updates", v) => prefs.check_updates = v != "false",
                ("last_update_check", v) => prefs.last_update_check = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        prefs
    }

    fn serialize(&self) -> String {
        format!(
            "theme={}\nkeep_in_tray={}\ncheck_updates={}\nlast_update_check={}\n",
            self.theme.key(),
            self.close_to_tray,
            self.check_updates,
            self.last_update_check
        )
    }

    pub fn save(&self) {
        if !self.persist {
            return;
        }
        let Some(p) = store_path() else { return };
        if let Some(dir) = p.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let _ = atomic_write(&p, self.serialize().as_bytes(), WriteMode::Replace);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tolerant_parsing() {
        let p = AppPrefs {
            theme: ThemePref::Light,
            close_to_tray: false,
            check_updates: false,
            last_update_check: 1_700_000_000,
            persist: false,
        };
        assert_eq!(AppPrefs::parse(&p.serialize()), p);
        let d = AppPrefs::parse("garbage\ntheme=purple\n");
        assert_eq!(d, AppPrefs::default());
        assert!(ThemePref::System.is_dark(None));
        assert!(!ThemePref::System.is_dark(Some(false)));
        assert!(ThemePref::Dark.is_dark(Some(false)));
    }
}
