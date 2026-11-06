//! App-level preferences that must be known before any vault is unlocked:
//! the colour theme and what the window's close button does. Stored in
//! `%APPDATA%\VaultRust\prefs.txt` as `key=value` lines. Nothing here is
//! secret; everything vault-specific stays inside the encrypted vault.

use std::fs;
use std::path::PathBuf;

use crate::i18n::Language;
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
        crate::i18n::tr(match self {
            ThemePref::System => "System",
            ThemePref::Light => "Light",
            ThemePref::Dark => "Dark",
        })
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
    /// The welcome tour was finished or skipped.
    pub tour_seen: bool,
    /// Interface language (`None` = the Windows display language, if
    /// VaultRust has it, otherwise English).
    pub language: Option<Language>,
    /// The browser extension may fill in logins.
    pub browser_enabled: bool,
    /// Browsers the user allowed to connect.
    pub browser_pairings: Vec<BrowserPairing>,
    persist: bool,
}

/// A browser allowed to use the extension: the SHA-256 of its token (see
/// `browser.rs`), which browser it said it was, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserPairing {
    pub hash: String,
    pub browser: String,
    pub added: i64,
}

/// Approved browsers kept at most (the oldest are dropped).
pub const MAX_BROWSER_PAIRINGS: usize = 20;

impl Default for AppPrefs {
    fn default() -> Self {
        AppPrefs {
            theme: ThemePref::System,
            close_to_tray: false,
            check_updates: true,
            last_update_check: 0,
            tour_seen: false,
            language: None,
            browser_enabled: false,
            browser_pairings: Vec::new(),
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
        AppPrefs {
            tour_seen: true,
            ..AppPrefs::default()
        }
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
                ("tour_seen", v) => prefs.tour_seen = v == "true",
                ("language", v) => prefs.language = Language::from_key(v),
                ("browser", v) => prefs.browser_enabled = v == "on",
                ("browser_pairing", v) => {
                    let mut parts = v.splitn(3, ' ');
                    if let (Some(hash), Some(added), Some(browser)) =
                        (parts.next(), parts.next(), parts.next())
                    {
                        if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                            prefs.browser_pairings.push(BrowserPairing {
                                hash: hash.to_ascii_lowercase(),
                                browser: browser.to_string(),
                                added: added.parse().unwrap_or(0),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        prefs.browser_pairings.truncate(MAX_BROWSER_PAIRINGS);
        prefs
    }

    fn serialize(&self) -> String {
        let mut s = format!(
            "theme={}\nkeep_in_tray={}\ncheck_updates={}\nlast_update_check={}\ntour_seen={}\nlanguage={}\nbrowser={}\n",
            self.theme.key(),
            self.close_to_tray,
            self.check_updates,
            self.last_update_check,
            self.tour_seen,
            self.language.map_or("system", Language::key),
            if self.browser_enabled { "on" } else { "off" },
        );
        for p in &self.browser_pairings {
            // One line each: the name can't break out of it.
            let name: String = p.browser.chars().filter(|c| !c.is_control()).collect();
            s.push_str(&format!(
                "browser_pairing={} {} {}\n",
                p.hash, p.added, name
            ));
        }
        s
    }

    /// Allow a browser (keeping at most [`MAX_BROWSER_PAIRINGS`]).
    pub fn add_browser_pairing(&mut self, pairing: BrowserPairing) {
        self.browser_pairings.retain(|p| p.hash != pairing.hash);
        self.browser_pairings.push(pairing);
        let extra = self
            .browser_pairings
            .len()
            .saturating_sub(MAX_BROWSER_PAIRINGS);
        self.browser_pairings.drain(..extra);
    }

    /// The language to show.
    pub fn effective_language(&self) -> Language {
        self.language
            .or_else(Language::from_system)
            .unwrap_or_default()
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
            tour_seen: true,
            language: Some(Language::Greek),
            browser_enabled: true,
            browser_pairings: vec![BrowserPairing {
                hash: "ab".repeat(32),
                browser: "Microsoft Edge".into(),
                added: 1_700_000_001,
            }],
            persist: false,
        };
        assert_eq!(AppPrefs::parse(&p.serialize()), p);
        // A bad hash or a name with a line break can't inject lines.
        let mut q = p.clone();
        q.browser_pairings[0].browser = "Evil\nbrowser=off".into();
        let back = AppPrefs::parse(&q.serialize());
        assert!(back.browser_enabled);
        assert_eq!(back.browser_pairings[0].browser, "Evilbrowser=off");
        assert!(AppPrefs::parse("browser_pairing=xyz 1 Chrome")
            .browser_pairings
            .is_empty());
        for i in 0..30 {
            q.add_browser_pairing(BrowserPairing {
                hash: format!("{i:064}"),
                browser: "Chrome".into(),
                added: i,
            });
        }
        assert_eq!(q.browser_pairings.len(), MAX_BROWSER_PAIRINGS);
        assert_eq!(q.browser_pairings.last().unwrap().added, 29);
        let d = AppPrefs::parse("garbage\ntheme=purple\n");
        assert_eq!(d, AppPrefs::default());
        assert!(ThemePref::System.is_dark(None));
        assert!(!ThemePref::System.is_dark(Some(false)));
        assert!(ThemePref::Dark.is_dark(Some(false)));
    }
}
