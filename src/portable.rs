//! Portable mode: VaultRust run from a USB stick (or any folder) keeps its
//! settings next to the program instead of in the computer's user profile,
//! so it can be used on any computer and leaves nothing behind there.
//!
//! It is on when a file named [`MARKER`] sits next to `VaultRust.exe`.
//! Settings and the recent-vaults list then live in [`DATA_DIR`] beside it,
//! and the features that have to change the computer itself (Start with
//! Windows, the browser extension, Windows Hello and the installer's entry
//! in Settings → Apps) are off.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::i18n::tr;
use crate::storage::{atomic_write, WriteMode};

/// The file that turns portable mode on.
pub const MARKER: &str = "portable.txt";
/// The folder next to the program that holds its settings.
pub const DATA_DIR: &str = "VaultRust data";
/// Name of the program in a portable copy.
const EXE_NAME: &str = "VaultRust.exe";

const MARKER_TEXT: &str = "\
This file makes VaultRust portable: it keeps its settings in the
\"VaultRust data\" folder next to it instead of on the computer, and doesn't
set anything up on the computers it runs on.

Delete this file to make it a normal copy of VaultRust again.
";

/// The folder of the program, if VaultRust runs in portable mode. Tests
/// always run in normal mode.
pub fn program_dir() -> Option<&'static Path> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        if cfg!(test) {
            return None;
        }
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        dir.join(MARKER).is_file().then(|| dir.to_path_buf())
    })
    .as_deref()
}

/// Whether VaultRust runs in portable mode.
pub fn is_on() -> bool {
    program_dir().is_some()
}

/// Where app settings are kept: `<program>\VaultRust data` in portable
/// mode, `%APPDATA%\VaultRust` otherwise.
pub fn settings_dir() -> Option<PathBuf> {
    if let Some(dir) = program_dir() {
        return Some(dir.join(DATA_DIR));
    }
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(PathBuf::from)?;
    Some(base.join("VaultRust"))
}

/// Put a portable VaultRust in `folder` (say, a USB stick): a copy of this
/// program and the marker file. Never replaces an existing program. Returns
/// the new program's path.
pub fn create_copy(folder: &Path) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    create_copy_of(&exe, folder)
}

fn create_copy_of(exe: &Path, folder: &Path) -> Result<PathBuf, String> {
    let target = folder.join(EXE_NAME);
    if target.exists() {
        return Err(tr("That folder already has VaultRust in it").to_string());
    }
    std::fs::copy(exe, &target).map_err(|e| {
        let _ = std::fs::remove_file(&target);
        e.to_string()
    })?;
    let marker = folder.join(MARKER);
    if !marker.is_file() {
        if let Err(e) = atomic_write(&marker, MARKER_TEXT.as_bytes(), WriteMode::CreateNew) {
            let _ = std::fs::remove_file(&target);
            return Err(e.to_string());
        }
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_run_in_normal_mode() {
        assert!(!is_on());
    }

    #[test]
    fn copy_has_program_and_marker_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("source.exe");
        std::fs::write(&exe, b"program").unwrap();
        let stick = dir.path().join("stick");
        std::fs::create_dir(&stick).unwrap();

        let made = create_copy_of(&exe, &stick).unwrap();
        assert_eq!(made, stick.join(EXE_NAME));
        assert_eq!(std::fs::read(&made).unwrap(), b"program");
        assert!(std::fs::read_to_string(stick.join(MARKER))
            .unwrap()
            .contains("portable"));

        std::fs::write(&exe, b"newer").unwrap();
        assert!(create_copy_of(&exe, &stick).is_err());
        assert_eq!(std::fs::read(&made).unwrap(), b"program");
    }
}
