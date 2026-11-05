//! Crash-safe file operations.
//!
//! Only ciphertext ever passes through this module. Writes go to a temporary
//! file in the destination directory, are flushed to stable storage, and are
//! then atomically moved into place, so an interrupted write (crash, power
//! loss, killed process) leaves either the complete old file or the complete
//! new file — never a partial one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::random_array;
use crate::error::{Result, VaultError};
use crate::format::{HEADER_LEN, MAX_PAYLOAD_LEN};

pub const VAULT_EXTENSION: &str = "vault";
const TEMP_EXTENSION: &str = "vrtmp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Fail with [`VaultError::AlreadyExists`] if the destination exists.
    CreateNew,
    /// Atomically replace the destination if it exists. Callers must have
    /// obtained explicit user confirmation before using this on a file the
    /// user did not just open.
    Replace,
}

/// Atomically write `bytes` to `path`.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: WriteMode) -> Result<()> {
    atomic_write_with(path, mode, |f| f.write_all(bytes))
}

/// Atomic write with a caller-supplied writer. Exposed for fault-injection
/// tests that simulate a write being interrupted part-way through.
pub fn atomic_write_with<F>(path: &Path, mode: WriteMode, write: F) -> Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    if mode == WriteMode::CreateNew && path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    let tmp = temp_path_for(path);
    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        write(&mut f)?;
        f.flush()?;
        f.sync_all()?;
        drop(f);
        match mode {
            WriteMode::Replace => rename_with_retry(&tmp, path)?,
            WriteMode::CreateNew => link_no_overwrite(&tmp, path)?,
        }
        sync_parent_dir(path);
        Ok(())
    })();
    // Whatever happened, never leave the temporary file behind.
    if tmp.exists() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Atomic replace. On Windows, antivirus scanners and the search indexer
/// briefly open freshly written files, which makes an immediate rename fail
/// with "access denied"; retry for up to about a second before giving up.
fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    let mut attempt = 0u64;
    loop {
        match fs::rename(from, to) {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied && attempt < 10 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(15 * attempt));
            }
            other => return other,
        }
    }
}

/// Move `tmp` to `dest` without ever replacing an existing `dest`.
fn link_no_overwrite(tmp: &Path, dest: &Path) -> Result<()> {
    // A hard link fails atomically if the destination exists.
    match fs::hard_link(tmp, dest) {
        Ok(()) => {
            fs::remove_file(tmp)?;
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(VaultError::AlreadyExists),
        Err(_) => {
            // File systems without hard links (FAT/exFAT USB drives). Fall
            // back to check-then-rename; the window is tiny and local.
            if dest.exists() {
                return Err(VaultError::AlreadyExists);
            }
            fs::rename(tmp, dest)?;
            Ok(())
        }
    }
}

/// Move or rename a file without overwriting an existing destination. Works
/// across volumes by copying and then removing the source.
pub fn move_no_overwrite(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        return Err(VaultError::AlreadyExists);
    }
    match fs::hard_link(from, to) {
        Ok(()) => {
            fs::remove_file(from)?;
            return Ok(());
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(VaultError::AlreadyExists)
        }
        Err(_) => {}
    }
    if to.exists() {
        return Err(VaultError::AlreadyExists);
    }
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    // Cross-volume: copy safely, then remove the original.
    let bytes = read_vault_bytes(from)?;
    atomic_write(to, &bytes, WriteMode::CreateNew)?;
    fs::remove_file(from)?;
    Ok(())
}

/// Read a vault file, refusing anything larger than the format allows before
/// reading it into memory.
pub fn read_vault_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let max = HEADER_LEN as u64 + MAX_PAYLOAD_LEN;
    if len > max {
        return Err(VaultError::TooLarge);
    }
    let mut buf = Vec::with_capacity(len as usize);
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(VaultError::TooLarge);
    }
    Ok(buf)
}

fn temp_path_for(path: &Path) -> PathBuf {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".into());
    let rnd: [u8; 8] = random_array();
    let hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    dir.join(format!(".{name}.{hex}.{TEMP_EXTENSION}"))
}

/// Remove temporary files left by a write that was interrupted by a crash or
/// power loss. They only ever contain ciphertext.
pub fn cleanup_stale_temp_files(vault_path: &Path) {
    let Some(dir) = vault_path.parent() else {
        return;
    };
    let Some(name) = vault_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
    else {
        return;
    };
    let prefix = format!(".{name}.");
    let suffix = format!(".{TEMP_EXTENSION}");
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(&prefix) && n.ends_with(&suffix) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    if let Some(dir) = path.parent() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) {
    // NTFS journals the rename metadata; directory handles cannot be fsynced
    // on Windows.
}

/// Folder for automatic backups: `<vault file name>.backups` next to it.
pub fn auto_backup_dir(vault_path: &Path) -> PathBuf {
    let dir = vault_path.parent().unwrap_or_else(|| Path::new("."));
    let name = vault_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".into());
    dir.join(format!("{name}.backups"))
}

fn auto_backup_prefix(vault_path: &Path) -> String {
    let stem = vault_path
        .file_stem()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".into());
    format!("{stem}-auto-")
}

/// Automatic backups of `vault_path`, newest first. Names carry a sortable
/// UTC timestamp: `<stem>-auto-YYYYMMDD-HHMMSS.vault`.
pub fn list_auto_backups(vault_path: &Path) -> Vec<PathBuf> {
    let dir = auto_backup_dir(vault_path);
    let prefix = auto_backup_prefix(vault_path);
    let suffix = format!(".{VAULT_EXTENSION}");
    let mut found: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n.starts_with(&prefix) && n.ends_with(&suffix)
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found.reverse();
    found
}

/// Write `bytes` (an encrypted vault image) as a new automatic backup unless
/// the newest one is younger than `min_interval_secs`, then delete all but
/// the newest `keep` backups.
pub fn write_rotating_backup(
    vault_path: &Path,
    bytes: &[u8],
    keep: usize,
    now: i64,
    min_interval_secs: i64,
) -> Result<()> {
    let prefix = auto_backup_prefix(vault_path);
    let existing = list_auto_backups(vault_path);
    let newest_allowed = format!(
        "{prefix}{}",
        crate::timeutil::file_stamp(now - min_interval_secs)
    );
    let recent = existing.first().is_some_and(|p| {
        min_interval_secs > 0
            && p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .is_some_and(|n| n.as_str() > newest_allowed.as_str())
    });
    if !recent {
        let dir = auto_backup_dir(vault_path);
        fs::create_dir_all(&dir)?;
        let mut name = format!(
            "{prefix}{}.{VAULT_EXTENSION}",
            crate::timeutil::file_stamp(now)
        );
        // Two forced backups within the same second get distinct names.
        let mut n = 1;
        while dir.join(&name).exists() {
            n += 1;
            name = format!(
                "{prefix}{}-{n}.{VAULT_EXTENSION}",
                crate::timeutil::file_stamp(now)
            );
        }
        atomic_write(&dir.join(name), bytes, WriteMode::CreateNew)?;
    }
    for old in list_auto_backups(vault_path).into_iter().skip(keep.max(1)) {
        let _ = fs::remove_file(old);
    }
    Ok(())
}

/// Ensure a path ends in `.vault`.
pub fn with_vault_extension(path: PathBuf) -> PathBuf {
    match path.extension() {
        Some(ext) if ext.eq_ignore_ascii_case(VAULT_EXTENSION) => path,
        _ => {
            let mut s = path.into_os_string();
            s.push(".");
            s.push(VAULT_EXTENSION);
            PathBuf::from(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_refuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");
        atomic_write(&p, b"one", WriteMode::CreateNew).unwrap();
        assert!(matches!(
            atomic_write(&p, b"two", WriteMode::CreateNew),
            Err(VaultError::AlreadyExists)
        ));
        assert_eq!(fs::read(&p).unwrap(), b"one");
    }

    #[test]
    fn replace_overwrites_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");
        atomic_write(&p, b"one", WriteMode::CreateNew).unwrap();
        atomic_write(&p, b"two", WriteMode::Replace).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn interrupted_write_keeps_original_intact() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");
        atomic_write(&p, b"original contents", WriteMode::CreateNew).unwrap();
        let err = atomic_write_with(&p, WriteMode::Replace, |f| {
            f.write_all(b"partial")?;
            Err(io::Error::other("simulated crash mid-write"))
        });
        assert!(err.is_err());
        assert_eq!(fs::read(&p).unwrap(), b"original contents");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "temp file left behind"
        );
    }

    #[test]
    fn stale_temp_files_are_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.vault");
        fs::write(dir.path().join(".a.vault.0011223344556677.vrtmp"), b"x").unwrap();
        fs::write(dir.path().join("unrelated.txt"), b"x").unwrap();
        cleanup_stale_temp_files(&p);
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["unrelated.txt".to_string()]);
    }

    #[test]
    fn move_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.vault");
        let b = dir.path().join("b.vault");
        fs::write(&a, b"a").unwrap();
        fs::write(&b, b"b").unwrap();
        assert!(matches!(
            move_no_overwrite(&a, &b),
            Err(VaultError::AlreadyExists)
        ));
        assert_eq!(fs::read(&b).unwrap(), b"b");
        let c = dir.path().join("c.vault");
        move_no_overwrite(&a, &c).unwrap();
        assert!(!a.exists());
        assert_eq!(fs::read(&c).unwrap(), b"a");
    }

    #[test]
    fn rotating_backups_respect_interval_and_limit() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Personal.vault");
        let t0 = 1_700_000_000;
        write_rotating_backup(&p, b"v1", 3, t0, 3600).unwrap();
        // Within the interval: no new copy.
        write_rotating_backup(&p, b"v2", 3, t0 + 60, 3600).unwrap();
        assert_eq!(list_auto_backups(&p).len(), 1);
        for i in 1..=5 {
            write_rotating_backup(&p, format!("v{i}").as_bytes(), 3, t0 + i * 3601, 3600).unwrap();
        }
        let all = list_auto_backups(&p);
        assert_eq!(all.len(), 3, "only the newest three are kept");
        assert_eq!(fs::read(&all[0]).unwrap(), b"v5");
        assert_eq!(fs::read(&all[2]).unwrap(), b"v3");
        assert!(all[0].parent().unwrap().ends_with("Personal.vault.backups"));
        // Forced backups ignore the interval and never collide.
        write_rotating_backup(&p, b"f1", 10, t0 + 5 * 3601, 0).unwrap();
        write_rotating_backup(&p, b"f2", 10, t0 + 5 * 3601, 0).unwrap();
        assert_eq!(list_auto_backups(&p).len(), 5);
    }

    #[test]
    fn extension_is_added() {
        assert_eq!(with_vault_extension("x".into()), PathBuf::from("x.vault"));
        assert_eq!(
            with_vault_extension("x.VAULT".into()),
            PathBuf::from("x.VAULT")
        );
        assert_eq!(
            with_vault_extension("x.txt".into()),
            PathBuf::from("x.txt.vault")
        );
    }
}
