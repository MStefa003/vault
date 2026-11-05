//! End-to-end tests for key files, Unicode-normalised passwords, automatic
//! backups and the schema v4 data (trash, password history, tags).

use std::fs;
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use vaultrust::crypto::{KdfParams, KeyFile};
use vaultrust::format::VaultFile;
use vaultrust::model::{Entry, EntryKind, FieldKind};
use vaultrust::storage;
use vaultrust::vault::{restore_backup, restore_backup_with, Credentials};
use vaultrust::{UnlockedVault, VaultError};

const PW: &str = "correct horse battery staple";

fn fast() -> KdfParams {
    KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).unwrap()
}

fn pw(s: &str) -> SecretString {
    SecretString::from(s)
}

fn creds(p: &str, key: Option<&KeyFile>) -> Credentials {
    Credentials::with_key_file(pw(p), key.cloned())
}

fn path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

fn with_items(v: &mut UnlockedVault) {
    for i in 0..3 {
        let mut e = Entry::new(EntryKind::Login);
        e.title = format!("item {i}");
        e.fields[3].value = format!("password {i}");
        v.data_mut().upsert(e);
    }
    v.save().unwrap();
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn key_file_is_required_and_must_match() {
    let dir = tempfile::tempdir().unwrap();
    let p = path(&dir, "kf.vault");
    let key = KeyFile::from_bytes(b"the key file contents");
    let mut v =
        UnlockedVault::create_with(&p, &creds(PW, Some(&key)), fast(), "kf", false).unwrap();
    assert!(v.uses_key_file());
    with_items(&mut v);
    let expected = v.data().clone();
    drop(v);

    // The header advertises the key file (KDF id 2).
    let bytes = fs::read(&p).unwrap();
    assert_eq!(bytes[10], 2);
    assert!(VaultFile::from_bytes(&bytes).unwrap().header.key_file);

    assert!(matches!(
        UnlockedVault::open(&p, &pw(PW)),
        Err(VaultError::KeyFileRequired)
    ));
    let wrong = KeyFile::from_bytes(b"some other file");
    assert!(matches!(
        UnlockedVault::open_with(&p, &creds(PW, Some(&wrong))),
        Err(VaultError::WrongPasswordOrTampered)
    ));
    assert!(matches!(
        UnlockedVault::open_with(&p, &creds("wrong password", Some(&key))),
        Err(VaultError::WrongPasswordOrTampered)
    ));
    let v = UnlockedVault::open_with(&p, &creds(PW, Some(&key))).unwrap();
    assert_eq!(v.data(), &expected);
    // Re-authentication needs only the password: the session keeps the key
    // file, like the vault key.
    assert!(v.verify_password(&pw(PW)));
    assert!(!v.verify_password(&pw("wrong password")));
    drop(v);

    // Downgrading the header to "no key file" is detected (the KDF id is
    // covered by the key-wrap AAD).
    let mut tampered = bytes.clone();
    tampered[10] = 1;
    fs::write(&p, &tampered).unwrap();
    assert!(UnlockedVault::open(&p, &pw(PW)).is_err());
    assert!(UnlockedVault::open_with(&p, &creds(PW, Some(&key))).is_err());
}

#[test]
fn key_file_can_be_added_changed_and_removed() {
    let dir = tempfile::tempdir().unwrap();
    let p = path(&dir, "kf2.vault");
    let mut v = UnlockedVault::create(&p, &pw(PW), fast(), "kf2", false).unwrap();
    with_items(&mut v);
    let payload_before = VaultFile::from_bytes(&fs::read(&p).unwrap())
        .unwrap()
        .payload;

    let a = KeyFile::from_bytes(b"key A");
    let task = v.credentials_change_task(creds(PW, None), creds(PW, Some(&a)), fast());
    v.apply_password_change(task.run().unwrap()).unwrap();
    assert!(v.uses_key_file());
    assert!(UnlockedVault::open(&p, &pw(PW)).is_err());
    assert!(UnlockedVault::open_with(&p, &creds(PW, Some(&a))).is_ok());
    // Only the header changed; the encrypted payload is untouched.
    let after = VaultFile::from_bytes(&fs::read(&p).unwrap()).unwrap();
    assert_eq!(after.payload, payload_before);

    // A password-only change keeps the key file.
    v.change_password(&pw(PW), &pw("second master password"), fast())
        .unwrap();
    assert!(UnlockedVault::open_with(&p, &creds("second master password", Some(&a))).is_ok());
    assert!(UnlockedVault::open(&p, &pw("second master password")).is_err());

    // The current key file is needed to change anything.
    let b = KeyFile::from_bytes(b"key B");
    let bad = v.credentials_change_task(
        creds("second master password", Some(&b)),
        creds("second master password", None),
        fast(),
    );
    assert!(bad.run().is_err());

    // Remove it again.
    let task = v.credentials_change_task(
        creds("second master password", Some(&a)),
        creds("second master password", None),
        fast(),
    );
    v.apply_password_change(task.run().unwrap()).unwrap();
    assert!(!v.uses_key_file());
    assert!(UnlockedVault::open(&p, &pw("second master password")).is_ok());
}

#[test]
fn key_file_backups_restore_only_with_the_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = path(&dir, "kf3.vault");
    let key = KeyFile::from_bytes(b"backup key");
    let mut v =
        UnlockedVault::create_with(&p, &creds(PW, Some(&key)), fast(), "kf", false).unwrap();
    with_items(&mut v);
    let b = path(&dir, "kf3-backup.vault");
    v.backup_to(&b, false).unwrap();
    let dest = path(&dir, "restored.vault");
    assert!(restore_backup(&b, &pw(PW), &dest, false).is_err());
    assert!(!dest.exists(), "nothing written before authentication");
    let r = restore_backup_with(&b, &creds(PW, Some(&key)), &dest, false).unwrap();
    assert_eq!(r.data(), v.data());
}

#[test]
fn key_files_on_disk_and_empty_files() {
    let dir = tempfile::tempdir().unwrap();
    let kf = path(&dir, "my.keyfile");
    fs::write(&kf, &*KeyFile::generate_contents()).unwrap();
    let a = KeyFile::from_path(&kf).unwrap();
    let p = path(&dir, "disk.vault");
    UnlockedVault::create_with(&p, &creds(PW, Some(&a)), fast(), "d", false).unwrap();
    let again = KeyFile::from_path(&kf).unwrap();
    assert!(UnlockedVault::open_with(&p, &creds(PW, Some(&again))).is_ok());

    let empty = path(&dir, "empty.keyfile");
    fs::write(&empty, b"").unwrap();
    assert!(KeyFile::from_path(&empty).is_err());
    assert!(KeyFile::from_path(Path::new("does-not-exist.keyfile")).is_err());
}

#[test]
fn composed_and_decomposed_passwords_open_the_same_vault() {
    let dir = tempfile::tempdir().unwrap();
    let p = path(&dir, "nfc.vault");
    // Precomposed é/è versus e + combining accents: identical on screen.
    let composed = "caf\u{e9} cr\u{e8}me 2024";
    let decomposed = "cafe\u{301} cre\u{300}me 2024";
    assert_ne!(composed.as_bytes(), decomposed.as_bytes());
    UnlockedVault::create(&p, &pw(decomposed), fast(), "nfc", false).unwrap();
    assert!(UnlockedVault::open(&p, &pw(composed)).is_ok());
    assert!(UnlockedVault::open(&p, &pw(decomposed)).is_ok());
    assert!(UnlockedVault::open(&p, &pw("cafe creme 2024")).is_err());
}

#[test]
fn automatic_backups_keep_previous_versions() {
    let dir = tempfile::tempdir().unwrap();
    let p = path(&dir, "auto.vault");
    let mut v = UnlockedVault::create(&p, &pw(PW), fast(), "auto", false).unwrap();
    // The first save after creation keeps the just-created file; later
    // saves within the hour add nothing.
    let first_image = fs::read(&p).unwrap();
    v.data_mut().settings.auto_backup_count = 3;
    v.save().unwrap();
    let mut e = Entry::new(EntryKind::Login);
    e.title = "added later".into();
    v.data_mut().upsert(e);
    v.save().unwrap();

    let backups = storage::list_auto_backups(&p);
    assert_eq!(backups.len(), 1, "at most one copy per interval");
    assert!(backups[0].starts_with(dir.path().join("auto.vault.backups")));
    assert_eq!(fs::read(&backups[0]).unwrap(), first_image);
    // The copy is a complete vault that opens with the same password.
    let old = UnlockedVault::open(&backups[0], &pw(PW)).unwrap();
    assert!(old.data().entries.is_empty());

    // Overwriting another window's change keeps that version first.
    let mut other = UnlockedVault::open(&p, &pw(PW)).unwrap();
    other.data_mut().name = "changed elsewhere".into();
    other.save().unwrap();
    let theirs = fs::read(&p).unwrap();
    v.data_mut().name = "mine".into();
    assert!(matches!(v.save(), Err(VaultError::ModifiedExternally)));
    v.save_overwriting_external_changes().unwrap();
    let backups = storage::list_auto_backups(&p);
    assert!(backups.iter().any(|b| fs::read(b).unwrap() == theirs));
    assert!(v.take_auto_backup_warning().is_none());

    // Turned off: no further copies.
    v.data_mut().settings.auto_backup_count = 0;
    let n = storage::list_auto_backups(&p).len();
    v.save().unwrap();
    v.data_mut().name = "again".into();
    v.save_overwriting_external_changes().unwrap();
    assert_eq!(storage::list_auto_backups(&p).len(), n);
}

#[test]
fn trash_history_and_tags_persist_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let p = path(&dir, "v4.vault");
    let mut v = UnlockedVault::create(&p, &pw(PW), fast(), "v4", false).unwrap();
    let mut e = Entry::new(EntryKind::Login);
    e.title = "Bank".into();
    e.add_tag("TAG-MARKER-finance");
    e.fields[3].value = "OLD-PASSWORD-MARKER-1".into();
    let id = e.id;
    v.data_mut().upsert(e);
    let mut edit = v.data().entry(id).unwrap().clone();
    edit.fields[3].value = "new password".into();
    v.data_mut().upsert(edit);
    let mut doomed = Entry::new(EntryKind::SecureNote);
    doomed.title = "TRASH-MARKER-title".into();
    let doomed_id = doomed.id;
    v.data_mut().upsert(doomed);
    v.data_mut().trash_entry(doomed_id);
    v.save().unwrap();

    let raw = fs::read(&p).unwrap();
    for marker in [
        "TAG-MARKER-finance",
        "OLD-PASSWORD-MARKER-1",
        "TRASH-MARKER-title",
    ] {
        assert!(!contains(&raw, marker), "{marker} leaked into the file");
    }
    let back = UnlockedVault::open(&p, &pw(PW)).unwrap();
    let bank = back.data().entry(id).unwrap();
    assert_eq!(bank.tags, ["TAG-MARKER-finance"]);
    assert_eq!(bank.history[0].value, "OLD-PASSWORD-MARKER-1");
    assert_eq!(bank.first_of(FieldKind::Password), Some("new password"));
    assert_eq!(back.data().trash[0].entry.title, "TRASH-MARKER-title");
}
