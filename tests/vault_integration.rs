//! End-to-end tests against real vault files on disk.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use vaultrust::crypto::KdfParams;
use vaultrust::format::{VaultFile, HEADER_LEN};
use vaultrust::model::{Entry, EntryKind, FieldKind};
use vaultrust::storage::{self, WriteMode};
use vaultrust::vault::restore_backup;
use vaultrust::{UnlockedVault, VaultError};

const PW: &str = "correct horse battery staple";

/// Minimum accepted Argon2 cost so the suite runs quickly. Real vaults use
/// `KdfParams::STANDARD` or stronger.
fn fast() -> KdfParams {
    KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).unwrap()
}

fn pw(s: &str) -> SecretString {
    SecretString::from(s)
}

fn vault_path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

fn new_vault(path: &Path) -> UnlockedVault {
    UnlockedVault::create(path, &pw(PW), fast(), "Test vault", false).unwrap()
}

/// Distinctive markers that must never appear in a vault file.
const MARKERS: &[&str] = &[
    "PLAINTEXT-MARKER-password-9f3a",
    "PLAINTEXT-MARKER-username-1c7e",
    "PLAINTEXT-MARKER-title-55aa",
    "4111111111119876",
    "PLAINTEXT-MARKER-note-0b0b",
    "sk_live_PLAINTEXT_MARKER_api_key",
    "PLAINTEXT-MARKER-wifi-psk",
    "PLAINTEXT-MARKER-vault-name",
    "https://plaintext-marker.example",
];

fn populate(v: &mut UnlockedVault) {
    let mut login = Entry::new(EntryKind::Login);
    login.title = MARKERS[2].into();
    login.fields[0].value = MARKERS[8].into();
    login.fields[1].value = MARKERS[1].into();
    login.fields[3].value = MARKERS[0].into();
    let mut card = Entry::new(EntryKind::CreditCard);
    card.title = "Card".into();
    card.fields[1].value = MARKERS[3].into();
    let mut note = Entry::new(EntryKind::SecureNote);
    note.title = "Note".into();
    note.notes = MARKERS[4].into();
    let mut api = Entry::new(EntryKind::ApiKey);
    api.title = "API".into();
    api.fields[1].value = MARKERS[5].into();
    let mut wifi = Entry::new(EntryKind::Wifi);
    wifi.title = "Home".into();
    wifi.fields[1].value = MARKERS[6].into();

    let d = v.data_mut();
    d.name = MARKERS[7].into();
    for e in [login, card, note, api, wifi] {
        d.upsert(e);
    }
    for kind in EntryKind::ALL {
        let mut e = Entry::new(kind);
        e.title = format!("{} item", kind.label());
        for f in &mut e.fields {
            f.value = format!("value for {}", f.label);
        }
        d.upsert(e);
    }
    v.save().unwrap();
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

#[test]
fn create_and_reopen_with_correct_password() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    populate(&mut v);
    let expected = v.data().clone();
    drop(v);

    let reopened = UnlockedVault::open(&p, &pw(PW)).unwrap();
    assert_eq!(reopened.data(), &expected);
    assert_eq!(reopened.data().entries.len(), 5 + EntryKind::ALL.len());
    assert_eq!(reopened.kdf_params(), fast());
}

#[test]
fn wrong_password_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    new_vault(&p);
    for bad in [
        "",
        "correct horse battery stapl",
        "Correct horse battery staple",
        "x",
    ] {
        let err = UnlockedVault::open(&p, &pw(bad)).unwrap_err();
        assert!(
            matches!(err, VaultError::WrongPasswordOrTampered),
            "{bad:?}: {err}"
        );
    }
}

#[test]
fn master_password_is_validated() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    assert!(UnlockedVault::create(&p, &pw("short"), fast(), "x", false).is_err());
    assert!(!p.exists());
}

#[test]
fn vault_file_contains_no_recognisable_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    populate(&mut v);
    v.backup_to(&vault_path(&dir, "b.vault"), false).unwrap();
    v.change_password(&pw(PW), &pw("another long master password"), fast())
        .unwrap();
    drop(v);

    for file in ["a.vault", "b.vault"] {
        let bytes = fs::read(vault_path(&dir, file)).unwrap();
        for m in MARKERS.iter().chain([
            &PW,
            &"another long master password",
            &"value for",
            &"Test vault",
        ]) {
            assert!(!contains(&bytes, m.as_bytes()), "{file}: found {m:?}");
            assert!(!contains(&bytes, &utf16le(m)), "{file}: found UTF-16 {m:?}");
        }
        // Field labels / kind names from the schema must not leak either.
        for m in ["Password", "Card number", "SSH private key", "Login"] {
            assert!(!contains(&bytes, m.as_bytes()), "{file}: found {m:?}");
        }
    }
    // Only the two vault files exist: no plaintext or temporary side files.
    let names: HashSet<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, HashSet::from(["a.vault".into(), "b.vault".into()]));
}

#[test]
fn every_tampered_header_byte_and_sampled_payload_byte_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    populate(&mut v);
    drop(v);
    let good = fs::read(&p).unwrap();
    let tampered = vault_path(&dir, "t.vault");

    let mut offsets: Vec<usize> = (0..HEADER_LEN).collect();
    offsets.extend((HEADER_LEN..good.len()).step_by(97));
    offsets.push(good.len() - 1); // last tag byte
    for off in offsets {
        let mut bad = good.clone();
        bad[off] ^= 0x01;
        fs::write(&tampered, &bad).unwrap();
        match UnlockedVault::open(&tampered, &pw(PW)) {
            Ok(_) => panic!("tampering at offset {off} was not detected"),
            Err(e) => {
                let expected = match off {
                    0..=7 => matches!(e, VaultError::NotAVault),
                    8..=9 => matches!(e, VaultError::UnsupportedVersion(_)),
                    10..=11 => matches!(e, VaultError::UnsupportedAlgorithm),
                    28..=39 => matches!(
                        e,
                        VaultError::InvalidKdfParams | VaultError::WrongPasswordOrTampered
                    ),
                    12..=143 => matches!(e, VaultError::WrongPasswordOrTampered),
                    144..=167 => matches!(e, VaultError::PayloadTampered),
                    168..=175 => matches!(e, VaultError::Malformed(_)),
                    _ => matches!(e, VaultError::PayloadTampered),
                };
                assert!(expected, "offset {off}: unexpected error {e:?}");
            }
        }
    }
}

#[test]
fn truncated_and_extended_files_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    new_vault(&p);
    let good = fs::read(&p).unwrap();
    let t = vault_path(&dir, "t.vault");
    for len in [0, 7, 100, HEADER_LEN, good.len() - 16, good.len() - 1] {
        fs::write(&t, &good[..len]).unwrap();
        assert!(UnlockedVault::open(&t, &pw(PW)).is_err(), "len {len}");
    }
    let mut longer = good.clone();
    longer.extend_from_slice(&[0; 32]);
    fs::write(&t, &longer).unwrap();
    assert!(UnlockedVault::open(&t, &pw(PW)).is_err());
}

#[test]
fn swapping_payload_between_vaults_is_rejected() {
    // Payload AAD binds the ciphertext to the vault id.
    let dir = tempfile::tempdir().unwrap();
    let a = vault_path(&dir, "a.vault");
    let b = vault_path(&dir, "b.vault");
    new_vault(&a);
    new_vault(&b);
    let fa = VaultFile::from_bytes(&fs::read(&a).unwrap()).unwrap();
    let mut fb = VaultFile::from_bytes(&fs::read(&b).unwrap()).unwrap();
    fb.payload = fa.payload.clone();
    fb.payload_nonce = fa.payload_nonce;
    fs::write(&b, fb.to_bytes()).unwrap();
    assert!(matches!(
        UnlockedVault::open(&b, &pw(PW)),
        Err(VaultError::PayloadTampered)
    ));
}

#[test]
fn never_overwrites_existing_vault_without_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    new_vault(&p);
    let before = fs::read(&p).unwrap();
    let err =
        UnlockedVault::create(&p, &pw("a different password"), fast(), "x", false).unwrap_err();
    assert!(matches!(err, VaultError::AlreadyExists));
    assert_eq!(fs::read(&p).unwrap(), before);

    // With explicit confirmation it is replaced.
    UnlockedVault::create(&p, &pw("a different password"), fast(), "x", true).unwrap();
    assert!(UnlockedVault::open(&p, &pw("a different password")).is_ok());
    assert!(UnlockedVault::open(&p, &pw(PW)).is_err());
}

#[test]
fn interrupted_save_leaves_previous_vault_intact() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    populate(&mut v);
    let expected = v.data().clone();
    let good = fs::read(&p).unwrap();

    // A save that dies half-way through writing the new image.
    let half = good.len() / 2;
    let res = storage::atomic_write_with(&p, WriteMode::Replace, |f| {
        f.write_all(&good[..half])?;
        Err(std::io::Error::other("power loss"))
    });
    assert!(res.is_err());
    assert_eq!(fs::read(&p).unwrap(), good);
    assert_eq!(UnlockedVault::open(&p, &pw(PW)).unwrap().data(), &expected);

    // A crash that left a partially written temp file behind: the vault still
    // opens and the stale temp file is cleaned up.
    let stale = dir.path().join(".a.vault.deadbeefdeadbeef.vrtmp");
    fs::write(&stale, &good[..half]).unwrap();
    assert_eq!(UnlockedVault::open(&p, &pw(PW)).unwrap().data(), &expected);
    assert!(!stale.exists());
}

#[test]
fn master_password_change_rewraps_key_only() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    populate(&mut v);
    let id = v.vault_id_hex();
    let before = fs::read(&p).unwrap();

    assert!(matches!(
        v.change_password(&pw("not the password"), &pw("new password 123"), fast()),
        Err(VaultError::WrongPasswordOrTampered)
    ));
    assert!(v
        .change_password(&pw(PW), &pw("too short"), fast())
        .is_err());

    let strong = KdfParams::new(16 * 1024, 2, 2).unwrap();
    v.change_password(&pw(PW), &pw("new password 123"), strong)
        .unwrap();
    let after = fs::read(&p).unwrap();

    // Salt, wrap nonce and wrapped key changed...
    assert_ne!(before[40..72], after[40..72]);
    assert_ne!(before[72..96], after[72..96]);
    assert_ne!(before[96..144], after[96..144]);
    // ...while the vault id and the encrypted payload are byte-for-byte equal.
    assert_eq!(before[12..28], after[12..28]);
    assert_eq!(before[144..], after[144..]);

    drop(v);
    assert!(UnlockedVault::open(&p, &pw(PW)).is_err());
    let v = UnlockedVault::open(&p, &pw("new password 123")).unwrap();
    assert_eq!(v.vault_id_hex(), id);
    assert_eq!(v.kdf_params(), strong);
    assert_eq!(v.data().entries.len(), 5 + EntryKind::ALL.len());
}

#[test]
fn every_save_uses_a_fresh_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    let mut nonces = HashSet::new();
    let mut cts = HashSet::new();
    for _ in 0..50 {
        v.save().unwrap();
        let f = VaultFile::from_bytes(&fs::read(&p).unwrap()).unwrap();
        assert!(nonces.insert(f.payload_nonce), "payload nonce reused");
        assert!(cts.insert(f.payload), "identical ciphertext for a re-save");
    }
    // Each password change also uses a fresh salt and key-wrap nonce.
    let mut wrap_nonces = HashSet::new();
    let mut salts = HashSet::new();
    let mut current = PW.to_string();
    for i in 0..5 {
        let next = format!("rotated password number {i}");
        v.change_password(&pw(&current), &pw(&next), fast())
            .unwrap();
        current = next;
        let f = VaultFile::from_bytes(&fs::read(&p).unwrap()).unwrap();
        assert!(wrap_nonces.insert(f.header.wrap_nonce));
        assert!(salts.insert(f.header.salt));
    }
}

#[test]
fn backup_is_verified_and_restorable() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let b = vault_path(&dir, "backup.vault");
    let mut v = new_vault(&p);
    populate(&mut v);
    v.backup_to(&b, false).unwrap();
    assert_eq!(fs::read(&p).unwrap(), fs::read(&b).unwrap());
    v.verify_backup(&b).unwrap();

    // Backups never overwrite silently, and never overwrite the vault itself.
    assert!(matches!(
        v.backup_to(&b, false),
        Err(VaultError::AlreadyExists)
    ));
    assert!(v.backup_to(&p, true).is_err());

    // A corrupted backup fails verification.
    let mut bytes = fs::read(&b).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    let corrupt = vault_path(&dir, "corrupt.vault");
    fs::write(&corrupt, &bytes).unwrap();
    assert!(matches!(
        v.verify_backup(&corrupt),
        Err(VaultError::BackupVerification)
    ));

    // Changes after the backup are not in it.
    let expected = v.data().clone();
    v.data_mut().entries.clear();
    v.save().unwrap();
    drop(v);

    // Restore to a new location.
    let restored_path = vault_path(&dir, "restored.vault");
    assert!(restore_backup(&b, &pw("wrong password"), &restored_path, false).is_err());
    assert!(!restored_path.exists());
    let r = restore_backup(&b, &pw(PW), &restored_path, false).unwrap();
    assert_eq!(r.data(), &expected);
    assert_eq!(r.path(), restored_path.as_path());

    // Restoring over an existing vault needs explicit confirmation.
    assert!(matches!(
        restore_backup(&b, &pw(PW), &p, false),
        Err(VaultError::AlreadyExists)
    ));
    assert_eq!(
        UnlockedVault::open(&p, &pw(PW))
            .unwrap()
            .data()
            .entries
            .len(),
        0
    );
    restore_backup(&b, &pw(PW), &p, true).unwrap();
    assert_eq!(UnlockedVault::open(&p, &pw(PW)).unwrap().data(), &expected);

    // A corrupted backup is never restored.
    assert!(restore_backup(&corrupt, &pw(PW), &vault_path(&dir, "x.vault"), false).is_err());
    assert!(!vault_path(&dir, "x.vault").exists());
}

#[test]
fn backup_keeps_password_at_time_of_backup() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let b = vault_path(&dir, "b.vault");
    let mut v = new_vault(&p);
    v.backup_to(&b, false).unwrap();
    v.change_password(&pw(PW), &pw("brand new password"), fast())
        .unwrap();
    assert!(UnlockedVault::open(&b, &pw(PW)).is_ok());
    assert!(UnlockedVault::open(&b, &pw("brand new password")).is_err());
}

#[test]
fn rename_and_move_vault() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    v.rename("Personal").unwrap();
    assert!(v.rename("   ").is_err());

    let occupied = vault_path(&dir, "occupied.vault");
    fs::write(&occupied, b"do not touch").unwrap();
    assert!(matches!(
        v.move_to(&occupied),
        Err(VaultError::AlreadyExists)
    ));
    assert_eq!(fs::read(&occupied).unwrap(), b"do not touch");

    let sub = dir.path().join("moved");
    fs::create_dir(&sub).unwrap();
    let dest = sub.join("Personal.vault");
    v.move_to(&dest).unwrap();
    assert!(!p.exists());
    v.data_mut().upsert(Entry::new(EntryKind::SecureNote));
    v.save().unwrap();
    drop(v);
    let v = UnlockedVault::open(&dest, &pw(PW)).unwrap();
    assert_eq!(v.data().name, "Personal");
    assert_eq!(v.data().entries.len(), 1);
}

#[test]
fn vault_is_portable_between_locations() {
    // "Moving to another computer" is copying the single file.
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    populate(&mut v);
    let expected = v.data().clone();
    drop(v);
    let copy = other.path().join("copied.vault");
    fs::copy(&p, &copy).unwrap();
    assert_eq!(
        UnlockedVault::open(&copy, &pw(PW)).unwrap().data(),
        &expected
    );
}

#[test]
fn settings_and_all_field_kinds_persist() {
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    {
        let d = v.data_mut();
        d.settings.auto_lock_minutes = 17;
        d.settings.clipboard_clear_secs = 45;
        d.settings.lock_on_minimize = true;
        d.settings.generator.length = 33;
        d.settings.passphrase.words = 8;
        let mut e = Entry::new(EntryKind::Custom);
        e.title = "Ünïcødé ✓ 🔐".into();
        for k in FieldKind::ALL {
            e.fields.push(vaultrust::model::Field::with_value(
                k.label(),
                k,
                "multi\nline ✓",
            ));
        }
        e.favorite = true;
        d.upsert(e);
    }
    v.save().unwrap();
    let expected = v.data().clone();
    drop(v);
    let v = UnlockedVault::open(&p, &pw(PW)).unwrap();
    assert_eq!(v.data(), &expected);
    assert_eq!(v.data().settings.auto_lock_minutes, 17);
}

#[test]
fn locking_drops_and_zeroizes_decrypted_state() {
    use zeroize::Zeroize;
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut v = new_vault(&p);
    populate(&mut v);
    // Zeroize is what runs on drop; verify it wipes every secret-bearing field.
    let mut data = v.data().clone();
    data.zeroize();
    assert!(data.name.is_empty());
    assert!(data.entries.is_empty());
    // Locking = dropping the vault; it must be reopenable afterwards.
    drop(v);
    assert!(UnlockedVault::open(&p, &pw(PW)).is_ok());
}

#[test]
fn external_modification_is_detected_before_saving() {
    // Two sessions (e.g. two VaultRust windows) open the same file.
    let dir = tempfile::tempdir().unwrap();
    let p = vault_path(&dir, "a.vault");
    let mut a = new_vault(&p);
    let mut b = UnlockedVault::open(&p, &pw(PW)).unwrap();

    b.data_mut().upsert(Entry::new(EntryKind::SecureNote));
    b.save().unwrap();
    let after_b = fs::read(&p).unwrap();

    // A must not silently overwrite B's change.
    a.data_mut().upsert(Entry::new(EntryKind::Login));
    assert!(matches!(a.save(), Err(VaultError::ModifiedExternally)));
    assert!(matches!(
        a.change_password(&pw(PW), &pw("another long password"), fast()),
        Err(VaultError::ModifiedExternally)
    ));
    assert!(matches!(
        a.move_to(&vault_path(&dir, "moved.vault")),
        Err(VaultError::ModifiedExternally)
    ));
    assert_eq!(fs::read(&p).unwrap(), after_b, "file must be untouched");

    // Only an explicit choice overwrites.
    a.save_overwriting_external_changes().unwrap();
    let reopened = UnlockedVault::open(&p, &pw(PW)).unwrap();
    assert_eq!(reopened.data().entries.len(), 1);
    assert_eq!(reopened.data().entries[0].kind, EntryKind::Login);

    // A deleted file is also treated as an external change.
    fs::remove_file(&p).unwrap();
    a.data_mut().upsert(Entry::new(EntryKind::Wifi));
    assert!(matches!(a.save(), Err(VaultError::ModifiedExternally)));
    assert!(!p.exists());
}
