//! High-level vault operations: create, unlock, save, change password,
//! backup, restore, move.
//!
//! Key hierarchy:
//!
//! ```text
//! master password ──Argon2id(salt, params)──▶ KEK
//! KEK ──XChaCha20-Poly1305 unwrap──▶ vault key (random, 256-bit)
//! vault key ──XChaCha20-Poly1305──▶ payload (postcard-encoded VaultData)
//! ```

use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};
use unicode_normalization::{is_nfc, UnicodeNormalization};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, KeyFile, SecretKey, NONCE_LEN};
use crate::error::{Result, VaultError};
use crate::format::{Header, VaultFile, MAX_PAYLOAD_LEN, VAULT_ID_LEN};
use crate::model::{VaultData, SCHEMA_VERSION};
use crate::storage::{self, WriteMode};
use crate::timeutil::now_unix;

/// What unlocks a vault: the master password and, for vaults created with
/// one, a key file.
#[derive(Clone)]
pub struct Credentials {
    pub password: SecretString,
    pub key_file: Option<KeyFile>,
}

impl Credentials {
    pub fn password(password: SecretString) -> Self {
        Credentials {
            password,
            key_file: None,
        }
    }

    pub fn with_key_file(password: SecretString, key_file: Option<KeyFile>) -> Self {
        Credentials { password, key_file }
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("key_file", &self.key_file.is_some())
            .finish_non_exhaustive()
    }
}

/// Plaintext payloads are padded to a multiple of this many bytes so the file
/// size only reveals the approximate amount of stored data.
const PAD_BLOCK: usize = 4096;
const INITIAL_ENCODE_BUF: usize = 64 * 1024;

/// An open, decrypted vault. Dropping it (locking) zeroizes the vault key and
/// all decrypted contents.
pub struct UnlockedVault {
    path: PathBuf,
    header: Header,
    key: SecretKey,
    data: VaultData,
    /// The payload exactly as last written to disk.
    sealed: Option<([u8; NONCE_LEN], Vec<u8>)>,
    dirty: bool,
    /// The key file this session was unlocked with, kept (like the vault
    /// key) so the user can re-confirm their identity with the password alone.
    key_file: Option<KeyFile>,
    /// Problem with the last automatic backup, for the UI to report. Saving
    /// itself never fails because of an automatic backup.
    auto_backup_warning: Option<VaultError>,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("path", &self.path)
            .field("entries", &self.data.entries.len())
            .finish_non_exhaustive()
    }
}

impl UnlockedVault {
    /// Create a brand new vault file. With `overwrite == false` an existing
    /// file at `path` is never touched.
    pub fn create(
        path: &Path,
        password: &SecretString,
        kdf: KdfParams,
        name: &str,
        overwrite: bool,
    ) -> Result<Self> {
        Self::create_with(
            path,
            &Credentials::password(password.clone()),
            kdf,
            name,
            overwrite,
        )
    }

    /// [`create`](Self::create) with an optional key file.
    pub fn create_with(
        path: &Path,
        creds: &Credentials,
        kdf: KdfParams,
        name: &str,
        overwrite: bool,
    ) -> Result<Self> {
        validate_master_password(&creds.password)?;
        if !overwrite && path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let key = crypto::random_key();
        let vault_id = crypto::random_array::<VAULT_ID_LEN>();
        let header = wrap_vault_key(creds, kdf, vault_id, &key)?;
        let mut vault = UnlockedVault {
            path: path.to_path_buf(),
            header,
            key,
            data: VaultData::new(name),
            sealed: None,
            dirty: true,
            key_file: creds.key_file.clone(),
            auto_backup_warning: None,
        };
        let mode = if overwrite {
            WriteMode::Replace
        } else {
            WriteMode::CreateNew
        };
        vault.write(mode)?;
        Ok(vault)
    }

    /// Unlock a vault file with its master password.
    pub fn open(path: &Path, password: &SecretString) -> Result<Self> {
        Self::open_with(path, &Credentials::password(password.clone()))
    }

    /// Unlock with a password and, if the vault needs one, a key file.
    pub fn open_with(path: &Path, creds: &Credentials) -> Result<Self> {
        let bytes = storage::read_vault_bytes(path)?;
        storage::cleanup_stale_temp_files(path);
        Self::open_bytes(path, &bytes, creds)
    }

    fn open_bytes(path: &Path, bytes: &[u8], creds: &Credentials) -> Result<Self> {
        let file = VaultFile::from_bytes(bytes)?;
        let key = unwrap_with(&file.header, creds)?;
        let plain = crypto::open(
            &key,
            &file.payload_nonce,
            &file.header.payload_aad(),
            &file.payload,
        )
        .map_err(|_| VaultError::PayloadTampered)?;
        let data = decode_payload(&plain)?;
        let uses_key_file = file.header.key_file;
        Ok(UnlockedVault {
            path: path.to_path_buf(),
            header: file.header,
            key,
            data,
            sealed: Some((file.payload_nonce, file.payload)),
            dirty: false,
            key_file: if uses_key_file {
                creds.key_file.clone()
            } else {
                None
            },
            auto_backup_warning: None,
        })
    }

    /// Whether unlocking this vault needs a key file.
    pub fn uses_key_file(&self) -> bool {
        self.header.key_file
    }

    pub fn vault_id(&self) -> [u8; VAULT_ID_LEN] {
        self.header.vault_id
    }

    /// What Windows Hello stores (encrypted) to unlock this vault: a copy of
    /// the vault key and the session's key file.
    pub fn hello_secret(&self) -> crate::hello::HelloSecret {
        let mut k = Box::new([0u8; crypto::KEY_LEN]);
        k.copy_from_slice(self.key.expose_secret());
        crate::hello::HelloSecret {
            vault_key: secrecy::SecretBox::new(k),
            key_file: self.key_file.clone(),
        }
    }

    /// Unlock with a vault key obtained from Windows Hello. The payload's
    /// authentication tag proves the key is right.
    pub fn open_with_hello(path: &Path, secret: crate::hello::HelloSecret) -> Result<Self> {
        let bytes = storage::read_vault_bytes(path)?;
        let file = VaultFile::from_bytes(&bytes)?;
        let plain = crypto::open(
            &secret.vault_key,
            &file.payload_nonce,
            &file.header.payload_aad(),
            &file.payload,
        )
        .map_err(|_| VaultError::WrongPasswordOrTampered)?;
        let data = decode_payload(&plain)?;
        let uses_key_file = file.header.key_file;
        Ok(UnlockedVault {
            path: path.to_path_buf(),
            header: file.header,
            key: secret.vault_key,
            data,
            sealed: Some((file.payload_nonce, file.payload)),
            dirty: false,
            key_file: if uses_key_file { secret.key_file } else { None },
            auto_backup_warning: None,
        })
    }

    /// Take (and clear) the problem reported by the last automatic backup.
    pub fn take_auto_backup_warning(&mut self) -> Option<VaultError> {
        self.auto_backup_warning.take()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn data(&self) -> &VaultData {
        &self.data
    }

    /// Mutable access; marks the vault as needing a save.
    pub fn data_mut(&mut self) -> &mut VaultData {
        self.dirty = true;
        &mut self.data
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf
    }

    pub fn vault_id_hex(&self) -> String {
        self.header
            .vault_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Encrypt the current contents with a fresh nonce and atomically
    /// replace the vault file.
    ///
    /// Fails with [`VaultError::ModifiedExternally`] if the file on disk is no
    /// longer exactly what this session last read or wrote (another VaultRust
    /// window, a sync tool or a restore changed it), so those changes are
    /// never silently overwritten.
    pub fn save(&mut self) -> Result<()> {
        self.check_disk_unchanged()?;
        if let Some(previous) = self.expected_disk_bytes() {
            self.auto_backup(&previous, false);
        }
        self.write(WriteMode::Replace)
    }

    /// Save even though the file was changed externally. Only call this after
    /// the user explicitly chose to overwrite the other version. The other
    /// version is kept as an automatic backup first (if enabled), since this
    /// is exactly the moment data would otherwise be lost.
    pub fn save_overwriting_external_changes(&mut self) -> Result<()> {
        if let Ok(other) = storage::read_vault_bytes(&self.path) {
            self.auto_backup(&other, true);
        }
        self.write(WriteMode::Replace)
    }

    /// Keep a copy of the vault file as it was before this save, in the
    /// `<file>.backups` folder next to it. At most one copy per
    /// [`AUTO_BACKUP_INTERVAL_SECS`] (unless `force`), and only the newest
    /// `auto_backup_count` copies are kept. Copies are ciphertext only.
    fn auto_backup(&mut self, previous: &[u8], force: bool) {
        let keep = self.data.settings.auto_backup_count;
        if keep == 0 {
            return;
        }
        let interval = if force { 0 } else { AUTO_BACKUP_INTERVAL_SECS };
        if let Err(e) = storage::write_rotating_backup(
            &self.path,
            previous,
            keep as usize,
            now_unix(),
            interval,
        ) {
            self.auto_backup_warning = Some(e);
        }
    }

    /// The folder automatic backups go to.
    pub fn auto_backup_dir(&self) -> PathBuf {
        storage::auto_backup_dir(&self.path)
    }

    /// The exact bytes this session expects to find on disk.
    fn expected_disk_bytes(&self) -> Option<Vec<u8>> {
        self.sealed.as_ref().map(|(nonce, payload)| {
            VaultFile {
                header: self.header.clone(),
                payload_nonce: *nonce,
                payload: payload.clone(),
            }
            .to_bytes()
        })
    }

    pub fn check_disk_unchanged(&self) -> Result<()> {
        let Some(expected) = self.expected_disk_bytes() else {
            return Ok(());
        };
        match storage::read_vault_bytes(&self.path) {
            Ok(actual) if actual == expected => Ok(()),
            Ok(_) => Err(VaultError::ModifiedExternally),
            Err(VaultError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(VaultError::ModifiedExternally)
            }
            Err(e) => Err(e),
        }
    }

    fn write(&mut self, mode: WriteMode) -> Result<()> {
        let (nonce, payload) = self.seal_payload()?;
        let file = VaultFile {
            header: self.header.clone(),
            payload_nonce: nonce,
            payload,
        };
        storage::atomic_write(&self.path, &file.to_bytes(), mode)?;
        self.sealed = Some((file.payload_nonce, file.payload));
        self.dirty = false;
        Ok(())
    }

    fn seal_payload(&self) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        let plain = encode_payload(&self.data)?;
        let nonce = crypto::random_nonce();
        let ct = crypto::seal(&self.key, &nonce, &self.header.payload_aad(), &plain)?;
        Ok((nonce, ct))
    }

    /// The current encrypted file image (saving first if needed).
    fn current_file(&mut self) -> Result<VaultFile> {
        if self.dirty || self.sealed.is_none() {
            self.save()?;
        }
        let (nonce, payload) = self
            .sealed
            .clone()
            .ok_or(VaultError::Invalid("vault not saved"))?;
        Ok(VaultFile {
            header: self.header.clone(),
            payload_nonce: nonce,
            payload,
        })
    }

    /// Check a password against this vault's header without changing state.
    /// For vaults with a key file, the key file from this session is used.
    pub fn verify_password(&self, password: &SecretString) -> bool {
        self.verify_task(password.clone())()
    }

    /// [`verify_password`](Self::verify_password) as a closure that can run
    /// on another thread (it performs a full Argon2 derivation).
    pub fn verify_task(&self, password: SecretString) -> impl FnOnce() -> bool + Send + 'static {
        let header = self.header.clone();
        let creds = Credentials::with_key_file(password, self.key_file.clone());
        move || unwrap_with(&header, &creds).is_ok()
    }

    /// The key file this session was unlocked with (for "keep the current
    /// key file" when changing the password).
    pub fn session_key_file(&self) -> Option<KeyFile> {
        self.key_file.clone()
    }

    /// Change the master password (and optionally the Argon2 cost). Only the
    /// key wrapping in the header changes: the vault key and the encrypted
    /// payload are reused unchanged.
    pub fn change_password(
        &mut self,
        current: &SecretString,
        new: &SecretString,
        kdf: KdfParams,
    ) -> Result<()> {
        let header = self
            .password_change_task(current.clone(), new.clone(), kdf)
            .run()?;
        self.apply_password_change(header)
    }

    /// Change the password and/or key file. `new.key_file` decides whether
    /// the vault uses a key file afterwards.
    pub fn credentials_change_task(
        &self,
        current: Credentials,
        new: Credentials,
        kdf: KdfParams,
    ) -> PasswordChangeTask {
        let mut key = Box::new([0u8; crypto::KEY_LEN]);
        key.copy_from_slice(self.key.expose_secret());
        PasswordChangeTask {
            header: self.header.clone(),
            key: secrecy::SecretBox::new(key),
            current,
            new,
            kdf,
        }
    }

    /// Prepare a password change whose slow part (two Argon2 derivations) can
    /// run on another thread. Apply the result with
    /// [`apply_password_change`](Self::apply_password_change).
    pub fn password_change_task(
        &self,
        current: SecretString,
        new: SecretString,
        kdf: KdfParams,
    ) -> PasswordChangeTask {
        // A password-only change keeps the session's key file, if any.
        let current = Credentials::with_key_file(current, self.key_file.clone());
        let new = Credentials::with_key_file(new, self.key_file.clone());
        self.credentials_change_task(current, new, kdf)
    }

    pub fn apply_password_change(&mut self, header: RewrappedHeader) -> Result<()> {
        let RewrappedHeader(header, key_file) = header;
        if header.vault_id != self.header.vault_id {
            return Err(VaultError::Invalid(
                "password change prepared for a different vault",
            ));
        }
        let mut file = self.current_file()?;
        self.check_disk_unchanged()?;
        file.header = header;
        storage::atomic_write(&self.path, &file.to_bytes(), WriteMode::Replace)?;
        self.header = file.header;
        self.key_file = key_file;
        Ok(())
    }

    /// Write an encrypted backup (an exact copy of the current vault file,
    /// protected by the current master password) and verify it by reading it
    /// back and decrypting it.
    pub fn backup_to(&mut self, dest: &Path, overwrite: bool) -> Result<()> {
        if same_file(dest, &self.path) {
            return Err(VaultError::Invalid(
                "a backup cannot overwrite the vault it is made from",
            ));
        }
        let file = self.current_file()?;
        let mode = if overwrite {
            WriteMode::Replace
        } else {
            WriteMode::CreateNew
        };
        storage::atomic_write(dest, &file.to_bytes(), mode)?;
        self.verify_backup(dest)
    }

    /// Confirm that `path` holds a backup of this vault whose contents
    /// decrypt and match the in-memory state.
    pub fn verify_backup(&self, path: &Path) -> Result<()> {
        let bytes = storage::read_vault_bytes(path)?;
        let file = VaultFile::from_bytes(&bytes).map_err(|_| VaultError::BackupVerification)?;
        if file.header != self.header {
            return Err(VaultError::BackupVerification);
        }
        let plain = crypto::open(
            &self.key,
            &file.payload_nonce,
            &file.header.payload_aad(),
            &file.payload,
        )
        .map_err(|_| VaultError::BackupVerification)?;
        let data = decode_payload(&plain).map_err(|_| VaultError::BackupVerification)?;
        if data != self.data {
            return Err(VaultError::BackupVerification);
        }
        Ok(())
    }

    /// Move (or rename) the vault file. Never overwrites an existing file.
    pub fn move_to(&mut self, dest: &Path) -> Result<()> {
        if self.dirty {
            self.save()?;
        }
        self.check_disk_unchanged()?;
        storage::move_no_overwrite(&self.path, dest)?;
        self.path = dest.to_path_buf();
        Ok(())
    }

    /// Change the display name stored inside the vault.
    pub fn rename(&mut self, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::Invalid("the vault name cannot be empty"));
        }
        self.data_mut().name = name.to_string();
        self.save()
    }
}

/// The slow half of a master password change; see
/// [`UnlockedVault::password_change_task`].
pub struct PasswordChangeTask {
    header: Header,
    key: SecretKey,
    current: Credentials,
    new: Credentials,
    kdf: KdfParams,
}

/// A new header wrapping the existing vault key under new credentials.
pub struct RewrappedHeader(Header, Option<KeyFile>);

impl PasswordChangeTask {
    pub fn run(self) -> Result<RewrappedHeader> {
        let unwrapped = unwrap_with(&self.header, &self.current)?;
        if unwrapped.expose_secret() != self.key.expose_secret() {
            return Err(VaultError::WrongPasswordOrTampered);
        }
        validate_master_password(&self.new.password)?;
        Ok(RewrappedHeader(
            wrap_vault_key(&self.new, self.kdf, self.header.vault_id, &self.key)?,
            self.new.key_file.clone(),
        ))
    }
}

/// Restore an encrypted backup to `dest`. The backup is fully decrypted and
/// authenticated with `password` before anything is written. Existing files
/// at `dest` are only replaced when `overwrite` is true.
pub fn restore_backup(
    backup: &Path,
    password: &SecretString,
    dest: &Path,
    overwrite: bool,
) -> Result<UnlockedVault> {
    restore_backup_with(
        backup,
        &Credentials::password(password.clone()),
        dest,
        overwrite,
    )
}

/// [`restore_backup`] for backups that need a key file.
pub fn restore_backup_with(
    backup: &Path,
    creds: &Credentials,
    dest: &Path,
    overwrite: bool,
) -> Result<UnlockedVault> {
    let bytes = storage::read_vault_bytes(backup)?;
    let mut vault = UnlockedVault::open_bytes(dest, &bytes, creds)?;
    if !same_file(backup, dest) {
        let mode = if overwrite {
            WriteMode::Replace
        } else {
            WriteMode::CreateNew
        };
        storage::atomic_write(dest, &bytes, mode)?;
        if storage::read_vault_bytes(dest)? != bytes {
            return Err(VaultError::BackupVerification);
        }
    }
    vault.path = dest.to_path_buf();
    Ok(vault)
}

/// Minimum acceptable master password. The UI additionally shows a strength
/// estimate and warns about weak choices.
pub const MIN_MASTER_PASSWORD_CHARS: usize = 10;

/// Automatic backups are taken at most this often (one hour), so a burst of
/// edits does not push all older copies out of the rotation.
pub const AUTO_BACKUP_INTERVAL_SECS: i64 = 3600;

pub fn validate_master_password(password: &SecretString) -> Result<()> {
    if nfc(password).chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(VaultError::Invalid(
            "the master password must be at least 10 characters long",
        ));
    }
    Ok(())
}

/// The master password in Unicode Normalization Form C, so the same visible
/// text typed with composed or decomposed accents gives the same key.
fn nfc(password: &SecretString) -> Zeroizing<String> {
    Zeroizing::new(password.expose_secret().nfc().collect())
}

fn wrap_vault_key(
    creds: &Credentials,
    kdf: KdfParams,
    vault_id: [u8; VAULT_ID_LEN],
    key: &SecretKey,
) -> Result<Header> {
    kdf.validate()?;
    let mut header = Header {
        vault_id,
        kdf,
        salt: crypto::random_array(),
        wrap_nonce: crypto::random_nonce(),
        wrapped_key: [0u8; crate::format::WRAPPED_KEY_LEN],
        key_file: creds.key_file.is_some(),
    };
    let kek = crypto::derive_kek_bytes(
        nfc(&creds.password).as_bytes(),
        creds.key_file.as_ref(),
        &header.salt,
        &header.kdf,
    )?;
    header.wrapped_key = crypto::wrap_key(&kek, &header.wrap_nonce, &header.key_wrap_aad(), key)?;
    Ok(header)
}

/// Unwrap the vault key. Vaults are keyed with the NFC form of the password;
/// vaults written before normalisation was introduced used the raw bytes, so
/// if the NFC attempt fails and the input was not already NFC, the raw form
/// is tried too (one extra Argon2 run, only in that rare case).
fn unwrap_with(header: &Header, creds: &Credentials) -> Result<SecretKey> {
    let key_file = match (header.key_file, &creds.key_file) {
        (true, None) => return Err(VaultError::KeyFileRequired),
        (true, Some(k)) => Some(k),
        // A key file supplied for a vault that doesn't use one is ignored.
        (false, _) => None,
    };
    let attempt = |pw: &[u8]| -> Result<Option<SecretKey>> {
        let kek = crypto::derive_kek_bytes(pw, key_file, &header.salt, &header.kdf)?;
        Ok(crypto::unwrap_key(
            &kek,
            &header.wrap_nonce,
            &header.key_wrap_aad(),
            &header.wrapped_key,
        ))
    };
    if let Some(k) = attempt(nfc(&creds.password).as_bytes())? {
        return Ok(k);
    }
    let raw = creds.password.expose_secret();
    if !is_nfc(raw) {
        if let Some(k) = attempt(raw.as_bytes())? {
            return Ok(k);
        }
    }
    Err(VaultError::WrongPasswordOrTampered)
}

/// Serialize into a zeroizing buffer: `u32 length || postcard || zero padding`.
///
/// The buffer is pre-sized and never grown in place, so no reallocation can
/// leave an un-wiped plaintext copy on the heap.
pub(crate) fn encode_payload(data: &VaultData) -> Result<Zeroizing<Vec<u8>>> {
    let mut cap = INITIAL_ENCODE_BUF;
    loop {
        let mut buf = Zeroizing::new(vec![0u8; cap]);
        let used = match postcard::to_slice(data, &mut buf[4..]) {
            Ok(s) => s.len(),
            Err(postcard::Error::SerializeBufferFull) => {
                cap = cap.checked_mul(2).ok_or(VaultError::TooLarge)?;
                if cap as u64 > MAX_PAYLOAD_LEN {
                    return Err(VaultError::TooLarge);
                }
                continue;
            }
            Err(_) => return Err(VaultError::Encode),
        };
        let len = u32::try_from(used).map_err(|_| VaultError::TooLarge)?;
        buf[..4].copy_from_slice(&len.to_le_bytes());
        let total = (4 + used).div_ceil(PAD_BLOCK) * PAD_BLOCK;
        // `cap` is a multiple of PAD_BLOCK and >= 4 + used, so this only shrinks.
        buf.truncate(total);
        return Ok(buf);
    }
}

pub(crate) fn decode_payload(plain: &[u8]) -> Result<VaultData> {
    if plain.len() < 4 {
        return Err(VaultError::Decode);
    }
    let len = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
    let body = plain.get(4..4 + len).ok_or(VaultError::Decode)?;
    // Every layout starts with the `schema: u32` field, so it can be read
    // first to choose the right decoder.
    let (schema, _) = postcard::take_from_bytes::<u32>(body).map_err(|_| VaultError::Decode)?;
    let mut data: VaultData = match schema {
        1 => postcard::from_bytes::<crate::model::v1::VaultDataV1>(body)
            .map_err(|_| VaultError::Decode)?
            .upgrade(),
        2 => postcard::from_bytes::<crate::model::v2::VaultDataV2>(body)
            .map_err(|_| VaultError::Decode)?
            .upgrade(),
        3 => postcard::from_bytes::<crate::model::v3::VaultDataV3>(body)
            .map_err(|_| VaultError::Decode)?
            .upgrade(),
        4 => postcard::from_bytes::<crate::model::v4::VaultDataV4>(body)
            .map_err(|_| VaultError::Decode)?
            .upgrade(),
        5 => postcard::from_bytes::<crate::model::v5::VaultDataV5>(body)
            .map_err(|_| VaultError::Decode)?
            .upgrade(),
        SCHEMA_VERSION => postcard::from_bytes(body).map_err(|_| VaultError::Decode)?,
        _ => {
            return Err(VaultError::Invalid(
                "this vault was written by a newer version of VaultRust",
            ))
        }
    };
    data.settings.sanitize();
    Ok(data)
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::v3::EntryV3;
    use crate::model::{Entry, EntryKind, Field, FieldKind};

    fn old_entry(kind: EntryKind, title: &str) -> EntryV3 {
        EntryV3 {
            id: 42,
            kind,
            title: title.into(),
            fields: vec![Field::with_value("Password", FieldKind::Password, "pw")],
            notes: "n".into(),
            favorite: true,
            created: 1,
            modified: 2,
            password_changed: 3,
        }
    }

    #[test]
    fn schema_v1_payload_is_upgraded() {
        use crate::model::v1::{VaultDataV1, VaultSettingsV1};
        let e = old_entry(EntryKind::Login, "old");
        let old = VaultDataV1 {
            schema: 1,
            name: "legacy".into(),
            created: 7,
            entries: vec![e],
            settings: VaultSettingsV1 {
                auto_lock_minutes: 12,
                clipboard_clear_secs: 40,
                lock_on_minimize: true,
                generator: Default::default(),
                passphrase: Default::default(),
            },
        };
        let body = postcard::to_allocvec(&old).unwrap();
        let mut plain = (body.len() as u32).to_le_bytes().to_vec();
        plain.extend_from_slice(&body);
        let d = decode_payload(&plain).unwrap();
        assert_eq!(d.schema, SCHEMA_VERSION);
        assert_eq!(d.name, "legacy");
        assert_eq!(d.entries[0].title, "old");
        assert_eq!(d.settings.auto_lock_minutes, 12);
        assert!(d.settings.lock_on_minimize);
        assert!(
            d.settings.hide_from_capture,
            "new settings take safe defaults"
        );
        // Re-encoding writes the current schema.
        assert_eq!(decode_payload(&encode_payload(&d).unwrap()).unwrap(), d);
    }

    #[test]
    fn schema_v2_payload_is_upgraded() {
        use crate::model::v2::VaultDataV2;
        let settings = crate::model::v3::VaultSettingsV3 {
            reveal_timeout_secs: 77,
            ..Default::default()
        };
        let old = VaultDataV2 {
            schema: 2,
            name: "v2".into(),
            created: 9,
            entries: vec![old_entry(EntryKind::Wifi, "w")],
            settings,
        };
        let body = postcard::to_allocvec(&old).unwrap();
        let mut plain = (body.len() as u32).to_le_bytes().to_vec();
        plain.extend_from_slice(&body);
        let d = decode_payload(&plain).unwrap();
        assert_eq!(d.schema, SCHEMA_VERSION);
        assert_eq!(d.name, "v2");
        assert_eq!(d.entries.len(), 1);
        assert_eq!(d.settings.reveal_timeout_secs, 77);
        assert_eq!(d.last_backup, 0);
    }

    #[test]
    fn schema_v3_payload_is_upgraded() {
        use crate::model::v3::{VaultDataV3, VaultSettingsV3};
        let old = VaultDataV3 {
            schema: 3,
            name: "v3".into(),
            created: 9,
            entries: vec![old_entry(EntryKind::Login, "kept")],
            settings: VaultSettingsV3 {
                auto_lock_minutes: 17,
                ..Default::default()
            },
            last_backup: 1234,
        };
        let body = postcard::to_allocvec(&old).unwrap();
        let mut plain = (body.len() as u32).to_le_bytes().to_vec();
        plain.extend_from_slice(&body);
        let d = decode_payload(&plain).unwrap();
        assert_eq!(d.schema, SCHEMA_VERSION);
        assert_eq!(d.last_backup, 1234);
        assert_eq!(d.settings.auto_lock_minutes, 17);
        assert!(
            d.settings.lock_on_session_lock,
            "new settings take safe defaults"
        );
        assert_eq!(d.settings.auto_backup_count, 10);
        let e = &d.entries[0];
        assert_eq!((e.id, e.title.as_str(), e.favorite), (42, "kept", true));
        assert_eq!(e.fields[0].value, "pw");
        assert_eq!((e.created, e.modified, e.password_changed), (1, 2, 3));
        assert!(e.tags.is_empty() && e.history.is_empty() && e.last_used == 0);
        assert!(d.trash.is_empty());
        // Re-encoding writes the current schema and round-trips.
        assert_eq!(decode_payload(&encode_payload(&d).unwrap()).unwrap(), d);
    }

    #[test]
    fn schema_v4_payload_is_upgraded() {
        use crate::model::v4::{EntryV4, TrashedEntryV4, VaultDataV4};
        use crate::model::HistoryItem;
        let entry = |id: u64, title: &str| EntryV4 {
            id,
            kind: EntryKind::Login,
            title: title.into(),
            fields: vec![Field::with_value("Password", FieldKind::Password, "pw")],
            notes: String::new(),
            favorite: false,
            created: 1,
            modified: 2,
            password_changed: 3,
            tags: vec!["work".into()],
            history: vec![HistoryItem {
                label: "Password".into(),
                value: "old".into(),
                replaced: 4,
            }],
            last_used: 5,
        };
        let old = VaultDataV4 {
            schema: 4,
            name: "v4".into(),
            created: 9,
            entries: vec![entry(1, "live")],
            settings: crate::model::VaultSettings {
                auto_backup_count: 7,
                ..Default::default()
            },
            last_backup: 11,
            trash: vec![TrashedEntryV4 {
                entry: entry(2, "binned"),
                deleted: 12,
            }],
        };
        let body = postcard::to_allocvec(&old).unwrap();
        let mut plain = (body.len() as u32).to_le_bytes().to_vec();
        plain.extend_from_slice(&body);
        let d = decode_payload(&plain).unwrap();
        assert_eq!(d.schema, SCHEMA_VERSION);
        assert_eq!(d.settings.auto_backup_count, 7);
        assert_eq!(d.last_backup, 11);
        let e = &d.entries[0];
        assert_eq!(e.tags, ["work"]);
        assert_eq!(e.history[0].value, "old");
        assert_eq!(e.last_used, 5);
        assert_eq!((e.expires, e.auto_type.as_str()), (0, ""));
        assert_eq!(d.trash[0].entry.title, "binned");
        assert_eq!(d.trash[0].deleted, 12);
        assert!(d.audit.is_empty());
        assert_eq!(decode_payload(&encode_payload(&d).unwrap()).unwrap(), d);
    }

    #[test]
    fn schema_v5_payload_is_upgraded() {
        use crate::model::v5::{EntryV5, TrashedEntryV5, VaultDataV5};
        use crate::model::{AuditEvent, AuditKind};
        let entry = |id: u64, title: &str| EntryV5 {
            id,
            kind: EntryKind::Login,
            title: title.into(),
            fields: vec![Field::with_value("Password", FieldKind::Password, "pw")],
            notes: String::new(),
            favorite: true,
            created: 1,
            modified: 2,
            password_changed: 3,
            tags: vec!["work".into()],
            history: Vec::new(),
            last_used: 5,
            expires: 6,
            auto_type: "{PASSWORD}{ENTER}".into(),
        };
        let old = VaultDataV5 {
            schema: 5,
            name: "v5".into(),
            created: 9,
            entries: vec![entry(1, "live")],
            settings: crate::model::VaultSettings::default(),
            last_backup: 11,
            trash: vec![TrashedEntryV5 {
                entry: entry(2, "binned"),
                deleted: 12,
            }],
            audit: vec![AuditEvent {
                at: 13,
                kind: AuditKind::Exported,
                detail: "x.csv".into(),
            }],
        };
        let body = postcard::to_allocvec(&old).unwrap();
        let mut plain = (body.len() as u32).to_le_bytes().to_vec();
        plain.extend_from_slice(&body);
        let d = decode_payload(&plain).unwrap();
        assert_eq!(d.schema, SCHEMA_VERSION);
        let e = &d.entries[0];
        assert_eq!((e.expires, e.auto_type.as_str()), (6, "{PASSWORD}{ENTER}"));
        assert!(e.attachments.is_empty());
        assert_eq!(d.trash[0].entry.title, "binned");
        assert_eq!(d.audit[0].detail, "x.csv");
        assert_eq!(decode_payload(&encode_payload(&d).unwrap()).unwrap(), d);
    }

    #[test]
    fn attachments_roundtrip() {
        use crate::model::Attachment;
        let mut d = VaultData::new("files");
        let mut e = Entry::new(EntryKind::SecureNote);
        e.attachments.push(Attachment {
            name: "codes.txt".into(),
            data: (0..=255u8).cycle().take(70_000).collect(),
            added: 1,
        });
        d.upsert(e);
        let back = decode_payload(&encode_payload(&d).unwrap()).unwrap();
        assert_eq!(back, d);
        assert_eq!(back.attachment_bytes(), 70_000);
    }

    #[test]
    fn schema_v4_roundtrips_new_fields() {
        let mut d = VaultData::new("v4");
        let mut e = Entry::new(EntryKind::Login);
        e.tags = vec!["work".into()];
        e.last_used = 99;
        e.fields.push(Field::with_value(
            "2FA",
            FieldKind::Totp,
            "JBSWY3DPEHPK3PXP",
        ));
        d.upsert(e.clone());
        e.fields[3].value = "changed".into();
        d.upsert(e);
        d.trash_entry(d.entries[0].id);
        d.settings.breach_list = r"D:\hibp.txt".into();
        let back = decode_payload(&encode_payload(&d).unwrap()).unwrap();
        assert_eq!(back, d);
        assert_eq!(
            back.trash[0].entry.fields.last().unwrap().kind,
            FieldKind::Totp
        );
    }

    #[test]
    fn future_schema_is_rejected() {
        let body = postcard::to_allocvec(&99u32).unwrap();
        let mut plain = (body.len() as u32).to_le_bytes().to_vec();
        plain.extend_from_slice(&body);
        assert!(matches!(
            decode_payload(&plain),
            Err(VaultError::Invalid(_))
        ));
    }

    #[test]
    fn vaults_keyed_with_raw_non_nfc_passwords_still_open() {
        // Before normalisation the raw UTF-8 bytes were used. Simulate such
        // a vault by wrapping the key with the decomposed bytes directly.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.vault");
        let decomposed = "cafe\u{301} au lait!!";
        assert!(!is_nfc(decomposed));
        let fast = KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).unwrap();
        let mut v = UnlockedVault::create(
            &path,
            &SecretString::from("placeholder password"),
            fast,
            "legacy",
            false,
        )
        .unwrap();
        let mut header = v.header.clone();
        let kek = crypto::derive_kek_bytes(decomposed.as_bytes(), None, &header.salt, &header.kdf)
            .unwrap();
        header.wrapped_key =
            crypto::wrap_key(&kek, &header.wrap_nonce, &header.key_wrap_aad(), &v.key).unwrap();
        v.header = header;
        v.save_overwriting_external_changes().unwrap();
        drop(v);
        assert!(UnlockedVault::open(&path, &SecretString::from(decomposed)).is_ok());
        assert!(UnlockedVault::open(&path, &SecretString::from("cafe au lait!!")).is_err());
    }

    #[test]
    fn payload_roundtrip_and_padding() {
        let mut d = VaultData::new("x");
        let mut e = Entry::new(EntryKind::Login);
        e.title = "t".repeat(100_000);
        d.entries.push(e);
        let enc = encode_payload(&d).unwrap();
        assert_eq!(enc.len() % PAD_BLOCK, 0);
        assert!(enc.len() > INITIAL_ENCODE_BUF);
        assert_eq!(decode_payload(&enc).unwrap(), d);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_payload(&[]).is_err());
        assert!(decode_payload(&[255, 255, 255, 255, 0]).is_err());
        assert!(decode_payload(&[3, 0, 0, 0, 1, 2, 3]).is_err());
    }
}
