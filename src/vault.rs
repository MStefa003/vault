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
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, SecretKey, NONCE_LEN};
use crate::error::{Result, VaultError};
use crate::format::{Header, VaultFile, MAX_PAYLOAD_LEN, VAULT_ID_LEN};
use crate::model::{VaultData, SCHEMA_VERSION};
use crate::storage::{self, WriteMode};

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
        validate_master_password(password)?;
        if !overwrite && path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let key = crypto::random_key();
        let vault_id = crypto::random_array::<VAULT_ID_LEN>();
        let header = wrap_vault_key(password, kdf, vault_id, &key)?;
        let mut vault = UnlockedVault {
            path: path.to_path_buf(),
            header,
            key,
            data: VaultData::new(name),
            sealed: None,
            dirty: true,
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
        let bytes = storage::read_vault_bytes(path)?;
        storage::cleanup_stale_temp_files(path);
        Self::open_bytes(path, &bytes, password)
    }

    fn open_bytes(path: &Path, bytes: &[u8], password: &SecretString) -> Result<Self> {
        let file = VaultFile::from_bytes(bytes)?;
        let key = unwrap_with_password(&file.header, password)?;
        let plain = crypto::open(
            &key,
            &file.payload_nonce,
            &file.header.payload_aad(),
            &file.payload,
        )
        .map_err(|_| VaultError::PayloadTampered)?;
        let data = decode_payload(&plain)?;
        Ok(UnlockedVault {
            path: path.to_path_buf(),
            header: file.header,
            key,
            data,
            sealed: Some((file.payload_nonce, file.payload)),
            dirty: false,
        })
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
        self.write(WriteMode::Replace)
    }

    /// Save even though the file was changed externally. Only call this after
    /// the user explicitly chose to overwrite the other version.
    pub fn save_overwriting_external_changes(&mut self) -> Result<()> {
        self.write(WriteMode::Replace)
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
    pub fn verify_password(&self, password: &SecretString) -> bool {
        unwrap_with_password(&self.header, password).is_ok()
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

    /// Prepare a password change whose slow part (two Argon2 derivations) can
    /// run on another thread. Apply the result with
    /// [`apply_password_change`](Self::apply_password_change).
    pub fn password_change_task(
        &self,
        current: SecretString,
        new: SecretString,
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

    pub fn apply_password_change(&mut self, header: RewrappedHeader) -> Result<()> {
        let header = header.0;
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
    current: SecretString,
    new: SecretString,
    kdf: KdfParams,
}

/// A new header wrapping the existing vault key under a new password.
pub struct RewrappedHeader(Header);

impl PasswordChangeTask {
    pub fn run(self) -> Result<RewrappedHeader> {
        let unwrapped = unwrap_with_password(&self.header, &self.current)?;
        if unwrapped.expose_secret() != self.key.expose_secret() {
            return Err(VaultError::WrongPasswordOrTampered);
        }
        validate_master_password(&self.new)?;
        Ok(RewrappedHeader(wrap_vault_key(
            &self.new,
            self.kdf,
            self.header.vault_id,
            &self.key,
        )?))
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
    let bytes = storage::read_vault_bytes(backup)?;
    let mut vault = UnlockedVault::open_bytes(dest, &bytes, password)?;
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

pub fn validate_master_password(password: &SecretString) -> Result<()> {
    if password.expose_secret().chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(VaultError::Invalid(
            "the master password must be at least 10 characters long",
        ));
    }
    Ok(())
}

fn wrap_vault_key(
    password: &SecretString,
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
    };
    let kek = crypto::derive_kek(password, &header.salt, &header.kdf)?;
    header.wrapped_key = crypto::wrap_key(&kek, &header.wrap_nonce, &header.key_wrap_aad(), key)?;
    Ok(header)
}

fn unwrap_with_password(header: &Header, password: &SecretString) -> Result<SecretKey> {
    let kek = crypto::derive_kek(password, &header.salt, &header.kdf)?;
    crypto::unwrap_key(
        &kek,
        &header.wrap_nonce,
        &header.key_wrap_aad(),
        &header.wrapped_key,
    )
    .ok_or(VaultError::WrongPasswordOrTampered)
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
    use crate::model::{Entry, EntryKind};

    #[test]
    fn schema_v1_payload_is_upgraded() {
        use crate::model::v1::{VaultDataV1, VaultSettingsV1};
        let mut e = Entry::new(EntryKind::Login);
        e.title = "old".into();
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
        let settings = crate::model::VaultSettings {
            reveal_timeout_secs: 77,
            ..Default::default()
        };
        let old = VaultDataV2 {
            schema: 2,
            name: "v2".into(),
            created: 9,
            entries: vec![Entry::new(EntryKind::Wifi)],
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
