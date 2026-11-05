//! Windows Hello quick unlock.
//!
//! How it works (the same idea as KeePassXC's Windows Hello support):
//!
//! 1. Windows Hello holds an RSA key pair for VaultRust in the TPM (a "key
//!    credential"). The private key never leaves it, and every use requires
//!    the user's fingerprint, face or PIN.
//! 2. On enabling, VaultRust asks Hello to sign a challenge derived from the
//!    vault id and a random salt. RSA PKCS#1 v1.5 signatures are
//!    deterministic, so the same challenge always yields the same signature;
//!    this is verified by signing twice.
//! 3. SHA-256 of the signature is a 256-bit key that encrypts (with
//!    XChaCha20-Poly1305) a copy of the vault key and, for vaults with one,
//!    the key-file digest. That blob is stored in
//!    `%APPDATA%\VaultRust\hello\<vault id>.bin`.
//! 4. To unlock, Hello signs the same challenge again; the derived key
//!    decrypts the blob, and the vault key opens the vault.
//!
//! The blob is useless without this computer's TPM and the user's Hello
//! gesture. VaultRust still asks for the master password once per app start
//! before offering Hello (enforced by the UI).

use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, KeyFile, SecretKey, KEY_LEN, NONCE_LEN};
use crate::format::VAULT_ID_LEN;
use crate::storage::{atomic_write, WriteMode};

const MAGIC: &[u8; 8] = b"VRHELLO1";
const SALT_LEN: usize = 32;
const CHALLENGE_DOMAIN: &[u8] = b"VaultRust/hello-challenge/v1";
const KEY_DOMAIN: &[u8] = b"VaultRust/hello-key/v1";
const AAD_DOMAIN: &[u8] = b"VaultRust/hello-wrap/v1";
/// Plaintext: vault key, key-file flag, key-file digest (zero if none).
const PLAIN_LEN: usize = KEY_LEN + 1 + KEY_LEN;

#[derive(Debug, thiserror::Error)]
pub enum HelloError {
    #[error("Windows Hello isn't set up on this computer")]
    Unavailable,
    #[error("Windows Hello was cancelled")]
    Cancelled,
    #[error("Windows Hello isn't turned on for this vault")]
    NotEnabled,
    #[error("this computer's Windows Hello key can't be used for unlocking (its signatures vary)")]
    NotDeterministic,
    #[error("the Windows Hello unlock data doesn't match this vault; turn Hello off and on again")]
    Mismatch,
    #[error("Windows Hello failed: {0}")]
    Platform(String),
    #[error("couldn't save the Windows Hello unlock data: {0}")]
    Io(#[from] std::io::Error),
}

/// What Hello unlocks: the vault key and, for vaults that use one, the key
/// file (as its digest).
pub struct HelloSecret {
    pub vault_key: SecretKey,
    pub key_file: Option<KeyFile>,
}

/// The encrypted unlock data for one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloBlob {
    vault_id: [u8; VAULT_ID_LEN],
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    sealed: Vec<u8>,
}

impl HelloBlob {
    fn to_bytes(&self) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&self.vault_id);
        b.extend_from_slice(&self.salt);
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.sealed);
        b
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        let rest = b.strip_prefix(MAGIC)?;
        let (vault_id, rest) = rest.split_first_chunk::<VAULT_ID_LEN>()?;
        let (salt, rest) = rest.split_first_chunk::<SALT_LEN>()?;
        let (nonce, sealed) = rest.split_first_chunk::<NONCE_LEN>()?;
        (sealed.len() == PLAIN_LEN + crypto::TAG_LEN).then(|| HelloBlob {
            vault_id: *vault_id,
            salt: *salt,
            nonce: *nonce,
            sealed: sealed.to_vec(),
        })
    }

    fn challenge(&self) -> [u8; 32] {
        challenge(&self.vault_id, &self.salt)
    }
}

fn challenge(vault_id: &[u8; VAULT_ID_LEN], salt: &[u8; SALT_LEN]) -> [u8; 32] {
    Sha256::new()
        .chain_update(CHALLENGE_DOMAIN)
        .chain_update(vault_id)
        .chain_update(salt)
        .finalize()
        .into()
}

fn key_from_signature(sig: &[u8]) -> SecretKey {
    let digest = Sha256::new()
        .chain_update(KEY_DOMAIN)
        .chain_update(sig)
        .finalize();
    let mut k = Box::new([0u8; KEY_LEN]);
    k.copy_from_slice(&digest);
    SecretBox::new(k)
}

fn aad(vault_id: &[u8; VAULT_ID_LEN]) -> Vec<u8> {
    let mut a = AAD_DOMAIN.to_vec();
    a.extend_from_slice(vault_id);
    a
}

/// Encrypt `secret` for `vault_id` with a key only `sign` can reproduce.
/// `sign` is called twice to make sure its signatures are deterministic.
pub fn seal(
    vault_id: [u8; VAULT_ID_LEN],
    secret: &HelloSecret,
    mut sign: impl FnMut(&[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError>,
) -> Result<HelloBlob, HelloError> {
    let salt: [u8; SALT_LEN] = crypto::random_array();
    let ch = challenge(&vault_id, &salt);
    let first = sign(&ch)?;
    let second = sign(&ch)?;
    if *first != *second {
        return Err(HelloError::NotDeterministic);
    }
    let key = key_from_signature(&first);
    let mut plain = Zeroizing::new([0u8; PLAIN_LEN]);
    plain[..KEY_LEN].copy_from_slice(secret.vault_key.expose_secret());
    if let Some(kf) = &secret.key_file {
        plain[KEY_LEN] = 1;
        plain[KEY_LEN + 1..].copy_from_slice(kf.digest_bytes());
    }
    let nonce = crypto::random_nonce();
    let sealed = crypto::seal(&key, &nonce, &aad(&vault_id), plain.as_slice())
        .map_err(|e| HelloError::Platform(e.to_string()))?;
    Ok(HelloBlob {
        vault_id,
        salt,
        nonce,
        sealed,
    })
}

/// Decrypt a blob with a fresh signature from `sign`.
pub fn open(
    blob: &HelloBlob,
    vault_id: &[u8; VAULT_ID_LEN],
    sign: impl FnOnce(&[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError>,
) -> Result<HelloSecret, HelloError> {
    if blob.vault_id != *vault_id {
        return Err(HelloError::Mismatch);
    }
    let sig = sign(&blob.challenge())?;
    let key = key_from_signature(&sig);
    let plain = crypto::open(&key, &blob.nonce, &aad(&blob.vault_id), &blob.sealed)
        .map_err(|_| HelloError::Mismatch)?;
    let mut vk = Box::new([0u8; KEY_LEN]);
    vk.copy_from_slice(&plain[..KEY_LEN]);
    let key_file = (plain[KEY_LEN] == 1).then(|| {
        let mut d = [0u8; KEY_LEN];
        d.copy_from_slice(&plain[KEY_LEN + 1..]);
        let kf = KeyFile::from_digest(d);
        zeroize::Zeroize::zeroize(&mut d);
        kf
    });
    Ok(HelloSecret {
        vault_key: SecretBox::new(vk),
        key_file,
    })
}

fn blob_dir() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA").map(PathBuf::from)?;
    Some(base.join("VaultRust").join("hello"))
}

fn blob_path(vault_id: &[u8; VAULT_ID_LEN]) -> Option<PathBuf> {
    let hex: String = vault_id.iter().map(|b| format!("{b:02x}")).collect();
    Some(blob_dir()?.join(format!("{hex}.bin")))
}

/// The stored unlock data for a vault, if Hello is enabled for it.
pub fn load(vault_id: &[u8; VAULT_ID_LEN]) -> Option<HelloBlob> {
    let bytes = std::fs::read(blob_path(vault_id)?).ok()?;
    HelloBlob::from_bytes(&bytes).filter(|b| b.vault_id == *vault_id)
}

pub fn is_enabled(vault_id: &[u8; VAULT_ID_LEN]) -> bool {
    load(vault_id).is_some()
}

pub fn store(blob: &HelloBlob) -> Result<(), HelloError> {
    let path = blob_path(&blob.vault_id).ok_or(HelloError::Unavailable)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    atomic_write(&path, &blob.to_bytes(), WriteMode::Replace)
        .map_err(|e| HelloError::Platform(e.to_string()))
}

pub fn remove(vault_id: &[u8; VAULT_ID_LEN]) {
    if let Some(p) = blob_path(vault_id) {
        let _ = std::fs::remove_file(p);
    }
}

/// Turn Hello on for a vault: create (or reuse) VaultRust's Hello key and
/// store the encrypted unlock data. Shows the Hello prompt (more than once).
pub fn enable(vault_id: [u8; VAULT_ID_LEN], secret: &HelloSecret) -> Result<(), HelloError> {
    platform::ensure_credential()?;
    let blob = seal(vault_id, secret, platform::sign)?;
    store(&blob)
}

/// Unlock with Hello: shows the Hello prompt.
pub fn unlock(vault_id: &[u8; VAULT_ID_LEN]) -> Result<HelloSecret, HelloError> {
    let blob = load(vault_id).ok_or(HelloError::NotEnabled)?;
    open(&blob, vault_id, platform::sign)
}

pub use platform::is_available;

#[cfg(windows)]
mod platform {
    use windows::core::HSTRING;
    use windows::Security::Credentials::{
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use zeroize::Zeroizing;

    use super::HelloError;

    /// Name of VaultRust's key credential (one per Windows user, shared by
    /// all vaults; each vault uses its own challenge).
    const CREDENTIAL: &str = "VaultRust";

    fn platform(e: windows::core::Error) -> HelloError {
        HelloError::Platform(e.message())
    }

    fn status(s: KeyCredentialStatus) -> Result<(), HelloError> {
        match s {
            KeyCredentialStatus::Success => Ok(()),
            KeyCredentialStatus::UserCanceled => Err(HelloError::Cancelled),
            KeyCredentialStatus::NotFound => Err(HelloError::NotEnabled),
            KeyCredentialStatus::SecurityDeviceLocked => Err(HelloError::Platform(
                "the security device is locked; try again later".into(),
            )),
            _ => Err(HelloError::Unavailable),
        }
    }

    /// Whether Windows Hello is set up for this user (asked once per run).
    pub fn is_available() -> bool {
        if cfg!(test) {
            return false;
        }
        static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            KeyCredentialManager::IsSupportedAsync()
                .and_then(|op| op.join())
                .unwrap_or(false)
        })
    }

    /// Open VaultRust's key credential, creating it if it doesn't exist.
    /// Existing credentials are reused so enabling Hello for a second vault
    /// doesn't invalidate the first.
    pub fn ensure_credential() -> Result<(), HelloError> {
        if !is_available() {
            return Err(HelloError::Unavailable);
        }
        let name = HSTRING::from(CREDENTIAL);
        let opened = KeyCredentialManager::OpenAsync(&name)
            .and_then(|op| op.join())
            .map_err(platform)?;
        if opened.Status().map_err(platform)? == KeyCredentialStatus::Success {
            return Ok(());
        }
        crate::os_protect::focus_hello_prompt_soon();
        let created = KeyCredentialManager::RequestCreateAsync(
            &name,
            KeyCredentialCreationOption::FailIfExists,
        )
        .and_then(|op| op.join())
        .map_err(platform)?;
        status(created.Status().map_err(platform)?)
    }

    /// Sign `data` with VaultRust's Hello key (shows the Hello prompt).
    pub fn sign(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError> {
        let name = HSTRING::from(CREDENTIAL);
        let opened = KeyCredentialManager::OpenAsync(&name)
            .and_then(|op| op.join())
            .map_err(platform)?;
        status(opened.Status().map_err(platform)?)?;
        let credential = opened.Credential().map_err(platform)?;
        let buffer = CryptographicBuffer::CreateFromByteArray(data).map_err(platform)?;
        crate::os_protect::focus_hello_prompt_soon();
        let result = credential
            .RequestSignAsync(&buffer)
            .and_then(|op| op.join())
            .map_err(platform)?;
        status(result.Status().map_err(platform)?)?;
        let signature = result.Result().map_err(platform)?;
        let mut out = windows::core::Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&signature, &mut out).map_err(platform)?;
        Ok(Zeroizing::new(out.to_vec()))
    }
}

#[cfg(not(windows))]
mod platform {
    use super::HelloError;
    use zeroize::Zeroizing;

    pub fn is_available() -> bool {
        false
    }
    pub fn ensure_credential() -> Result<(), HelloError> {
        Err(HelloError::Unavailable)
    }
    pub fn sign(_data: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError> {
        Err(HelloError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};

    /// A deterministic stand-in for the TPM: HMAC with a fixed device key.
    fn fake_signer(
        device: &'static [u8],
    ) -> impl FnMut(&[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError> {
        move |data| {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(device).unwrap();
            m.update(data);
            Ok(Zeroizing::new(m.finalize().into_bytes().to_vec()))
        }
    }

    fn secret(with_key_file: bool) -> HelloSecret {
        HelloSecret {
            vault_key: crypto::random_key(),
            key_file: with_key_file.then(|| KeyFile::from_bytes(b"kf")),
        }
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let id = [7u8; VAULT_ID_LEN];
        for kf in [false, true] {
            let s = secret(kf);
            let blob = seal(id, &s, fake_signer(b"device A")).unwrap();
            let back = HelloBlob::from_bytes(&blob.to_bytes()).unwrap();
            assert_eq!(back, blob);
            let out = open(&back, &id, fake_signer(b"device A")).unwrap();
            assert_eq!(out.vault_key.expose_secret(), s.vault_key.expose_secret());
            assert_eq!(
                out.key_file.as_ref().map(|k| *k.digest_bytes()),
                s.key_file.as_ref().map(|k| *k.digest_bytes())
            );
        }
    }

    #[test]
    fn other_devices_vaults_and_tampering_fail() {
        let id = [7u8; VAULT_ID_LEN];
        let blob = seal(id, &secret(false), fake_signer(b"device A")).unwrap();
        assert!(matches!(
            open(&blob, &id, fake_signer(b"device B")),
            Err(HelloError::Mismatch)
        ));
        assert!(matches!(
            open(&blob, &[8u8; VAULT_ID_LEN], fake_signer(b"device A")),
            Err(HelloError::Mismatch)
        ));
        let mut bytes = blob.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let bad = HelloBlob::from_bytes(&bytes).unwrap();
        assert!(open(&bad, &id, fake_signer(b"device A")).is_err());
        assert!(HelloBlob::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert!(HelloBlob::from_bytes(b"nonsense").is_none());
    }

    #[test]
    fn non_deterministic_signers_are_refused() {
        let mut n = 0u8;
        let flaky = move |_: &[u8]| {
            n += 1;
            Ok(Zeroizing::new(vec![n; 32]))
        };
        assert!(matches!(
            seal([1; VAULT_ID_LEN], &secret(false), flaky),
            Err(HelloError::NotDeterministic)
        ));
    }

    #[test]
    fn cancelled_prompt_is_reported() {
        let cancel = |_: &[u8]| Err(HelloError::Cancelled);
        assert!(matches!(
            seal([1; VAULT_ID_LEN], &secret(false), cancel),
            Err(HelloError::Cancelled)
        ));
    }
}
