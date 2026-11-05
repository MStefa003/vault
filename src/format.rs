//! On-disk vault file format (version 1).
//!
//! All integers are little-endian. The layout is fixed-size up to the payload,
//! so parsing is a sequence of bounds-checked slice reads with no
//! attacker-controlled allocation other than the payload itself, whose length
//! is capped at [`MAX_PAYLOAD_LEN`] and must match the file length exactly.
//!
//! ```text
//! offset size  field
//!      0    8  magic  "VAULTRS\x1A"
//!      8    2  format version (1)
//!     10    1  KDF algorithm id     (1 = Argon2id v1.3)
//!     11    1  AEAD algorithm id    (1 = XChaCha20-Poly1305)
//!     12   16  vault id (random, fixed for the lifetime of the vault)
//!     28    4  Argon2 memory cost (KiB)
//!     32    4  Argon2 time cost
//!     36    4  Argon2 parallelism
//!     40   32  salt
//!     72   24  key-wrap nonce
//!     96   48  wrapped vault key (32-byte key + 16-byte Poly1305 tag)
//!    144   24  payload nonce
//!    168    8  payload length N (ciphertext + tag)
//!    176    N  payload ciphertext || tag
//! ```
//!
//! Associated data:
//! * key wrap: `"VaultRust/key-wrap/v1" || bytes[0..72]` — binds the wrapped key
//!   to the vault identity, version, algorithms, KDF parameters and salt.
//! * payload:  `"VaultRust/payload/v1" || bytes[0..28]` — binds the payload to
//!   the vault identity, version and algorithms, but *not* to the password
//!   wrapping, so a master password change only rewrites the header.

use crate::crypto::{KdfParams, KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{Result, VaultError};

pub const MAGIC: [u8; 8] = *b"VAULTRS\x1A";
pub const FORMAT_VERSION: u16 = 1;
pub const KDF_ARGON2ID_V13: u8 = 1;
pub const AEAD_XCHACHA20_POLY1305: u8 = 1;

pub const VAULT_ID_LEN: usize = 16;
pub const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

const OFF_VERSION: usize = 8;
const OFF_KDF_ALG: usize = 10;
const OFF_AEAD_ALG: usize = 11;
const OFF_VAULT_ID: usize = 12;
const OFF_M_COST: usize = 28;
const OFF_T_COST: usize = 32;
const OFF_P_COST: usize = 36;
const OFF_SALT: usize = 40;
const OFF_WRAP_NONCE: usize = 72;
const OFF_WRAPPED_KEY: usize = 96;
const OFF_PAYLOAD_NONCE: usize = 144;
const OFF_PAYLOAD_LEN: usize = 168;
pub const HEADER_LEN: usize = 176;

/// Payload ciphertext cap (256 MiB). Far beyond any realistic password vault.
pub const MAX_PAYLOAD_LEN: u64 = 256 * 1024 * 1024;

const KEY_WRAP_DOMAIN: &[u8] = b"VaultRust/key-wrap/v1";
const PAYLOAD_DOMAIN: &[u8] = b"VaultRust/payload/v1";

/// Everything in the file except the encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub vault_id: [u8; VAULT_ID_LEN],
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub wrap_nonce: [u8; NONCE_LEN],
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
}

/// A complete parsed vault file. Contains only public or encrypted data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFile {
    pub header: Header,
    pub payload_nonce: [u8; NONCE_LEN],
    pub payload: Vec<u8>,
}

impl Header {
    /// Bytes 0..72 of the serialized header (identity, version, algorithms,
    /// KDF parameters, salt).
    fn prefix_bytes(&self) -> [u8; OFF_WRAP_NONCE] {
        let mut b = [0u8; OFF_WRAP_NONCE];
        b[..8].copy_from_slice(&MAGIC);
        b[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[OFF_KDF_ALG] = KDF_ARGON2ID_V13;
        b[OFF_AEAD_ALG] = AEAD_XCHACHA20_POLY1305;
        b[OFF_VAULT_ID..OFF_M_COST].copy_from_slice(&self.vault_id);
        b[OFF_M_COST..OFF_T_COST].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        b[OFF_T_COST..OFF_P_COST].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        b[OFF_P_COST..OFF_SALT].copy_from_slice(&self.kdf.p_cost.to_le_bytes());
        b[OFF_SALT..OFF_WRAP_NONCE].copy_from_slice(&self.salt);
        b
    }

    /// Associated data for wrapping/unwrapping the vault key.
    pub fn key_wrap_aad(&self) -> Vec<u8> {
        let mut aad = KEY_WRAP_DOMAIN.to_vec();
        aad.extend_from_slice(&self.prefix_bytes());
        aad
    }

    /// Associated data for the payload. Independent of the password wrapping.
    pub fn payload_aad(&self) -> Vec<u8> {
        payload_aad_for(&self.vault_id)
    }
}

pub fn payload_aad_for(vault_id: &[u8; VAULT_ID_LEN]) -> Vec<u8> {
    let mut aad = PAYLOAD_DOMAIN.to_vec();
    aad.extend_from_slice(&MAGIC);
    aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    aad.push(KDF_ARGON2ID_V13);
    aad.push(AEAD_XCHACHA20_POLY1305);
    aad.extend_from_slice(vault_id);
    aad
}

impl VaultFile {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.header.prefix_bytes());
        out.extend_from_slice(&self.header.wrap_nonce);
        out.extend_from_slice(&self.header.wrapped_key);
        out.extend_from_slice(&self.payload_nonce);
        out.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.payload);
        debug_assert_eq!(out.len(), HEADER_LEN + self.payload.len());
        out
    }

    /// Parse a vault file. Performs structural validation only; authenticity
    /// is established later by successfully decrypting.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 || bytes[..8] != MAGIC {
            return Err(VaultError::NotAVault);
        }
        if bytes.len() < HEADER_LEN {
            return Err(VaultError::Malformed("file is truncated"));
        }
        let version = u16::from_le_bytes(arr(bytes, OFF_VERSION));
        if version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        if bytes[OFF_KDF_ALG] != KDF_ARGON2ID_V13 || bytes[OFF_AEAD_ALG] != AEAD_XCHACHA20_POLY1305
        {
            return Err(VaultError::UnsupportedAlgorithm);
        }
        let kdf = KdfParams {
            m_cost_kib: u32::from_le_bytes(arr(bytes, OFF_M_COST)),
            t_cost: u32::from_le_bytes(arr(bytes, OFF_T_COST)),
            p_cost: u32::from_le_bytes(arr(bytes, OFF_P_COST)),
        };
        kdf.validate()?;

        let payload_len = u64::from_le_bytes(arr(bytes, OFF_PAYLOAD_LEN));
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(VaultError::Malformed("payload length exceeds limit"));
        }
        if payload_len < TAG_LEN as u64 {
            return Err(VaultError::Malformed("payload too short"));
        }
        let actual = (bytes.len() - HEADER_LEN) as u64;
        if actual != payload_len {
            return Err(VaultError::Malformed(
                "payload length does not match file size (truncated or extended file)",
            ));
        }

        Ok(VaultFile {
            header: Header {
                vault_id: arr(bytes, OFF_VAULT_ID),
                kdf,
                salt: arr(bytes, OFF_SALT),
                wrap_nonce: arr(bytes, OFF_WRAP_NONCE),
                wrapped_key: arr(bytes, OFF_WRAPPED_KEY),
            },
            payload_nonce: arr(bytes, OFF_PAYLOAD_NONCE),
            payload: bytes[HEADER_LEN..].to_vec(),
        })
    }
}

/// Copy a fixed-size array out of `bytes` at `off`. Callers have already
/// checked that `bytes.len() >= HEADER_LEN`, and all offsets are constants
/// inside the header.
fn arr<const N: usize>(bytes: &[u8], off: usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&bytes[off..off + N]);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultFile {
        VaultFile {
            header: Header {
                vault_id: [1; 16],
                kdf: KdfParams::STANDARD,
                salt: [2; 32],
                wrap_nonce: [3; 24],
                wrapped_key: [4; 48],
            },
            payload_nonce: [5; 24],
            payload: vec![6; 100],
        }
    }

    #[test]
    fn roundtrip() {
        let f = sample();
        let bytes = f.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN + 100);
        assert_eq!(VaultFile::from_bytes(&bytes).unwrap(), f);
    }

    #[test]
    fn rejects_bad_magic_version_alg_and_lengths() {
        let good = sample().to_bytes();

        assert!(matches!(
            VaultFile::from_bytes(b"hello"),
            Err(VaultError::NotAVault)
        ));
        assert!(matches!(
            VaultFile::from_bytes(&[]),
            Err(VaultError::NotAVault)
        ));

        let mut b = good.clone();
        b[0] = b'X';
        assert!(matches!(
            VaultFile::from_bytes(&b),
            Err(VaultError::NotAVault)
        ));

        let mut b = good.clone();
        b[8] = 2;
        assert!(matches!(
            VaultFile::from_bytes(&b),
            Err(VaultError::UnsupportedVersion(2))
        ));

        let mut b = good.clone();
        b[10] = 9;
        assert!(matches!(
            VaultFile::from_bytes(&b),
            Err(VaultError::UnsupportedAlgorithm)
        ));

        let mut b = good.clone();
        b[11] = 9;
        assert!(matches!(
            VaultFile::from_bytes(&b),
            Err(VaultError::UnsupportedAlgorithm)
        ));

        // Absurd memory cost is rejected before any allocation.
        let mut b = good.clone();
        b[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            VaultFile::from_bytes(&b),
            Err(VaultError::InvalidKdfParams)
        ));

        // Truncated and extended files.
        assert!(VaultFile::from_bytes(&good[..good.len() - 1]).is_err());
        assert!(VaultFile::from_bytes(&good[..HEADER_LEN - 1]).is_err());
        let mut b = good.clone();
        b.push(0);
        assert!(VaultFile::from_bytes(&b).is_err());

        // Huge declared payload length.
        let mut b = good.clone();
        b[168..176].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(VaultFile::from_bytes(&b).is_err());
    }

    #[test]
    fn every_truncation_is_rejected_without_panicking() {
        let good = sample().to_bytes();
        for len in 0..good.len() {
            assert!(VaultFile::from_bytes(&good[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn aad_binds_expected_fields() {
        let f = sample();
        let mut g = f.clone();
        g.header.salt[0] ^= 1;
        assert_ne!(f.header.key_wrap_aad(), g.header.key_wrap_aad());
        assert_eq!(f.header.payload_aad(), g.header.payload_aad());

        let mut h = f.clone();
        h.header.kdf.t_cost += 1;
        assert_ne!(f.header.key_wrap_aad(), h.header.key_wrap_aad());

        let mut i = f.clone();
        i.header.vault_id[0] ^= 1;
        assert_ne!(f.header.key_wrap_aad(), i.header.key_wrap_aad());
        assert_ne!(f.header.payload_aad(), i.header.payload_aad());
    }
}
