//! Cryptographic primitives used by VaultRust.
//!
//! * Key derivation: Argon2id (v1.3) via the `argon2` crate.
//! * Authenticated encryption: XChaCha20-Poly1305 via `chacha20poly1305`.
//! * Randomness: the operating system CSPRNG (`OsRng` -> `getrandom`,
//!   which uses `ProcessPrng`/`BCryptGenRandom` on Windows).
//!
//! All key material lives in [`SecretBox`] / [`Zeroizing`] containers so it is
//! wiped when dropped. See `docs/SECURITY.md` for the rationale behind each
//! choice and the limits of in-memory protection.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 32;

/// A 256-bit symmetric key that is zeroized on drop.
pub type SecretKey = SecretBox<[u8; KEY_LEN]>;

/// Argon2id cost parameters, stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// Lower bound accepted when reading a vault (8 MiB).
    pub const MIN_M_COST_KIB: u32 = 8 * 1024;
    /// Upper bound accepted when reading a vault (2 GiB). Prevents a crafted
    /// file from forcing an enormous allocation.
    pub const MAX_M_COST_KIB: u32 = 2 * 1024 * 1024;
    pub const MAX_T_COST: u32 = 50;
    pub const MAX_P_COST: u32 = 16;

    /// 64 MiB, 3 passes, 4 lanes. Above the OWASP 2024 recommendation
    /// (19 MiB, t=2, p=1) while still unlocking in well under a second on a
    /// typical desktop.
    pub const STANDARD: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 4,
    };

    /// 256 MiB, 4 passes, 4 lanes. Noticeably slower to unlock.
    pub const STRONG: KdfParams = KdfParams {
        m_cost_kib: 256 * 1024,
        t_cost: 4,
        p_cost: 4,
    };

    /// 1 GiB, 4 passes, 4 lanes. Only for machines with plenty of RAM.
    pub const PARANOID: KdfParams = KdfParams {
        m_cost_kib: 1024 * 1024,
        t_cost: 4,
        p_cost: 4,
    };

    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        let p = KdfParams {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<()> {
        let ok = (Self::MIN_M_COST_KIB..=Self::MAX_M_COST_KIB).contains(&self.m_cost_kib)
            && (1..=Self::MAX_T_COST).contains(&self.t_cost)
            && (1..=Self::MAX_P_COST).contains(&self.p_cost)
            && self.m_cost_kib >= 8 * self.p_cost;
        if ok {
            Ok(())
        } else {
            Err(VaultError::InvalidKdfParams)
        }
    }

    pub fn describe(&self) -> String {
        let plural =
            |n: u32, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        format!(
            "Argon2id, {} MiB, {}, {}",
            self.m_cost_kib / 1024,
            plural(self.t_cost, "pass", "passes"),
            plural(self.p_cost, "lane", "lanes")
        )
    }
}

/// Fill a fixed-size array with output from the OS CSPRNG.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Generate a fresh random XChaCha20 nonce. With 192-bit random nonces the
/// probability of a collision under one key is negligible (~2^-96 after 2^48
/// messages), so no nonce counter has to be persisted.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    random_array::<NONCE_LEN>()
}

/// Generate a fresh random 256-bit key directly inside its secret container.
pub fn random_key() -> SecretKey {
    let mut key = Box::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(key.as_mut_slice());
    SecretBox::new(key)
}

/// Uniformly random integer in `0..bound` using rejection sampling, so there
/// is no modulo bias. `bound` must be non-zero.
pub fn random_below(bound: u32) -> u32 {
    assert!(bound > 0, "random_below: bound must be non-zero");
    // Largest multiple of `bound` that fits in u32 space; values at or above
    // it are rejected.
    let zone = u32::MAX - (u32::MAX - bound + 1) % bound;
    loop {
        let v = OsRng.next_u32();
        if v <= zone {
            return v % bound;
        }
    }
}

/// Derive the key-encryption key from the master password with Argon2id.
pub fn derive_kek(
    password: &SecretString,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<SecretKey> {
    params.validate()?;
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Box::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(
            password.expose_secret().as_bytes(),
            salt,
            out.as_mut_slice(),
        )
        .map_err(|_| VaultError::Kdf)?;
    Ok(SecretBox::new(out))
}

/// Encrypt `plaintext` with XChaCha20-Poly1305. Returns `ciphertext || tag`.
///
/// The plaintext is copied into a buffer that is encrypted in place, so no
/// stray plaintext copy is left behind in the returned allocation.
pub fn seal(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
    let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
    buf.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, &mut buf)
        .map_err(|_| VaultError::Encryption)?;
    buf.extend_from_slice(&tag);
    Ok(buf)
}

/// Authenticate and decrypt `ciphertext || tag`. Fails closed: if the tag does
/// not verify, no plaintext is returned.
pub fn open(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, AuthError> {
    if sealed.len() < TAG_LEN {
        return Err(AuthError);
    }
    let (ct, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
    let mut buf = Zeroizing::new(ct.to_vec());
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            aad,
            buf.as_mut_slice(),
            Tag::from_slice(tag),
        )
        .map_err(|_| AuthError)?;
    Ok(buf)
}

/// Authentication tag verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthError;

/// Encrypt a 256-bit key under another key ("key wrapping").
pub fn wrap_key(
    kek: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    key: &SecretKey,
) -> Result<[u8; KEY_LEN + TAG_LEN]> {
    let sealed = seal(kek, nonce, aad, key.expose_secret())?;
    let mut out = [0u8; KEY_LEN + TAG_LEN];
    out.copy_from_slice(&sealed);
    Ok(out)
}

/// Decrypt a wrapped key. Returns `None` if authentication fails.
pub fn unwrap_key(
    kek: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    wrapped: &[u8; KEY_LEN + TAG_LEN],
) -> Option<SecretKey> {
    let plain = open(kek, nonce, aad, wrapped).ok()?;
    if plain.len() != KEY_LEN {
        return None;
    }
    let mut key = Box::new([0u8; KEY_LEN]);
    key.copy_from_slice(&plain);
    Some(SecretBox::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn test_params() -> KdfParams {
        KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).unwrap()
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = random_key();
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"aad", b"hello world").unwrap();
        assert_eq!(ct.len(), 11 + TAG_LEN);
        assert_ne!(&ct[..11], b"hello world");
        let pt = open(&key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt.as_slice(), b"hello world");
    }

    #[test]
    fn open_rejects_wrong_key_nonce_aad_and_tampering() {
        let key = random_key();
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"aad", b"secret").unwrap();

        assert!(open(&random_key(), &nonce, b"aad", &ct).is_err());
        assert!(open(&key, &random_nonce(), b"aad", &ct).is_err());
        assert!(open(&key, &nonce, b"other", &ct).is_err());
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert!(open(&key, &nonce, b"aad", &bad).is_err(), "bit flip at {i}");
        }
        assert!(open(&key, &nonce, b"aad", &ct[..ct.len() - 1]).is_err());
        assert!(open(&key, &nonce, b"aad", &[]).is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..100_000 {
            assert!(seen.insert(random_nonce()), "duplicate nonce generated");
        }
    }

    #[test]
    fn random_keys_differ() {
        let a = random_key();
        let b = random_key();
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_ne!(a.expose_secret(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn kdf_is_deterministic_and_salt_and_password_dependent() {
        let p = test_params();
        let salt = random_array::<SALT_LEN>();
        let pw = SecretString::from("correct horse battery staple");
        let k1 = derive_kek(&pw, &salt, &p).unwrap();
        let k2 = derive_kek(&pw, &salt, &p).unwrap();
        assert_eq!(k1.expose_secret(), k2.expose_secret());

        let k3 = derive_kek(&pw, &random_array::<SALT_LEN>(), &p).unwrap();
        assert_ne!(k1.expose_secret(), k3.expose_secret());

        let k4 = derive_kek(
            &SecretString::from("Correct horse battery staple"),
            &salt,
            &p,
        )
        .unwrap();
        assert_ne!(k1.expose_secret(), k4.expose_secret());
    }

    #[test]
    fn kdf_params_bounds() {
        assert!(KdfParams::new(1024, 1, 1).is_err());
        assert!(KdfParams::new(KdfParams::MAX_M_COST_KIB + 1, 1, 1).is_err());
        assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 0, 1).is_err());
        assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 0).is_err());
        assert!(KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 17).is_err());
        KdfParams::STANDARD.validate().unwrap();
        KdfParams::STRONG.validate().unwrap();
        KdfParams::PARANOID.validate().unwrap();
    }

    #[test]
    fn wrap_unwrap() {
        let kek = random_key();
        let key = random_key();
        let nonce = random_nonce();
        let wrapped = wrap_key(&kek, &nonce, b"hdr", &key).unwrap();
        let back = unwrap_key(&kek, &nonce, b"hdr", &wrapped).unwrap();
        assert_eq!(back.expose_secret(), key.expose_secret());
        assert!(unwrap_key(&random_key(), &nonce, b"hdr", &wrapped).is_none());
        assert!(unwrap_key(&kek, &nonce, b"HDR", &wrapped).is_none());
    }

    #[test]
    fn random_below_is_in_range_and_covers_values() {
        let mut seen = [false; 7];
        for _ in 0..10_000 {
            let v = random_below(7) as usize;
            seen[v] = true;
        }
        assert!(seen.iter().all(|s| *s));
        assert_eq!(random_below(1), 0);
    }
}
