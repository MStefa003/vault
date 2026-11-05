//! Error type shared by the storage and cryptography layers.
//!
//! Error messages never contain secret material (passwords, keys or
//! decrypted vault contents).

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("file system error: {0}")]
    Io(#[from] io::Error),

    #[error("not a VaultRust vault file")]
    NotAVault,

    #[error("malformed vault file: {0}")]
    Malformed(&'static str),

    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),

    #[error("unsupported algorithm identifier")]
    UnsupportedAlgorithm,

    #[error("key derivation parameters are out of the accepted range")]
    InvalidKdfParams,

    #[error("key derivation failed")]
    Kdf,

    /// Unwrapping the vault key failed: either the master password is wrong
    /// or the header was modified. The two cases are cryptographically
    /// indistinguishable by design.
    #[error("incorrect master password, or the vault header has been modified")]
    WrongPasswordOrTampered,

    /// The key unwrapped correctly but the payload did not authenticate.
    #[error(
        "vault contents failed authentication: the file is corrupted or has been tampered with"
    )]
    PayloadTampered,

    #[error("encryption failed")]
    Encryption,

    #[error("vault contents could not be decoded")]
    Decode,

    #[error("vault contents could not be encoded")]
    Encode,

    #[error("vault contents exceed the maximum supported size")]
    TooLarge,

    #[error("a file already exists at the destination")]
    AlreadyExists,

    /// The vault file on disk changed since this session read or wrote it.
    #[error("the vault file was changed outside this window since it was opened")]
    ModifiedExternally,

    #[error("backup verification failed: the written backup does not match this vault")]
    BackupVerification,

    #[error("{0}")]
    Invalid(&'static str),
}

pub type Result<T> = std::result::Result<T, VaultError>;
