//! Error type shared by the storage and cryptography layers.
//!
//! Error messages never contain secret material (passwords, keys or
//! decrypted vault contents).

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("{}", crate::i18n::format(crate::i18n::tr("file system error: {0}"), &[("0", .0)]))]
    Io(#[from] io::Error),

    #[error("{}", crate::i18n::tr("not a VaultRust vault file"))]
    NotAVault,

    #[error("{}", crate::i18n::format(crate::i18n::tr("malformed vault file: {0}"), &[("0", .0)]))]
    Malformed(&'static str),

    #[error("{}", crate::i18n::format(crate::i18n::tr("unsupported vault format version {0}"), &[("0", .0)]))]
    UnsupportedVersion(u16),

    #[error("{}", crate::i18n::tr("unsupported algorithm identifier"))]
    UnsupportedAlgorithm,

    #[error(
        "{}",
        crate::i18n::tr("key derivation parameters are out of the accepted range")
    )]
    InvalidKdfParams,

    #[error("{}", crate::i18n::tr("key derivation failed"))]
    Kdf,

    /// Unwrapping the vault key failed: either the master password is wrong
    /// or the header was modified. The two cases are cryptographically
    /// indistinguishable by design.
    #[error(
        "{}",
        crate::i18n::tr("incorrect master password, or the vault header has been modified")
    )]
    WrongPasswordOrTampered,

    #[error("{}", crate::i18n::tr("this vault also needs its key file to unlock"))]
    KeyFileRequired,

    /// The key unwrapped correctly but the payload did not authenticate.
    #[error(
        "{}",
        crate::i18n::tr(
            "vault contents failed authentication: the file is corrupted or has been tampered with"
        )
    )]
    PayloadTampered,

    #[error("{}", crate::i18n::tr("encryption failed"))]
    Encryption,

    #[error("{}", crate::i18n::tr("vault contents could not be decoded"))]
    Decode,

    #[error("{}", crate::i18n::tr("vault contents could not be encoded"))]
    Encode,

    #[error(
        "{}",
        crate::i18n::tr("vault contents exceed the maximum supported size")
    )]
    TooLarge,

    #[error("{}", crate::i18n::tr("a file already exists at the destination"))]
    AlreadyExists,

    /// The vault file on disk changed since this session read or wrote it.
    #[error(
        "{}",
        crate::i18n::tr("the vault file was changed outside this window since it was opened")
    )]
    ModifiedExternally,

    #[error(
        "{}",
        crate::i18n::tr(
            "backup verification failed: the written backup does not match this vault"
        )
    )]
    BackupVerification,

    #[error("{}", crate::i18n::tr(.0))]
    Invalid(&'static str),
}

pub type Result<T> = std::result::Result<T, VaultError>;
