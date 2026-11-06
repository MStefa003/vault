//! VaultRust: a local password safe. Vault data never leaves the computer;
//! the only network use is the optional update check (`update`).
//!
//! The library holds everything security relevant (cryptography, file
//! format, storage, data model, generator, analysis, import/export); the
//! `ui` module is a thin egui front end on top of it.

// Unsafe code is denied everywhere except `os_protect`, which makes one
// documented Win32 call.
#![deny(unsafe_code)]

pub mod analysis;
pub mod autotype;
pub mod breach;
#[cfg(feature = "gui")]
pub mod clipboard;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod format;
pub mod generator;
pub mod hello;
pub mod i18n;
pub mod import_export;
pub mod kdbx;
pub mod model;
pub mod os_protect;
pub mod prefs;
#[cfg(feature = "gui")]
pub mod qr;
pub mod recent;
pub mod session;
pub mod storage;
pub mod timeutil;
pub mod totp;
#[cfg(feature = "gui")]
pub mod ui;
pub mod update;
pub mod vault;

pub use error::{Result, VaultError};
pub use vault::{Credentials, UnlockedVault};

/// Entry points for the fuzz targets in `fuzz/`. Not a stable API.
#[doc(hidden)]
pub mod fuzzing {
    pub fn decode_payload(plain: &[u8]) {
        let _ = crate::vault::decode_payload(plain);
    }
}
