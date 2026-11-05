//! VaultRust: a strictly local, offline password safe.
//!
//! The library holds everything security relevant (cryptography, file
//! format, storage, data model, generator, analysis, import/export); the
//! `ui` module is a thin egui front end on top of it.

// Unsafe code is denied everywhere except `os_protect`, which makes one
// documented Win32 call.
#![deny(unsafe_code)]

pub mod analysis;
pub mod clipboard;
pub mod crypto;
pub mod error;
pub mod format;
pub mod generator;
pub mod import_export;
pub mod model;
pub mod os_protect;
pub mod recent;
pub mod session;
pub mod storage;
pub mod timeutil;
pub mod ui;
pub mod vault;

pub use error::{Result, VaultError};
pub use vault::UnlockedVault;
