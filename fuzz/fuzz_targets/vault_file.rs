//! The vault file parser must never panic, and anything it accepts must
//! serialise back to the identical bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultrust::format::VaultFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = VaultFile::from_bytes(data) {
        assert_eq!(file.to_bytes(), data);
    }
});
