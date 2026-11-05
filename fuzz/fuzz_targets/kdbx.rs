//! KeePass import must never panic, hang or over-allocate on arbitrary
//! input (key-derivation limits are lowered under `cfg(fuzzing)`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

fuzz_target!(|data: &[u8]| {
    let _ = vaultrust::kdbx::import_kdbx(data, &SecretString::from("fuzz"));
});
