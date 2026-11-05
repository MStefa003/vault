//! Decoding a decrypted payload (every schema version) must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vaultrust::fuzzing::decode_payload(data);
});
