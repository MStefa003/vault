//! CSV import must never panic on arbitrary input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vaultrust::import_export::import_csv(data);
});
