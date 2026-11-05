//! One-time-code secrets and otpauth:// URIs come from user input and
//! imports; parsing and code generation must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(t) = vaultrust::totp::Totp::parse(s) {
            let code = t.code_at(1_700_000_000);
            assert_eq!(code.len(), t.digits as usize);
            assert!(t.remaining_at(1_700_000_000) <= t.period);
        }
    }
});
