//! Cheap, deterministic stand-ins for the fuzz targets in `fuzz/` that run
//! with every `cargo test`: feed every parser that sees untrusted input a
//! few thousand random and mutated inputs and require that none panics.

use secrecy::SecretString;
use vaultrust::crypto::random_array;
use vaultrust::format::VaultFile;
use vaultrust::import_export::{import_csv, import_json};
use vaultrust::totp::Totp;

/// Small xorshift generator seeded from the OS, so every run explores
/// different inputs; the seed is printed to reproduce a failure.
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        let seed = u64::from_le_bytes(random_array::<8>()) | 1;
        println!("robustness seed: {seed}");
        Rng(seed)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = (self.next() as usize) % (max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut v = seed.to_vec();
        for _ in 0..1 + self.next() % 8 {
            if v.is_empty() {
                break;
            }
            let i = (self.next() as usize) % v.len();
            match self.next() % 3 {
                0 => v[i] = self.next() as u8,
                1 => {
                    v.truncate(i);
                }
                _ => v.insert(i, self.next() as u8),
            }
        }
        v
    }
}

#[test]
fn vault_parser_and_payload_decoder_never_panic() {
    let mut rng = Rng::new();
    for _ in 0..3000 {
        let data = rng.bytes(400);
        if let Ok(f) = VaultFile::from_bytes(&data) {
            assert_eq!(f.to_bytes(), data);
        }
        vaultrust::fuzzing::decode_payload(&data);
    }
}

#[test]
fn csv_and_json_import_never_panic() {
    let mut rng = Rng::new();
    let csv_seed = b"name,url,username,password,totp,tags\nA,https://a,u,p,JBSWY3DP,x;y\n";
    let json_seed = br#"{"encrypted":false,"items":[{"type":1,"name":"a","login":{"username":"u","password":"p","totp":"x"}}]}"#;
    for _ in 0..2000 {
        let _ = import_csv(&rng.mutate(csv_seed));
        let _ = import_json(&rng.mutate(json_seed));
        let raw = rng.bytes(200);
        let _ = import_csv(&raw);
        let _ = import_json(&raw);
    }
}

#[test]
fn kdbx_import_never_panics_on_mutated_databases() {
    let mut rng = Rng::new();
    let seed = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/kdbx/kdbx3-aes-salsa20.kdbx"),
    )
    .unwrap();
    let pw = SecretString::from("not the password");
    // Header fields (truncated, garbled, inserted bytes).
    for _ in 0..150 {
        let _ = vaultrust::kdbx::import_kdbx(&rng.mutate(&seed[..64]), &pw);
    }
    // Bit flips in the encrypted payload, with the right password so
    // decryption, block checks, decompression and XML parsing all run. The
    // header (and its KDF round count) stays intact, so every case is fast.
    let right = SecretString::from("fixture password");
    let header_end = 256.min(seed.len());
    for _ in 0..40 {
        let mut m = seed.clone();
        let i = header_end + (rng.next() as usize) % (m.len() - header_end);
        m[i] ^= 1 << (rng.next() % 8);
        assert!(
            vaultrust::kdbx::import_kdbx(&m, &right).is_err(),
            "flip at {i} went unnoticed"
        );
    }
}

#[test]
fn totp_parsing_never_panics() {
    let mut rng = Rng::new();
    let seed = b"otpauth://totp/Ex:a?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256";
    for _ in 0..3000 {
        let m = rng.mutate(seed);
        if let Ok(s) = std::str::from_utf8(&m) {
            if let Ok(t) = Totp::parse(s) {
                assert_eq!(t.code_at(1_700_000_000).len(), t.digits as usize);
            }
        }
    }
}
