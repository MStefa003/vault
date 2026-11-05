//! Release signing for VaultRust updates (see docs/RELEASING.md).
//!
//! ```text
//! vaultrust-sign generate <key file>           create a signing key
//! vaultrust-sign sign <exe> <version> <out>    sign a build (key from
//!                                              VAULTRUST_SIGNING_KEY)
//! vaultrust-sign verify <exe> <version> <sig>  check against the built-in key
//! ```

use std::process::ExitCode;

use rand_core::{OsRng, RngCore};
use vaultrust::update::{hex_decode, hex_encode, signed_message, verify, Version, PUBLIC_KEY};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["generate", key_file] => generate(key_file),
        ["sign", exe, version, out] => sign(exe, version, out),
        ["verify", exe, version, sig] => check(exe, version, sig),
        _ => Err("usage: vaultrust-sign generate <key file> | sign <exe> <version> <out> | verify <exe> <version> <sig>".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn version(s: &str) -> Result<Version, String> {
    Version::parse(s).ok_or_else(|| format!("not a version: {s}"))
}

fn generate(key_file: &str) -> Result<(), String> {
    if std::path::Path::new(key_file).exists() {
        return Err(format!(
            "{key_file} already exists; not overwriting a signing key"
        ));
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
    if let Some(dir) = std::path::Path::new(key_file).parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(key_file, hex_encode(&seed)).map_err(|e| e.to_string())?;
    let pk: &[u8] = kp.pk.as_ref();
    let list: Vec<String> = pk.iter().map(|b| format!("0x{b:02x}")).collect();
    println!("Signing key written to {key_file} (keep it secret, back it up).");
    println!("Public key for src/update.rs:\n[{}]", list.join(", "));
    Ok(())
}

fn sign(exe: &str, version_text: &str, out: &str) -> Result<(), String> {
    let v = version(version_text)?;
    let seed_hex = std::env::var("VAULTRUST_SIGNING_KEY")
        .map_err(|_| "set VAULTRUST_SIGNING_KEY to the signing key".to_string())?;
    let seed: [u8; 32] = hex_decode(seed_hex.trim())
        .and_then(|b| b.try_into().ok())
        .ok_or("VAULTRUST_SIGNING_KEY is not a 64-character hex key")?;
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
    if *kp.pk != PUBLIC_KEY {
        return Err("this key does not match the public key built into VaultRust".into());
    }
    let bytes = std::fs::read(exe).map_err(|e| format!("{exe}: {e}"))?;
    let sig = kp.sk.sign(signed_message(v, &bytes), None);
    let text = hex_encode(sig.as_ref());
    verify(v, &bytes, text.as_bytes(), &PUBLIC_KEY).map_err(|e| e.to_string())?;
    std::fs::write(out, text).map_err(|e| format!("{out}: {e}"))?;
    println!("Signed {exe} as version {v} -> {out}");
    Ok(())
}

fn check(exe: &str, version_text: &str, sig: &str) -> Result<(), String> {
    let v = version(version_text)?;
    let bytes = std::fs::read(exe).map_err(|e| format!("{exe}: {e}"))?;
    let sig = std::fs::read(sig).map_err(|e| format!("{sig}: {e}"))?;
    verify(v, &bytes, &sig, &PUBLIC_KEY).map_err(|e| e.to_string())?;
    println!("Signature OK for version {v}");
    Ok(())
}
