//! Small, dependency-free decoders: Base32 (TOTP secrets), Base64 (KeePass
//! XML) and URL percent-decoding (`otpauth://` URIs).
//!
//! Every decoder writes into a [`Zeroizing`] buffer because the decoded bytes
//! are usually secrets.

use zeroize::Zeroizing;

/// Decode RFC 4648 Base32. Case-insensitive; spaces, dashes and `=` padding
/// are ignored. Returns `None` on any other character.
pub fn base32_decode(input: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8 + 1));
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for c in input.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            ' ' | '-' | '=' | '\t' => continue,
            _ => return None,
        };
        buffer = (buffer << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1u64 << bits) - 1;
        }
    }
    Some(out)
}

/// Decode standard Base64 (with or without padding). Whitespace is ignored.
pub fn base64_decode(input: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 3 / 4 + 3));
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut padding = false;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding = true;
                continue;
            }
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        if padding {
            // Data after padding is malformed.
            return None;
        }
        buffer = (buffer << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }
    Some(out)
}

/// Decode `%XX` escapes (and `+` as space in query strings).
pub fn percent_decode(input: &str, plus_is_space: bool) -> Zeroizing<String> {
    let bytes = input.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            b'+' if plus_is_space => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648_vectors() {
        for (enc, dec) in [
            ("", ""),
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("MZXW6YTB", "fooba"),
            ("MZXW6YTBOI======", "foobar"),
            ("mzxw 6ytb oi", "foobar"),
        ] {
            assert_eq!(
                base32_decode(enc).unwrap().as_slice(),
                dec.as_bytes(),
                "{enc}"
            );
        }
        assert!(base32_decode("MZ1W").is_none());
    }

    #[test]
    fn base64_vectors() {
        for (enc, dec) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
            ("Zm9v\nYmFy", "foobar"),
        ] {
            assert_eq!(
                base64_decode(enc).unwrap().as_slice(),
                dec.as_bytes(),
                "{enc}"
            );
        }
        assert!(base64_decode("Zm9v!").is_none());
        assert!(base64_decode("Zg==Zg").is_none());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b%3Ac", false).as_str(), "a b:c");
        assert_eq!(percent_decode("a+b", true).as_str(), "a b");
        assert_eq!(percent_decode("a+b", false).as_str(), "a+b");
        assert_eq!(percent_decode("100%", false).as_str(), "100%");
        assert_eq!(percent_decode("%zz%4", false).as_str(), "%zz%4");
    }
}
