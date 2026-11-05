//! Time-based one-time passwords (RFC 6238), computed entirely offline.
//!
//! A one-time-code field stores either a Base32 secret (`JBSWY3DPEHPK3PXP`)
//! or a full `otpauth://totp/...` URI as exported by most authenticator
//! apps. Only the current code is ever shown; the secret stays concealed.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

use crate::encoding::{base32_decode, percent_decode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed TOTP configuration. The secret is wiped on drop.
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    #[error("the one-time code secret is empty")]
    Empty,
    #[error("the one-time code secret is not valid Base32")]
    BadSecret,
    #[error("only time-based (TOTP) codes are supported")]
    NotTotp,
    #[error("unsupported one-time code settings")]
    BadParameter,
}

impl Totp {
    /// Parse a Base32 secret or an `otpauth://totp/` URI.
    pub fn parse(value: &str) -> Result<Totp, TotpError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(TotpError::Empty);
        }
        let lower_prefix: String = value.chars().take(10).collect::<String>().to_lowercase();
        if lower_prefix.starts_with("otpauth://") {
            return Self::parse_uri(value);
        }
        Self::from_base32(value, 6, 30, Algorithm::Sha1)
    }

    fn from_base32(
        secret: &str,
        digits: u32,
        period: u64,
        algorithm: Algorithm,
    ) -> Result<Totp, TotpError> {
        let secret = base32_decode(secret).ok_or(TotpError::BadSecret)?;
        if secret.is_empty() {
            return Err(TotpError::BadSecret);
        }
        if !(6..=10).contains(&digits) || !(1..=600).contains(&period) {
            return Err(TotpError::BadParameter);
        }
        Ok(Totp {
            secret,
            digits,
            period,
            algorithm,
        })
    }

    fn parse_uri(uri: &str) -> Result<Totp, TotpError> {
        let rest = &uri["otpauth://".len()..];
        let (kind, rest) = rest.split_once('/').ok_or(TotpError::NotTotp)?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(TotpError::NotTotp);
        }
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut secret = None;
        let mut digits = 6;
        let mut period = 30;
        let mut algorithm = Algorithm::Sha1;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v, true);
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(v),
                "digits" => digits = v.parse().map_err(|_| TotpError::BadParameter)?,
                "period" => period = v.parse().map_err(|_| TotpError::BadParameter)?,
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(TotpError::BadParameter),
                    }
                }
                _ => {}
            }
        }
        let secret = secret.ok_or(TotpError::Empty)?;
        Self::from_base32(&secret, digits, period, algorithm)
    }

    /// The code for a given unix time.
    pub fn code_at(&self, unix_time: i64) -> String {
        let counter = (unix_time.max(0) as u64) / self.period;
        let msg = counter.to_be_bytes();
        let digest: Zeroizing<Vec<u8>> = Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => mac::<Hmac<sha1::Sha1>>(&self.secret, &msg),
            Algorithm::Sha256 => mac::<Hmac<sha2::Sha256>>(&self.secret, &msg),
            Algorithm::Sha512 => mac::<Hmac<sha2::Sha512>>(&self.secret, &msg),
        });
        // RFC 4226 dynamic truncation.
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let bin = (u32::from(digest[offset] & 0x7f) << 24)
            | (u32::from(digest[offset + 1]) << 16)
            | (u32::from(digest[offset + 2]) << 8)
            | u32::from(digest[offset + 3]);
        let modulus = 10u64.pow(self.digits);
        format!(
            "{:0width$}",
            u64::from(bin) % modulus,
            width = self.digits as usize
        )
    }

    /// Seconds until the code at `unix_time` changes.
    pub fn remaining_at(&self, unix_time: i64) -> u64 {
        self.period - (unix_time.max(0) as u64) % self.period
    }
}

fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

/// The issuer (service name) and account name in an `otpauth://` link,
/// e.g. `otpauth://totp/GitHub:octocat?secret=…&issuer=GitHub` gives
/// `("GitHub", "octocat")`. Either may be empty. Not secret.
pub fn otpauth_labels(uri: &str) -> (String, String) {
    let uri = uri.trim();
    if !uri.to_ascii_lowercase().starts_with("otpauth://") {
        return (String::new(), String::new());
    }
    let rest = &uri["otpauth://".len()..];
    let Some((_, rest)) = rest.split_once('/') else {
        return (String::new(), String::new());
    };
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = crate::encoding::percent_decode(label, false);
    let (mut issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k.eq_ignore_ascii_case("issuer") {
                let v = crate::encoding::percent_decode(v, true);
                if !v.trim().is_empty() {
                    issuer = v.trim().to_string();
                }
            }
        }
    }
    (issuer, account)
}

/// Group a code for display: "123456" -> "123 456".
pub fn format_code(code: &str) -> String {
    let n = code.len();
    let split = match n {
        6 => 3,
        8 => 4,
        _ => return code.to_string(),
    };
    format!("{} {}", &code[..split], &code[split..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otpauth_labels_are_read() {
        assert_eq!(
            otpauth_labels("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"),
            ("GitHub".into(), "octocat".into())
        );
        assert_eq!(
            otpauth_labels("otpauth://totp/me%40mail.com?secret=X&issuer=Big%20Bank"),
            ("Big Bank".into(), "me@mail.com".into())
        );
        assert_eq!(
            otpauth_labels("otpauth://totp/ACME%20Co:john?secret=X"),
            ("ACME Co".into(), "john".into())
        );
        assert_eq!(
            otpauth_labels("JBSWY3DPEHPK3PXP"),
            (String::new(), String::new())
        );
    }

    // RFC 6238 appendix B: ASCII "12345678901234567890" (repeated to the
    // hash's block-friendly length for SHA-256 / SHA-512), 8 digits.
    const SHA1_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SHA256_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SHA512_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    #[test]
    fn rfc6238_vectors() {
        let cases: &[(i64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (t, sha1, sha256, sha512) in cases {
            for (key, alg, want) in [
                (SHA1_KEY, "SHA1", sha1),
                (SHA256_KEY, "SHA256", sha256),
                (SHA512_KEY, "SHA512", sha512),
            ] {
                let uri = format!("otpauth://totp/x?secret={key}&digits=8&algorithm={alg}");
                let totp = Totp::parse(&uri).unwrap();
                assert_eq!(&totp.code_at(*t), want, "{alg} at {t}");
            }
        }
    }

    #[test]
    fn plain_secret_defaults() {
        let t = Totp::parse(" jbsw y3dp ehpk 3pxp ").unwrap();
        assert_eq!(t.digits, 6);
        assert_eq!(t.period, 30);
        assert_eq!(t.code_at(0).len(), 6);
        assert_eq!(t.remaining_at(0), 30);
        assert_eq!(t.remaining_at(29), 1);
        assert_eq!(t.remaining_at(30), 30);
    }

    #[test]
    fn uri_parsing() {
        let t = Totp::parse(
            "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=60",
        )
        .unwrap();
        assert_eq!(t.period, 60);
        assert_eq!(
            Totp::parse("otpauth://hotp/x?secret=JBSWY3DP").unwrap_err(),
            TotpError::NotTotp
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?issuer=a").unwrap_err(),
            TotpError::Empty
        );
        assert_eq!(
            Totp::parse("not base32!").unwrap_err(),
            TotpError::BadSecret
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?secret=JBSWY3DP&digits=3").unwrap_err(),
            TotpError::BadParameter
        );
        assert_eq!(Totp::parse("").unwrap_err(), TotpError::Empty);
    }

    #[test]
    fn code_formatting() {
        assert_eq!(format_code("123456"), "123 456");
        assert_eq!(format_code("12345678"), "1234 5678");
        assert_eq!(format_code("1234567"), "1234567");
    }
}
