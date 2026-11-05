//! Password strength estimation and vault health checks (weak, reused and
//! old passwords). Runs entirely in memory on the decrypted vault.
//!
//! The strength estimate is a heuristic: character-pool entropy with
//! penalties for repetition, sequences, keyboard walks, common passwords and
//! dictionary words. It is deliberately conservative but it is *not* a
//! guarantee of resistance to a determined attacker.

use std::collections::HashMap;

use crate::generator::wordlist;
use crate::model::{EntryKind, VaultData, EXPIRY_WARNING_DAYS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    VeryWeak,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

impl Strength {
    pub fn label(self) -> &'static str {
        match self {
            Strength::VeryWeak => "Very weak",
            Strength::Weak => "Weak",
            Strength::Fair => "Fair",
            Strength::Strong => "Strong",
            Strength::VeryStrong => "Very strong",
        }
    }

    pub fn is_weak(self) -> bool {
        self <= Strength::Weak
    }

    /// 0.0..=1.0, for meters.
    pub fn fraction(self) -> f32 {
        match self {
            Strength::VeryWeak => 0.1,
            Strength::Weak => 0.3,
            Strength::Fair => 0.55,
            Strength::Strong => 0.8,
            Strength::VeryStrong => 1.0,
        }
    }

    fn from_bits(bits: f64) -> Strength {
        match bits {
            b if b < 28.0 => Strength::VeryWeak,
            b if b < 40.0 => Strength::Weak,
            b if b < 60.0 => Strength::Fair,
            b if b < 80.0 => Strength::Strong,
            _ => Strength::VeryStrong,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StrengthReport {
    pub bits: f64,
    pub strength: Strength,
    pub warnings: Vec<&'static str>,
}

const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "passw0rd",
    "p@ssw0rd",
    "p@ssword",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "12345",
    "1234",
    "111111",
    "000000",
    "123123",
    "654321",
    "666666",
    "121212",
    "qwerty",
    "qwertyuiop",
    "qwerty123",
    "azerty",
    "asdfgh",
    "asdf",
    "zxcvbn",
    "1q2w3e4r",
    "1qaz2wsx",
    "qazwsx",
    "abc123",
    "abcdef",
    "letmein",
    "iloveyou",
    "admin",
    "administrator",
    "welcome",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "basketball",
    "soccer",
    "hockey",
    "master",
    "sunshine",
    "princess",
    "shadow",
    "superman",
    "batman",
    "trustno1",
    "login",
    "starwars",
    "hello",
    "freedom",
    "whatever",
    "michael",
    "charlie",
    "jordan",
    "hunter",
    "hunter2",
    "ranger",
    "buster",
    "harley",
    "andrew",
    "tigger",
    "killer",
    "jessica",
    "pepper",
    "daniel",
    "access",
    "computer",
    "secret",
    "summer",
    "winter",
    "spring",
    "autumn",
    "flower",
    "cookie",
    "chocolate",
    "pokemon",
    "minecraft",
    "fortnite",
    "google",
    "facebook",
    "changeme",
    "default",
    "guest",
    "root",
    "toor",
    "test",
    "testing",
    "test123",
    "pass",
    "pass123",
    "letmein1",
    "mustang",
    "maggie",
    "ginger",
    "joshua",
    "matrix",
    "biteme",
    "banana",
    "orange",
    "purple",
    "silver",
    "golden",
    "lovely",
    "loveme",
    "angel",
    "family",
    "friends",
    "money",
    "internet",
    "samsung",
    "apple",
    "windows",
    "linux",
    "ubuntu",
    "oracle",
    "mysql",
    "postgres",
    "wifi",
    "router",
    "zaq12wsx",
    "princess1",
    "password1",
    "password123",
    "qwerty1",
    "abcd1234",
];

const KEYBOARD_ROWS: &[&str] = &[
    "`1234567890-=",
    "qwertyuiop[]",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
];

fn pool_size(password: &str) -> f64 {
    let (mut lower, mut upper, mut digit, mut symbol, mut other) =
        (false, false, false, false, false);
    for c in password.chars() {
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if c.is_ascii() {
            symbol = true;
        } else {
            other = true;
        }
    }
    let mut n = 0.0;
    if lower {
        n += 26.0;
    }
    if upper {
        n += 26.0;
    }
    if digit {
        n += 10.0;
    }
    if symbol {
        n += 33.0;
    }
    if other {
        n += 100.0;
    }
    n
}

/// Undo common character substitutions ("p@ssw0rd" -> "password").
fn unleet(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '@' | '4' => 'a',
            '3' => 'e',
            '1' | '!' | '|' => 'i',
            '0' => 'o',
            '$' | '5' => 's',
            '7' => 't',
            _ => c,
        })
        .collect()
}

/// Mark characters covered by dictionary / common-password / keyboard
/// substrings of at least four characters.
fn mark_patterns(lower: &[char], covered: &mut [bool], warnings: &mut Vec<&'static str>) {
    let s: String = lower.iter().collect();
    let unleeted: Vec<char> = unleet(&s).chars().collect();
    let n = lower.len();
    let mut dict_hit = false;
    let mut common_hit = false;
    let mut keyboard_hit = false;
    for start in 0..n {
        for end in (start + 4..=n).rev() {
            if covered[start..end].iter().all(|c| *c) {
                break;
            }
            let sub: String = lower[start..end].iter().collect();
            let sub_u: String = unleeted[start..end].iter().collect();
            let is_common = COMMON_PASSWORDS.contains(&sub.as_str())
                || COMMON_PASSWORDS.contains(&sub_u.as_str());
            let is_word = end - start >= 4
                && (wordlist().binary_search(&sub.as_str()).is_ok()
                    || wordlist().binary_search(&sub_u.as_str()).is_ok());
            let is_keyboard = KEYBOARD_ROWS.iter().any(|row| {
                row.contains(sub.as_str())
                    || row.chars().rev().collect::<String>().contains(sub.as_str())
            });
            if is_common || is_word || is_keyboard {
                common_hit |= is_common;
                dict_hit |= is_word && !is_common;
                keyboard_hit |= is_keyboard && !is_common;
                for c in &mut covered[start..end] {
                    *c = true;
                }
                break;
            }
        }
    }
    if common_hit {
        warnings.push("Contains a commonly used password");
    }
    if dict_hit {
        warnings.push("Contains dictionary words");
    }
    if keyboard_hit {
        warnings.push("Contains a keyboard pattern");
    }
}

pub fn estimate_strength(password: &str) -> StrengthReport {
    let chars: Vec<char> = password.chars().collect();
    let n = chars.len();
    let mut warnings = Vec::new();
    if n == 0 {
        return StrengthReport {
            bits: 0.0,
            strength: Strength::VeryWeak,
            warnings: vec!["Empty password"],
        };
    }
    let lower: Vec<char> = chars.iter().flat_map(|c| c.to_lowercase()).collect();
    let whole: String = lower.iter().collect();
    let stripped = whole.trim_end_matches(|c: char| c.is_ascii_digit() || "!?.".contains(c));
    if COMMON_PASSWORDS.contains(&whole.as_str())
        || COMMON_PASSWORDS.contains(&stripped)
        || COMMON_PASSWORDS.contains(&unleet(stripped).as_str())
    {
        return StrengthReport {
            bits: 8.0,
            strength: Strength::VeryWeak,
            warnings: vec!["This is one of the most common passwords"],
        };
    }

    let per_char = pool_size(password).max(2.0).log2();
    let mut covered = vec![false; lower.len()];
    if lower.len() == n {
        mark_patterns(&lower, &mut covered, &mut warnings);
    }

    let mut bits = 0.0;
    let mut repeats = false;
    let mut sequence = false;
    let mut in_pattern = false;
    for i in 0..n {
        if covered.get(i).copied().unwrap_or(false) {
            // A dictionary word / pattern counts as ~one guess among ~2^11.
            if !in_pattern {
                bits += 11.0;
                in_pattern = true;
            }
            continue;
        }
        in_pattern = false;
        if i > 0 {
            let (a, b) = (chars[i - 1] as i64, chars[i] as i64);
            if a == b {
                repeats = true;
                bits += 0.5;
                continue;
            }
            if (a - b).abs() == 1 && chars[i].is_ascii_alphanumeric() {
                sequence = true;
                bits += 1.0;
                continue;
            }
        }
        bits += per_char;
    }
    if repeats {
        warnings.push("Contains repeated characters");
    }
    if sequence {
        warnings.push("Contains sequences like abc or 123");
    }
    if chars.iter().all(|c| c.is_ascii_digit()) {
        warnings.push("Only digits");
    }
    if n < 12 {
        warnings.push("Shorter than 12 characters");
    }
    let mut strength = Strength::from_bits(bits);
    if n < 8 {
        strength = strength.min(Strength::Weak);
    }
    StrengthReport {
        bits,
        strength,
        warnings,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRef {
    pub entry_id: u64,
    pub field_index: usize,
}

#[derive(Debug, Clone)]
pub struct WeakPassword {
    pub at: PasswordRef,
    pub strength: Strength,
}

#[derive(Debug, Clone, Default)]
pub struct HealthReport {
    pub total_passwords: usize,
    /// Passwords rated fair (neither weak nor strong).
    pub fair: usize,
    pub weak: Vec<WeakPassword>,
    /// Groups of two or more locations sharing an identical password.
    pub reused: Vec<Vec<PasswordRef>>,
    /// Entries whose password has not changed for over a year.
    pub old: Vec<u64>,
    /// Entries past their expiry date (explicit, or a card's printed one),
    /// with that date, soonest first.
    pub expired: Vec<(u64, i64)>,
    /// Entries expiring within [`EXPIRY_WARNING_DAYS`], soonest first.
    pub expiring: Vec<(u64, i64)>,
    /// 0-100, from password strength and reuse only.
    pub score: u32,
}

impl HealthReport {
    pub fn reused_count(&self) -> usize {
        self.reused.iter().map(Vec::len).sum()
    }

    pub fn is_reused(&self, entry_id: u64) -> bool {
        self.reused.iter().flatten().any(|r| r.entry_id == entry_id)
    }

    /// The expiry date of an entry that is expired or expiring soon.
    pub fn expiry(&self, entry_id: u64) -> Option<i64> {
        self.expired
            .iter()
            .chain(&self.expiring)
            .find(|(id, _)| *id == entry_id)
            .map(|(_, at)| *at)
    }

    pub fn is_weak(&self, entry_id: u64) -> bool {
        self.weak.iter().any(|w| w.at.entry_id == entry_id)
    }

    /// Passwords rated strong or very strong.
    pub fn strong(&self) -> usize {
        self.total_passwords - self.weak.len() - self.fair
    }
}

const OLD_PASSWORD_SECS: i64 = 365 * 86_400;

pub fn analyze(data: &VaultData, now: i64) -> HealthReport {
    let mut report = HealthReport::default();
    let mut by_value: HashMap<&str, Vec<PasswordRef>> = HashMap::new();
    let mut flagged = 0usize;
    for entry in &data.entries {
        let mut has_password = false;
        for (i, field) in entry.fields.iter().enumerate() {
            if field.kind != crate::model::FieldKind::Password || field.value.is_empty() {
                continue;
            }
            has_password = true;
            report.total_passwords += 1;
            let at = PasswordRef {
                entry_id: entry.id,
                field_index: i,
            };
            let s = estimate_strength(&field.value).strength;
            if s.is_weak() {
                report.weak.push(WeakPassword {
                    at: at.clone(),
                    strength: s,
                });
            } else if s == Strength::Fair {
                report.fair += 1;
            }
            by_value.entry(field.value.as_str()).or_default().push(at);
        }
        if has_password
            && entry.kind != EntryKind::SecureNote
            && now - entry.password_changed > OLD_PASSWORD_SECS
        {
            report.old.push(entry.id);
        }
    }
    report.reused = by_value.into_values().filter(|v| v.len() > 1).collect();
    report.reused.sort_by_key(|g| std::cmp::Reverse(g.len()));

    for entry in &data.entries {
        if let Some(at) = entry.effective_expiry() {
            if at <= now {
                report.expired.push((entry.id, at));
            } else if at - now <= EXPIRY_WARNING_DAYS * 86_400 {
                report.expiring.push((entry.id, at));
            }
        }
    }
    report.expired.sort_by_key(|(_, at)| *at);
    report.expiring.sort_by_key(|(_, at)| *at);

    for entry in &data.entries {
        for (i, f) in entry.fields.iter().enumerate() {
            if f.kind != crate::model::FieldKind::Password || f.value.is_empty() {
                continue;
            }
            let at = PasswordRef {
                entry_id: entry.id,
                field_index: i,
            };
            if report.weak.iter().any(|w| w.at == at)
                || report.reused.iter().flatten().any(|r| *r == at)
            {
                flagged += 1;
            }
        }
    }
    report.score = if report.total_passwords == 0 {
        100
    } else {
        let good = report.total_passwords - flagged;
        let base = (good * 100 / report.total_passwords) as u32;
        base.saturating_sub((report.old.len() as u32).min(10))
    };
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Entry, EntryKind};

    #[test]
    fn expired_and_expiring_items_are_reported() {
        let now = 1_700_000_000;
        let mut v = VaultData::new("t");
        let mut past = Entry::new(EntryKind::ApiKey);
        past.expires = now - 10;
        let mut soon = Entry::new(EntryKind::Login);
        soon.expires = now + 3 * 86_400;
        let mut later = Entry::new(EntryKind::Login);
        later.expires = now + 60 * 86_400;
        let mut card = Entry::new(EntryKind::CreditCard);
        card.fields[2].value = "01/20".into();
        let ids = (past.id, soon.id, later.id, card.id);
        for e in [past, soon, later, card] {
            v.upsert(e);
        }
        let r = analyze(&v, now);
        let expired: Vec<u64> = r.expired.iter().map(|(id, _)| *id).collect();
        assert_eq!(expired, [ids.3, ids.0], "soonest first");
        assert_eq!(r.expiring.len(), 1);
        assert_eq!(r.expiring[0].0, ids.1);
        assert_eq!(r.expiry(ids.1), Some(now + 3 * 86_400));
        assert_eq!(r.expiry(ids.2), None);
    }

    #[test]
    fn common_passwords_are_very_weak() {
        for p in [
            "password",
            "Password1",
            "P@ssw0rd",
            "123456",
            "qwerty",
            "letmein!",
        ] {
            assert_eq!(estimate_strength(p).strength, Strength::VeryWeak, "{p}");
        }
    }

    #[test]
    fn patterns_are_penalised() {
        assert!(estimate_strength("aaaaaaaaaaaaaaaa").strength.is_weak());
        assert!(estimate_strength("abcdefghijklmnop").strength.is_weak());
        assert!(estimate_strength("qwertyuiopasdfgh").strength.is_weak());
        assert!(estimate_strength("Ab1!").strength.is_weak());
    }

    #[test]
    fn random_passwords_are_strong() {
        assert!(estimate_strength("x7#Kq9!vT2$mWz4pL8@r").strength >= Strength::Strong);
        let opts = crate::generator::GeneratorOptions::default();
        for _ in 0..50 {
            let p = crate::generator::generate_password(&opts).unwrap();
            assert!(
                estimate_strength(&p).strength >= Strength::Strong,
                "{}",
                p.as_str()
            );
        }
    }

    #[test]
    fn passphrases_are_reasonable() {
        let p = crate::generator::generate_passphrase(&Default::default());
        assert!(
            estimate_strength(&p).strength >= Strength::Fair,
            "{}",
            p.as_str()
        );
    }

    #[test]
    fn detects_reuse_weak_and_old() {
        let mut v = VaultData::new("t");
        let mk = |pw: &str, changed: i64| {
            let mut e = Entry::new(EntryKind::Login);
            e.fields[3].value = pw.into();
            e.password_changed = changed;
            e
        };
        let now = 2_000_000_000;
        v.entries.push(mk("Tr0ub4dor&3-horse-battery", now));
        v.entries.push(mk("Tr0ub4dor&3-horse-battery", now));
        v.entries.push(mk("password", now));
        v.entries
            .push(mk("x7#Kq9!vT2$mWz4pL8@r", now - 400 * 86_400));
        let r = analyze(&v, now);
        assert_eq!(r.total_passwords, 4);
        assert_eq!(r.reused.len(), 1);
        assert_eq!(r.reused[0].len(), 2);
        assert_eq!(r.weak.len(), 1);
        assert_eq!(r.weak[0].at.entry_id, v.entries[2].id);
        assert_eq!(r.old, vec![v.entries[3].id]);
        assert!(r.score < 100);
    }
}
