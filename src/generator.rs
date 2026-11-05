//! Password and passphrase generation using the OS CSPRNG with unbiased
//! (rejection-sampled) selection.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::random_below;

pub const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
pub const DIGITS: &str = "0123456789";
pub const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Characters that are easily confused with each other in many fonts.
pub const AMBIGUOUS: &str = "Il1|O0oB8S5Z2`'\"";

pub const MIN_LENGTH: u32 = 4;
pub const MAX_LENGTH: u32 = 256;
pub const MIN_WORDS: u32 = 3;
pub const MAX_WORDS: u32 = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorOptions {
    pub length: u32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    /// Extra characters added to the pool (or the whole pool, see below).
    pub custom_chars: String,
    /// Use only `custom_chars`, ignoring the class toggles.
    pub custom_only: bool,
    /// Guarantee at least one character from every enabled class.
    pub require_each_class: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        GeneratorOptions {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            custom_chars: String::new(),
            custom_only: false,
            require_each_class: true,
        }
    }
}

impl GeneratorOptions {
    pub fn sanitize(&mut self) {
        self.length = self.length.clamp(MIN_LENGTH, MAX_LENGTH);
    }

    /// The enabled character classes after applying exclusions. Each class
    /// is de-duplicated; classes may be empty if everything was excluded.
    fn classes(&self) -> Vec<Vec<char>> {
        let keep = |c: &char| !(self.exclude_ambiguous && AMBIGUOUS.contains(*c));
        let mut classes = Vec::new();
        if !self.custom_only {
            for (on, set) in [
                (self.uppercase, UPPER),
                (self.lowercase, LOWER),
                (self.digits, DIGITS),
                (self.symbols, SYMBOLS),
            ] {
                if on {
                    classes.push(set.chars().filter(keep).collect::<Vec<_>>());
                }
            }
        }
        let mut custom: Vec<char> = self
            .custom_chars
            .chars()
            .filter(|c| !c.is_control() && !c.is_whitespace())
            .filter(keep)
            .collect();
        custom.sort_unstable();
        custom.dedup();
        if !custom.is_empty() {
            classes.push(custom);
        }
        classes.retain(|c| !c.is_empty());
        classes
    }

    /// The full, de-duplicated character pool.
    pub fn pool(&self) -> Vec<char> {
        let mut pool: Vec<char> = self.classes().into_iter().flatten().collect();
        pool.sort_unstable();
        pool.dedup();
        pool
    }

    /// Entropy of a generated password in bits: `length * log2(pool size)`.
    /// The "require each class" rule removes a small fraction of the space;
    /// the estimate ignores that (the reduction is well under one bit for
    /// practical lengths).
    pub fn entropy_bits(&self) -> f64 {
        let n = self.pool().len();
        if n < 2 {
            return 0.0;
        }
        f64::from(self.length) * (n as f64).log2()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    EmptyPool,
    TooShortForClasses,
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenerateError::EmptyPool => f.write_str("select at least one character set"),
            GenerateError::TooShortForClasses => {
                f.write_str("the length is too short to include every selected character set")
            }
        }
    }
}

/// Generate a random password according to `opts`.
pub fn generate_password(opts: &GeneratorOptions) -> Result<Zeroizing<String>, GenerateError> {
    let mut opts = opts.clone();
    opts.sanitize();
    let classes = opts.classes();
    let pool = opts.pool();
    if pool.is_empty() {
        return Err(GenerateError::EmptyPool);
    }
    let len = opts.length as usize;
    if opts.require_each_class && classes.len() > len {
        return Err(GenerateError::TooShortForClasses);
    }
    loop {
        // Capacity covers the worst case of 4-byte chars, so the String never
        // reallocates and leaves un-wiped copies behind.
        let mut out = Zeroizing::new(String::with_capacity(len * 4));
        for _ in 0..len {
            out.push(pool[random_below(pool.len() as u32) as usize]);
        }
        // Rejection sampling keeps the output uniform over all passwords
        // that satisfy the class requirement.
        if !opts.require_each_class || classes.iter().all(|c| out.chars().any(|x| c.contains(&x))) {
            return Ok(out);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseOptions {
    pub words: u32,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        PassphraseOptions {
            words: 6,
            separator: "-".into(),
            capitalize: true,
            include_number: true,
        }
    }
}

impl PassphraseOptions {
    pub fn sanitize(&mut self) {
        self.words = self.words.clamp(MIN_WORDS, MAX_WORDS);
        if self.separator.chars().count() > 3 {
            self.separator = self.separator.chars().take(3).collect();
        }
    }

    /// Entropy in bits. Capitalization is deterministic and adds nothing;
    /// the number adds log2(10) for the digit plus log2(words) for its
    /// position.
    pub fn entropy_bits(&self) -> f64 {
        let w = f64::from(self.words.clamp(MIN_WORDS, MAX_WORDS));
        let mut bits = w * (wordlist().len() as f64).log2();
        if self.include_number {
            bits += 10f64.log2() + w.log2();
        }
        bits
    }
}

/// The embedded word list, de-duplicated and sorted.
pub fn wordlist() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| {
        let mut v: Vec<&'static str> = include_str!("wordlist.txt")
            .split_whitespace()
            .filter(|w| w.chars().all(|c| c.is_ascii_lowercase()))
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    })
}

pub fn generate_passphrase(opts: &PassphraseOptions) -> Zeroizing<String> {
    let mut opts = opts.clone();
    opts.sanitize();
    let list = wordlist();
    let n = opts.words as usize;
    let number_at = opts.include_number.then(|| random_below(n as u32) as usize);
    let mut out = Zeroizing::new(String::with_capacity(n * (12 + opts.separator.len()) + 2));
    for i in 0..n {
        if i > 0 {
            out.push_str(&opts.separator);
        }
        let word = list[random_below(list.len() as u32) as usize];
        if opts.capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.push(first.to_ascii_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(word);
        }
        if number_at == Some(i) {
            out.push(char::from(b'0' + random_below(10) as u8));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn length_and_charset_respected() {
        let opts = GeneratorOptions {
            length: 64,
            symbols: false,
            ..Default::default()
        };
        for _ in 0..200 {
            let p = generate_password(&opts).unwrap();
            assert_eq!(p.chars().count(), 64);
            assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn ambiguous_excluded() {
        let opts = GeneratorOptions {
            length: 200,
            exclude_ambiguous: true,
            ..Default::default()
        };
        for _ in 0..50 {
            let p = generate_password(&opts).unwrap();
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn custom_only() {
        let opts = GeneratorOptions {
            length: 30,
            custom_only: true,
            custom_chars: "ab c\tab".into(),
            ..Default::default()
        };
        let p = generate_password(&opts).unwrap();
        assert!(p.chars().all(|c| c == 'a' || c == 'b' || c == 'c'));
        assert_eq!(opts.pool(), vec!['a', 'b', 'c']);
    }

    #[test]
    fn errors() {
        let none = GeneratorOptions {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert_eq!(
            generate_password(&none).unwrap_err(),
            GenerateError::EmptyPool
        );
        let short = GeneratorOptions {
            custom_chars: "€".into(),
            length: 4,
            ..Default::default()
        };
        assert_eq!(
            generate_password(&short).unwrap_err(),
            GenerateError::TooShortForClasses
        );
    }

    #[test]
    fn passwords_are_unique() {
        let opts = GeneratorOptions::default();
        let set: HashSet<String> = (0..1000)
            .map(|_| generate_password(&opts).unwrap().to_string())
            .collect();
        assert_eq!(set.len(), 1000);
    }

    #[test]
    fn entropy() {
        let opts = GeneratorOptions {
            length: 10,
            uppercase: false,
            lowercase: false,
            symbols: false,
            ..Default::default()
        };
        assert!((opts.entropy_bits() - 10.0 * 10f64.log2()).abs() < 1e-9);
        let default = GeneratorOptions::default();
        assert!(default.entropy_bits() > 120.0);
    }

    #[test]
    fn wordlist_quality() {
        let list = wordlist();
        assert!(list.len() >= 1500, "word list has {} words", list.len());
        assert!(list.iter().all(|w| (2..=10).contains(&w.len())));
    }

    #[test]
    fn passphrase_shape() {
        let opts = PassphraseOptions {
            words: 5,
            separator: ".".into(),
            capitalize: false,
            include_number: false,
        };
        let p = generate_passphrase(&opts);
        let parts: Vec<&str> = p.split('.').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|w| wordlist().contains(w)));

        let with_num = generate_passphrase(&PassphraseOptions::default());
        assert_eq!(with_num.chars().filter(|c| c.is_ascii_digit()).count(), 1);
        assert!(PassphraseOptions::default().entropy_bits() > 60.0);
    }
}
