//! Interface language.
//!
//! Text is written in English in the source and looked up in a per-language
//! table at run time: [`tr`] for fixed text, [`trf!`] for text with values in
//! it. The English text is the key, so a missing translation falls back to
//! English rather than to nothing. Placeholders are `{}` (taken in order) or
//! `{name}` (the argument written as `name`), optionally with a precision
//! (`{bits:.0}`) or zero padding (`{:02}`); translations may reorder them.

use std::collections::HashMap;
use std::fmt::Display;
#[cfg(not(test))]
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

mod el;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    #[default]
    English,
    Greek,
}

impl Language {
    pub const ALL: [Language; 2] = [Language::English, Language::Greek];

    /// The language's name in that language (what a speaker looks for).
    pub fn native_name(self) -> &'static str {
        match self {
            Language::English => "English",
            Language::Greek => "Ελληνικά",
        }
    }

    /// Stored in the preferences file.
    pub fn key(self) -> &'static str {
        match self {
            Language::English => "en",
            Language::Greek => "el",
        }
    }

    pub fn from_key(key: &str) -> Option<Language> {
        Language::ALL.into_iter().find(|l| l.key() == key)
    }

    /// The Windows display language, if it is one VaultRust speaks.
    pub fn from_system() -> Option<Language> {
        Language::from_key(crate::os_protect::user_ui_language()?)
    }

    fn table(self) -> Option<&'static HashMap<&'static str, &'static str>> {
        match self {
            Language::English => None,
            Language::Greek => {
                static EL: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
                Some(EL.get_or_init(|| el::TABLE.iter().copied().collect()))
            }
        }
    }

    /// This language's text for `en`, if it has one.
    pub fn lookup(self, en: &str) -> Option<&'static str> {
        self.table()?.get(en).copied()
    }
}

#[cfg(not(test))]
static CURRENT: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
thread_local! {
    /// Tests run in parallel threads of one process, so each test thread
    /// gets its own language instead of sharing one.
    static TEST_LANGUAGE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

pub fn set_language(lang: Language) {
    #[cfg(test)]
    TEST_LANGUAGE.with(|l| l.set(lang as u8));
    #[cfg(not(test))]
    CURRENT.store(lang as u8, Ordering::Relaxed);
}

pub fn language() -> Language {
    #[cfg(test)]
    let n = TEST_LANGUAGE.with(|l| l.get());
    #[cfg(not(test))]
    let n = CURRENT.load(Ordering::Relaxed);
    match n {
        1 => Language::Greek,
        _ => Language::English,
    }
}

/// `en` in the current language (or `en` itself if it has no translation).
pub fn tr(en: &str) -> &str {
    language().lookup(en).unwrap_or(en)
}

/// Whether `text` is `en` in any language. For recognising labels that
/// VaultRust itself wrote into a vault (field names of new items are written
/// in the language in use at the time).
pub fn is_any(text: &str, en: &str) -> bool {
    text == en || Language::ALL.iter().any(|l| l.lookup(en) == Some(text))
}

/// Fill in the placeholders of `template` (already translated). Used by
/// [`trf!`]; `args` pairs each value with the source text of its argument.
pub fn format(template: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut next = 0;
    let mut rest = template;
    while let Some(open) = rest.find(['{', '}']) {
        out.push_str(&rest[..open]);
        let tail = &rest[open..];
        // "{{" and "}}" are literal braces, as in `format!`.
        if tail.starts_with("{{") || tail.starts_with("}}") {
            out.push(tail.as_bytes()[0] as char);
            rest = &tail[2..];
            continue;
        }
        let Some(close) = tail.find('}').filter(|_| tail.starts_with('{')) else {
            out.push(tail.as_bytes()[0] as char);
            rest = &tail[1..];
            continue;
        };
        let inner = &tail[1..close];
        let (name, spec) = inner.split_once(':').unwrap_or((inner, ""));
        let value = if name.is_empty() {
            let v = args.get(next).map(|(_, v)| *v);
            next += 1;
            v
        } else {
            args.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
        };
        match value {
            Some(v) => out.push_str(&apply_spec(v, spec)),
            None => out.push_str(&tail[..=close]),
        }
        rest = &tail[close + 1..];
    }
    out.push_str(rest);
    out
}

/// The subset of `format!` specs the interface uses: `.N` and `0N`.
fn apply_spec(v: &dyn Display, spec: &str) -> String {
    if let Some(p) = spec.strip_prefix('.').and_then(|p| p.parse::<usize>().ok()) {
        format!("{v:.p$}")
    } else if let Some(w) = spec.strip_prefix('0').and_then(|w| w.parse::<usize>().ok()) {
        format!("{v:0>w$}")
    } else {
        v.to_string()
    }
}

/// Translated text with values filled in:
/// `trf!("Backup failed: {e}", e)`, `trf!("{} items", list.len())`.
#[macro_export]
macro_rules! trf {
    ($s:literal $(, $arg:expr)* $(,)?) => {
        $crate::i18n::format(
            $crate::i18n::tr($s),
            &[$((stringify!($arg), &$arg as &dyn ::std::fmt::Display)),*],
        )
    };
}

/// "1 item" / "3 items": English singular and plural forms; the
/// translation of each form is looked up separately.
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format(tr(if n == 1 { one } else { many }), &[("n", &n)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        let e = "disk full";
        let n = 3;
        assert_eq!(
            format("Backup failed: {e}", &[("e", &e)]),
            "Backup failed: disk full"
        );
        assert_eq!(format("{} of {}", &[("a", &1), ("b", &2)]), "1 of 2");
        assert_eq!(format("{n} · {n}", &[("n", &n)]), "3 · 3");
        assert_eq!(format("{:.1} MB", &[("x", &2.25f64)]), "2.2 MB");
        assert_eq!(format("{}:{:02}", &[("m", &4), ("s", &7)]), "4:07");
        assert_eq!(format("{{literal}} {missing}", &[]), "{literal} {missing}");
        assert_eq!(format("unclosed { brace }", &[]), "unclosed { brace }");
        let bits = 71.6f64;
        assert_eq!(
            trf!("· {bits:.0} bits of entropy", bits),
            "· 72 bits of entropy"
        );
    }

    /// Every translation keeps the placeholders of its English text, so no
    /// value is lost or shows up as `{name}`.
    #[test]
    fn translations_keep_placeholders() {
        fn holes(s: &str) -> Vec<String> {
            let mut v: Vec<String> = s
                .split('{')
                .skip(1)
                .filter_map(|p| p.split_once('}').map(|(h, _)| h.to_string()))
                .collect();
            v.sort();
            v
        }
        let mut seen = std::collections::HashSet::new();
        for (en, el) in el::TABLE {
            assert!(seen.insert(*en), "duplicate Greek entry for {en:?}");
            assert_eq!(holes(en), holes(el), "placeholders differ for {en:?}");
            assert!(!el.trim().is_empty(), "empty translation for {en:?}");
        }
    }

    /// Every text passed to `t`, `trf!` or `plural` in the source has a
    /// Greek translation.
    #[test]
    fn every_interface_text_is_translated() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut missing = Vec::new();
        let mut stack = vec![dir];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if !name.ends_with(".rs")
                    || ["el.rs", "tests.rs", "i18n.rs"].contains(&name.as_str())
                {
                    continue;
                }
                let src = std::fs::read_to_string(&path).unwrap();
                for key in keys_in(&src) {
                    if Language::Greek.lookup(&key).is_none() {
                        missing.push(format!("{name}: {key:?}"));
                    }
                }
            }
        }
        missing.sort();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "{} texts without a Greek translation:\n{}",
            missing.len(),
            missing.join("\n")
        );
    }

    /// String literals that are the first argument of `tr(` or `trf!(`, and
    /// both forms passed to `plural(`.
    fn keys_in(src: &str) -> Vec<String> {
        let mut keys = Vec::new();
        for marker in ["tr(", "trf!("] {
            let mut rest = src;
            while let Some(i) = rest.find(marker) {
                let before = rest[..i].chars().next_back();
                rest = &rest[i + marker.len()..];
                if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    continue;
                }
                // rustfmt may put the text on the next line.
                let Some(text) = rest.trim_start().strip_prefix('"') else {
                    continue;
                };
                if let Some((s, _)) = literal(text) {
                    keys.push(s);
                }
            }
        }
        let mut rest = src;
        while let Some(i) = rest.find("plural(") {
            rest = &rest[i + 7..];
            let mut r = rest;
            for _ in 0..2 {
                let Some(q) = r.find('"') else { break };
                if r[..q].contains(')') {
                    break;
                }
                r = &r[q + 1..];
                let Some((s, used)) = literal(r) else { break };
                r = &r[used..];
                keys.push(s);
            }
        }
        keys.retain(|k| k.chars().any(char::is_alphabetic));
        keys
    }

    /// The text of a string literal starting at `s` (just after its opening
    /// quote), unescaped, and the bytes it took up including the closing
    /// quote. Handles `\"`, `\\`, `\n`, `\t` and line continuations.
    fn literal(s: &str) -> Option<(String, usize)> {
        let mut out = String::new();
        let mut chars = s.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => return Some((out, i + 1)),
                '\\' => match chars.next()?.1 {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    '\r' | '\n' => while chars.next_if(|(_, c)| c.is_whitespace()).is_some() {},
                    _ => return None,
                },
                c => out.push(c),
            }
        }
        None
    }
}
