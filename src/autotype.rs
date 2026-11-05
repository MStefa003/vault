//! Auto-type: matching a foreign window to vault entries and building the
//! keystrokes to type into it. The typing itself (Win32 `SendInput`) lives in
//! [`crate::os_protect::auto_type`].
//!
//! Matching uses the target window's title (a browser shows the page title,
//! e.g. "Sign in to GitHub · GitHub — Mozilla Firefox"). Titles are chosen by
//! web pages, so a match is only a suggestion: the user always confirms which
//! item is typed.

use zeroize::Zeroizing;

use crate::model::{Entry, FieldKind};
use crate::os_protect::TypeStep;
use crate::totp::Totp;

/// What to type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sequence {
    /// Username, Tab, password, Enter (just password, Enter without a
    /// username).
    Login,
    /// Password, Enter.
    Password,
    /// Current one-time code, Enter.
    Code,
}

impl Sequence {
    pub fn describe(self) -> &'static str {
        match self {
            Sequence::Login => "username, Tab, password, Enter",
            Sequence::Password => "password, Enter",
            Sequence::Code => "one-time code, Enter",
        }
    }
}

/// "https://www.mail.example.com/login" -> "mail.example.com".
pub fn url_host(url: &str) -> String {
    let rest = url
        .trim()
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url.trim());
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    host.trim_start_matches("www.").to_lowercase()
}

/// The registrable name of a host: "mail.google.com" -> "google",
/// "shop.example.co.uk" -> "example".
pub fn site_name(host: &str) -> &str {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    match labels.len() {
        0 => "",
        1 => labels[0],
        n => {
            let (sld, tld) = (labels[n - 2], labels[n - 1]);
            // Two-letter country code under a short second level (co.uk,
            // com.au): the name is one label further left.
            if n >= 3 && tld.len() == 2 && sld.len() <= 3 {
                labels[n - 3]
            } else {
                sld
            }
        }
    }
}

/// `needle` appears in `hay` as a whole word (both lower-case).
fn contains_word(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    hay.match_indices(needle).any(|(i, _)| {
        let before = hay[..i].chars().next_back();
        let after = hay[i + needle.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

/// How well an entry matches a window title, or `None` if it doesn't.
pub fn match_score(e: &Entry, window_title: &str) -> Option<i32> {
    let title = window_title.to_lowercase();
    let mut best: Option<i32> = None;
    let mut consider = |s: i32| best = Some(best.map_or(s, |b| b.max(s)));
    for f in e.fields.iter().filter(|f| f.kind == FieldKind::Url) {
        let host = url_host(&f.value);
        if host.is_empty() {
            continue;
        }
        if title.contains(&host) {
            consider(100);
        }
        let name = site_name(&host);
        if name.len() >= 3 && contains_word(&title, name) {
            consider(80);
        }
    }
    let entry_title = e.title.trim().to_lowercase();
    if entry_title.chars().count() >= 3 && contains_word(&title, &entry_title) {
        consider(60);
    }
    best
}

/// The default login sequence, in the syntax of [`parse_sequence`].
pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
/// Longest single `{DELAY n}`, in milliseconds.
pub const MAX_DELAY_MS: u32 = 10_000;

/// One element of a custom auto-type sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Text(String),
    Username,
    Password,
    Totp,
    Title,
    Url,
    /// A field by its label (`{FIELD:PIN}`).
    Field(String),
    Tab,
    Enter,
    Space,
    Delay(u32),
}

/// Parse a KeePass-style sequence: literal text plus `{USERNAME}`,
/// `{PASSWORD}`, `{TOTP}`, `{TITLE}`, `{URL}`, `{FIELD:label}`, `{TAB}`,
/// `{ENTER}`, `{SPACE}` and `{DELAY ms}`. `{{}` and `{}}` type literal braces.
/// Placeholder names are case-insensitive.
pub fn parse_sequence(seq: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut rest = seq;
    while let Some(open) = rest.find('{') {
        text.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        // `{{}` and `{}}` are escaped braces.
        if let Some(r) = after.strip_prefix("{}") {
            text.push('{');
            rest = r;
            continue;
        }
        if let Some(r) = after.strip_prefix("}}") {
            text.push('}');
            rest = r;
            continue;
        }
        let close = after
            .find('}')
            .ok_or_else(|| "a { has no matching }".to_string())?;
        let inner = after[..close].trim();
        rest = &after[close + 1..];
        let upper = inner.to_ascii_uppercase();
        let token = match upper.as_str() {
            "USERNAME" | "USER" => Token::Username,
            "PASSWORD" => Token::Password,
            "TOTP" | "OTP" => Token::Totp,
            "TITLE" => Token::Title,
            "URL" => Token::Url,
            "TAB" => Token::Tab,
            "ENTER" => Token::Enter,
            "SPACE" => Token::Space,
            _ if upper.starts_with("DELAY") => {
                let ms: u32 = inner[5..]
                    .trim_start_matches([' ', '='])
                    .trim()
                    .parse()
                    .map_err(|_| format!("{{{inner}}} needs a number of milliseconds"))?;
                if ms > MAX_DELAY_MS {
                    return Err(format!("{{{inner}}} is longer than 10 seconds"));
                }
                Token::Delay(ms)
            }
            _ if upper.starts_with("FIELD:") || upper.starts_with("S:") => {
                let label = inner.split_once(':').map(|(_, l)| l.trim()).unwrap_or("");
                if label.is_empty() {
                    return Err("{FIELD:…} needs a field label".into());
                }
                Token::Field(label.to_string())
            }
            _ => return Err(format!("unknown placeholder {{{inner}}}")),
        };
        if !text.is_empty() {
            out.push(Token::Text(std::mem::take(&mut text)));
        }
        out.push(token);
    }
    text.push_str(rest);
    if !text.is_empty() {
        out.push(Token::Text(text));
    }
    Ok(out)
}

/// Turn a custom sequence into keystrokes for `e`.
fn resolve(e: &Entry, tokens: &[Token], now: i64) -> Result<Vec<TypeStep>, String> {
    let text = |s: &str| TypeStep::Text(Zeroizing::new(s.to_string()));
    let mut steps = Vec::new();
    for t in tokens {
        steps.push(match t {
            Token::Text(s) => text(s),
            Token::Username => text(
                e.first_of(FieldKind::Username)
                    .or_else(|| e.first_of(FieldKind::Email))
                    .ok_or("This item has no username")?,
            ),
            Token::Password => text(
                e.first_of(FieldKind::Password)
                    .ok_or("This item has no password")?,
            ),
            Token::Totp => text(
                &e.totp_secret()
                    .and_then(|s| Totp::parse(s).ok())
                    .ok_or("This item has no one-time code")?
                    .code_at(now),
            ),
            Token::Title => text(&e.title),
            Token::Url => text(
                e.first_of(FieldKind::Url)
                    .ok_or("This item has no website")?,
            ),
            Token::Field(label) => text(
                e.fields
                    .iter()
                    .find(|f| f.label.eq_ignore_ascii_case(label) && !f.value.is_empty())
                    .map(|f| f.value.as_str())
                    .ok_or_else(|| format!("This item has no “{label}” field"))?,
            ),
            Token::Tab => TypeStep::Tab,
            Token::Enter => TypeStep::Enter,
            Token::Space => text(" "),
            Token::Delay(ms) => TypeStep::Delay(*ms),
        });
    }
    Ok(steps)
}

/// The keystrokes for `seq`, or a reason the entry can't provide them. An
/// item's own auto-type sequence replaces the default login sequence.
pub fn build(e: &Entry, seq: Sequence, now: i64) -> Result<Vec<TypeStep>, String> {
    if seq == Sequence::Login && !e.auto_type.trim().is_empty() {
        let tokens = parse_sequence(&e.auto_type)
            .map_err(|err| format!("This item's auto-type sequence is invalid: {err}"))?;
        return resolve(e, &tokens, now);
    }
    let text = |s: &str| TypeStep::Text(Zeroizing::new(s.to_string()));
    match seq {
        Sequence::Login | Sequence::Password => {
            let pw = e
                .first_of(FieldKind::Password)
                .ok_or("This item has no password")?;
            let mut steps = Vec::new();
            if seq == Sequence::Login {
                if let Some(user) = e
                    .first_of(FieldKind::Username)
                    .or_else(|| e.first_of(FieldKind::Email))
                {
                    steps.push(text(user));
                    steps.push(TypeStep::Tab);
                }
            }
            steps.push(text(pw));
            steps.push(TypeStep::Enter);
            Ok(steps)
        }
        Sequence::Code => {
            let totp = e
                .totp_secret()
                .and_then(|s| Totp::parse(s).ok())
                .ok_or("This item has no one-time code")?;
            Ok(vec![text(&totp.code_at(now)), TypeStep::Enter])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EntryKind, Field};

    fn login(title: &str, url: &str, user: &str, pw: &str) -> Entry {
        let mut e = Entry::new(EntryKind::Login);
        e.title = title.into();
        e.fields[0].value = url.into();
        e.fields[1].value = user.into();
        e.fields[3].value = pw.into();
        e
    }

    #[test]
    fn hosts_and_site_names() {
        assert_eq!(url_host("https://www.GitHub.com/login?x=1"), "github.com");
        assert_eq!(
            url_host("http://user@mail.example.com:8443/"),
            "mail.example.com"
        );
        assert_eq!(url_host("example.org"), "example.org");
        assert_eq!(site_name("mail.google.com"), "google");
        assert_eq!(site_name("shop.example.co.uk"), "example");
        assert_eq!(site_name("localhost"), "localhost");
    }

    #[test]
    fn matches_browser_window_titles() {
        let gh = login("GitHub", "https://github.com/login", "alice", "pw");
        let bank = login("My Bank", "https://online.mybank.co.uk", "a", "pw");
        let t = "Sign in to GitHub · GitHub — Mozilla Firefox";
        assert!(match_score(&gh, t).is_some());
        assert!(match_score(&bank, t).is_none());
        assert_eq!(
            match_score(&bank, "MyBank – Online banking - Google Chrome"),
            Some(80)
        );
        assert_eq!(
            match_score(&gh, "github.com/settings - Microsoft Edge"),
            Some(100)
        );
        // Whole words only: "git" must not match "digital".
        let git = login("Git", "https://git.example", "a", "pw");
        assert!(match_score(&git, "Digital wallet").is_none());
    }

    #[test]
    fn builds_sequences() {
        let e = login("x", "", "alice", "s3cret");
        let steps = build(&e, Sequence::Login, 0).unwrap();
        assert_eq!(steps.len(), 4);
        assert!(matches!(&steps[0], TypeStep::Text(t) if t.as_str() == "alice"));
        assert!(matches!(steps[1], TypeStep::Tab));
        assert!(matches!(&steps[2], TypeStep::Text(t) if t.as_str() == "s3cret"));
        assert!(matches!(steps[3], TypeStep::Enter));
        assert_eq!(build(&e, Sequence::Password, 0).unwrap().len(), 2);

        let no_user = login("x", "", "", "pw");
        assert_eq!(build(&no_user, Sequence::Login, 0).unwrap().len(), 2);
        let empty = login("x", "", "", "");
        assert!(build(&empty, Sequence::Login, 0).is_err());
        assert!(build(&e, Sequence::Code, 0).is_err());

        let mut otp = e.clone();
        otp.fields.push(Field::with_value(
            "2FA",
            FieldKind::Totp,
            "JBSWY3DPEHPK3PXP",
        ));
        let code = build(&otp, Sequence::Code, 59).unwrap();
        assert!(matches!(&code[0], TypeStep::Text(t) if t.len() == 6));
    }

    #[test]
    fn parses_custom_sequences() {
        use Token::*;
        assert_eq!(
            parse_sequence(DEFAULT_SEQUENCE).unwrap(),
            [Username, Tab, Password, Enter]
        );
        assert_eq!(
            parse_sequence("{user}{enter}{DELAY 1500}{password}{Enter}").unwrap(),
            [Username, Enter, Delay(1500), Password, Enter]
        );
        assert_eq!(
            parse_sequence("id={FIELD:Customer no}{TAB}{{}x{}}").unwrap(),
            [
                Text("id=".into()),
                Field("Customer no".into()),
                Tab,
                Text("{x}".into())
            ]
        );
        assert!(parse_sequence("{NOPE}").unwrap_err().contains("unknown"));
        assert!(parse_sequence("{DELAY abc}").is_err());
        assert!(parse_sequence("{DELAY 99999}").is_err());
        assert!(parse_sequence("{USERNAME").is_err());
        assert!(parse_sequence("{FIELD:}").is_err());
    }

    #[test]
    fn custom_sequence_replaces_the_default() {
        let mut e = login("Bank", "https://bank.example", "alice", "pw");
        e.fields
            .push(Field::with_value("PIN", FieldKind::Secret, "1234"));
        e.auto_type = "{USERNAME}{ENTER}{DELAY 800}{FIELD:pin}{TAB}{PASSWORD}{ENTER}".into();
        let steps = build(&e, Sequence::Login, 0).unwrap();
        let kinds: Vec<String> = steps
            .iter()
            .map(|s| match s {
                TypeStep::Text(t) => t.to_string(),
                TypeStep::Tab => "TAB".into(),
                TypeStep::Enter => "ENTER".into(),
                TypeStep::Delay(ms) => format!("DELAY{ms}"),
            })
            .collect();
        assert_eq!(
            kinds,
            ["alice", "ENTER", "DELAY800", "1234", "TAB", "pw", "ENTER"]
        );
        // Password-only and code sequences ignore the custom sequence.
        assert_eq!(build(&e, Sequence::Password, 0).unwrap().len(), 2);
        e.auto_type = "{FIELD:Missing}".into();
        assert!(build(&e, Sequence::Login, 0)
            .unwrap_err()
            .contains("Missing"));
        e.auto_type = "{BROKEN".into();
        assert!(build(&e, Sequence::Login, 0)
            .unwrap_err()
            .contains("invalid"));
    }
}
