//! User-initiated import and export.
//!
//! * Imports (CSV from common password managers, Bitwarden unencrypted JSON,
//!   generic JSON arrays) are parsed entirely in memory. Nothing derived from
//!   the plaintext source file is ever written to disk except inside the
//!   encrypted vault.
//! * The only plaintext export is an explicit CSV export, which the UI gates
//!   behind a prominent warning and a typed confirmation.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::model::{Entry, EntryKind, Field, FieldKind, VaultData};

/// Refuse to load import files larger than this (64 MiB).
pub const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("could not read the file: {0}")]
    Io(#[from] std::io::Error),
    #[error("the file is larger than 64 MiB")]
    TooLarge,
    #[error("the CSV file could not be parsed: {0}")]
    Csv(String),
    #[error("the JSON file could not be parsed: {0}")]
    Json(String),
    #[error("unrecognised format: no title, URL, username or password column was found")]
    Unrecognised,
    #[error("this is an encrypted export; please export unencrypted JSON from the other application, import it, then delete it")]
    EncryptedExport,
    #[error("this is a KeePass database; it needs its password to import")]
    KdbxNeedsPassword,
    #[error("{0}")]
    Kdbx(#[from] crate::kdbx::KdbxError),
}

#[derive(Debug, Default)]
pub struct ImportResult {
    pub entries: Vec<Entry>,
    pub skipped: usize,
    pub format: &'static str,
}

/// Read an import file into a zeroizing buffer.
pub fn read_import_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    if len > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(len as usize + 1));
    Read::by_ref(&mut f)
        .take(MAX_IMPORT_BYTES + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    Ok(buf)
}

/// Import based on the file extension, falling back to content sniffing.
pub fn import_auto(path: &Path, bytes: &[u8]) -> Result<ImportResult, ImportError> {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if crate::kdbx::is_kdbx(bytes) {
        return Err(ImportError::KdbxNeedsPassword);
    }
    let first = bytes
        .iter()
        .copied()
        .find(|b| !(b.is_ascii_whitespace() || *b == 0xEF || *b == 0xBB || *b == 0xBF));
    if ext == "json" || matches!(first, Some(b'{') | Some(b'[')) {
        import_json(bytes)
    } else {
        import_csv(bytes)
    }
}

#[derive(Default)]
struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    email: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    kind: Option<usize>,
    extra: Option<usize>,
    tags: Option<usize>,
}

fn classify_header(h: &str) -> Option<&'static str> {
    let h = h.trim().trim_start_matches('\u{feff}').to_ascii_lowercase();
    let h = h.as_str();
    Some(match h {
        "name" | "title" | "account" | "account name" | "item name" | "entry" | "site name" => {
            "title"
        }
        "url" | "login_uri" | "website" | "web site" | "uri" | "login url" | "web address"
        | "site" => "url",
        "username" | "login_username" | "user name" | "login" | "user" | "login name"
        | "user id" => "username",
        "email" | "e-mail" | "email address" => "email",
        "password" | "login_password" | "pass" => "password",
        "notes" | "note" | "extra" | "comments" | "comment" => "notes",
        "totp" | "login_totp" | "otpauth" | "one-time password" | "otp" => "totp",
        "type" | "kind" => "kind",
        "extra_fields" => "extra",
        "tags" | "tag" | "folder" | "grouping" | "group" => "tags",
        _ => return None,
    })
}

pub fn import_csv(bytes: &[u8]) -> Result<ImportResult, ImportError> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::None)
        .from_reader(bytes);
    let headers = rdr
        .headers()
        .map_err(|e| ImportError::Csv(e.to_string()))?
        .clone();
    let mut cols = Columns::default();
    for (i, h) in headers.iter().enumerate() {
        let slot = match classify_header(h) {
            Some("title") => &mut cols.title,
            Some("url") => &mut cols.url,
            Some("username") => &mut cols.username,
            Some("email") => &mut cols.email,
            Some("password") => &mut cols.password,
            Some("notes") => &mut cols.notes,
            Some("totp") => &mut cols.totp,
            Some("kind") => &mut cols.kind,
            Some("extra") => &mut cols.extra,
            Some("tags") => &mut cols.tags,
            _ => continue,
        };
        slot.get_or_insert(i);
    }
    if cols.title.is_none()
        && cols.url.is_none()
        && cols.username.is_none()
        && cols.password.is_none()
    {
        return Err(ImportError::Unrecognised);
    }

    let mut result = ImportResult {
        format: "CSV",
        ..Default::default()
    };
    for rec in rdr.records() {
        let rec = match rec {
            Ok(r) => r,
            Err(_) => {
                result.skipped += 1;
                continue;
            }
        };
        let get = |c: Option<usize>| c.and_then(|i| rec.get(i)).unwrap_or("").trim().to_string();
        let item = FlatItem {
            kind: get(cols.kind),
            title: get(cols.title),
            url: get(cols.url),
            username: get(cols.username),
            email: get(cols.email),
            password: c_raw(&rec, cols.password),
            notes: c_raw(&rec, cols.notes),
            totp: get(cols.totp),
            extra: c_raw(&rec, cols.extra),
            tags: get(cols.tags),
        };
        match item.into_entry() {
            Some(e) => result.entries.push(e),
            None => result.skipped += 1,
        }
    }
    Ok(result)
}

/// Raw (untrimmed) cell: passwords may legitimately start or end with spaces.
fn c_raw(rec: &csv::StringRecord, col: Option<usize>) -> String {
    col.and_then(|i| rec.get(i)).unwrap_or("").to_string()
}

struct FlatItem {
    kind: String,
    title: String,
    url: String,
    username: String,
    email: String,
    password: String,
    notes: String,
    totp: String,
    extra: String,
    tags: String,
}

impl Drop for FlatItem {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.notes.zeroize();
        self.totp.zeroize();
        self.extra.zeroize();
        self.username.zeroize();
        self.email.zeroize();
    }
}

impl FlatItem {
    fn into_entry(self) -> Option<Entry> {
        if self.title.is_empty()
            && self.url.is_empty()
            && self.username.is_empty()
            && self.password.is_empty()
            && self.notes.trim().is_empty()
        {
            return None;
        }
        let k = self.kind.to_ascii_lowercase();
        let kind = EntryKind::ALL
            .into_iter()
            .find(|e| e.label().eq_ignore_ascii_case(&k))
            .unwrap_or(match k.as_str() {
                "note" | "securenote" | "secure note" => EntryKind::SecureNote,
                _ if self.password.is_empty()
                    && self.username.is_empty()
                    && self.url.is_empty()
                    && !self.notes.trim().is_empty() =>
                {
                    EntryKind::SecureNote
                }
                _ => EntryKind::Login,
            });
        let mut e = Entry::new(kind);
        e.title = if !self.title.is_empty() {
            self.title.clone()
        } else if !self.url.is_empty() {
            host_of(&self.url)
        } else if !self.username.is_empty() {
            self.username.clone()
        } else {
            "Imported item".into()
        };
        e.notes = self.notes.clone();
        for t in self.tags.split([';', ',']) {
            e.add_tag(t);
        }
        set_or_add(&mut e, FieldKind::Url, "Website", &self.url);
        set_or_add(&mut e, FieldKind::Username, "Username", &self.username);
        set_or_add(&mut e, FieldKind::Email, "Email", &self.email);
        set_or_add(&mut e, FieldKind::Password, "Password", &self.password);
        if !self.totp.is_empty() {
            e.fields.push(Field::with_value(
                "One-time code",
                FieldKind::Totp,
                &self.totp,
            ));
        }
        for line in self.extra.lines() {
            if let Some((label, value)) = line.split_once('=') {
                let label = label.trim();
                if label.is_empty() {
                    continue;
                }
                if let Some(f) = e
                    .fields
                    .iter_mut()
                    .find(|f| f.label == label && f.value.is_empty())
                {
                    f.value = value.to_string();
                } else {
                    e.fields
                        .push(Field::with_value(label, FieldKind::Secret, value));
                }
            }
        }
        Some(e)
    }
}

/// Fill the first empty field of `kind`, or add one if the value is non-empty
/// and the template has no such field.
fn set_or_add(e: &mut Entry, kind: FieldKind, label: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    if let Some(f) = e
        .fields
        .iter_mut()
        .find(|f| f.kind == kind && f.value.is_empty())
    {
        f.value = value.to_string();
    } else {
        e.fields.push(Field::with_value(label, kind, value));
    }
}

fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    host.trim_start_matches("www.").to_string()
}

pub fn import_json(bytes: &[u8]) -> Result<ImportResult, ImportError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| ImportError::Json(e.to_string()))?;
    if v.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(ImportError::EncryptedExport);
    }
    if let Some(items) = v.get("items").and_then(Value::as_array) {
        let mut result = ImportResult {
            format: "Bitwarden JSON",
            ..Default::default()
        };
        for item in items {
            match bitwarden_item(item) {
                Some(e) => result.entries.push(e),
                None => result.skipped += 1,
            }
        }
        return Ok(result);
    }
    if let Some(items) = v.as_array() {
        let mut result = ImportResult {
            format: "JSON",
            ..Default::default()
        };
        for item in items {
            let Some(obj) = item.as_object() else {
                result.skipped += 1;
                continue;
            };
            let mut flat = FlatItem {
                kind: String::new(),
                title: String::new(),
                url: String::new(),
                username: String::new(),
                email: String::new(),
                password: String::new(),
                notes: String::new(),
                totp: String::new(),
                extra: String::new(),
                tags: String::new(),
            };
            for (k, val) in obj {
                let Some(s) = val.as_str() else { continue };
                let slot = match classify_header(k) {
                    Some("title") => &mut flat.title,
                    Some("url") => &mut flat.url,
                    Some("username") => &mut flat.username,
                    Some("email") => &mut flat.email,
                    Some("password") => &mut flat.password,
                    Some("notes") => &mut flat.notes,
                    Some("totp") => &mut flat.totp,
                    Some("kind") => &mut flat.kind,
                    Some("tags") => &mut flat.tags,
                    _ => continue,
                };
                if slot.is_empty() {
                    *slot = s.to_string();
                }
            }
            match flat.into_entry() {
                Some(e) => result.entries.push(e),
                None => result.skipped += 1,
            }
        }
        return Ok(result);
    }
    Err(ImportError::Unrecognised)
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(n) => cur = n,
            None => return "",
        }
    }
    cur.as_str().unwrap_or("")
}

fn set_label(e: &mut Entry, label: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    if let Some(f) = e.fields.iter_mut().find(|f| f.label == label) {
        f.value = value.to_string();
    }
}

fn bitwarden_item(item: &Value) -> Option<Entry> {
    let ty = item.get("type").and_then(Value::as_u64)?;
    let mut e = match ty {
        1 => {
            let mut e = Entry::new(EntryKind::Login);
            let uri = item
                .get("login")
                .and_then(|l| l.get("uris"))
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .map(|u| s(u, &["uri"]))
                .unwrap_or("");
            set_or_add(&mut e, FieldKind::Url, "Website", uri);
            set_or_add(
                &mut e,
                FieldKind::Username,
                "Username",
                s(item, &["login", "username"]),
            );
            set_or_add(
                &mut e,
                FieldKind::Password,
                "Password",
                s(item, &["login", "password"]),
            );
            let totp = s(item, &["login", "totp"]);
            if !totp.is_empty() {
                e.fields
                    .push(Field::with_value("One-time code", FieldKind::Totp, totp));
            }
            e
        }
        2 => Entry::new(EntryKind::SecureNote),
        3 => {
            let mut e = Entry::new(EntryKind::CreditCard);
            set_label(
                &mut e,
                "Cardholder name",
                s(item, &["card", "cardholderName"]),
            );
            set_label(&mut e, "Card number", s(item, &["card", "number"]));
            set_label(&mut e, "Security code (CVV)", s(item, &["card", "code"]));
            set_label(&mut e, "Issuer", s(item, &["card", "brand"]));
            let (m, y) = (
                s(item, &["card", "expMonth"]),
                s(item, &["card", "expYear"]),
            );
            if !m.is_empty() || !y.is_empty() {
                let yy = if y.len() == 4 { &y[2..] } else { y };
                set_label(&mut e, "Expiry (MM/YY)", &format!("{m:0>2}/{yy}"));
            }
            e
        }
        4 => {
            let mut e = Entry::new(EntryKind::Identity);
            let id = |k: &str| s(item, &["identity", k]);
            let name = [
                id("title"),
                id("firstName"),
                id("middleName"),
                id("lastName"),
            ]
            .iter()
            .filter(|p| !p.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
            set_label(&mut e, "Full name", &name);
            set_label(&mut e, "Email", id("email"));
            set_label(&mut e, "Phone", id("phone"));
            let addr = [
                id("address1"),
                id("address2"),
                id("address3"),
                id("city"),
                id("state"),
                id("postalCode"),
                id("country"),
            ]
            .iter()
            .filter(|p| !p.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join("\n");
            set_label(&mut e, "Address", &addr);
            set_label(&mut e, "ID / passport number", id("passportNumber"));
            set_label(&mut e, "Tax / social security number", id("ssn"));
            if !id("licenseNumber").is_empty() {
                e.fields.push(Field::with_value(
                    "Licence number",
                    FieldKind::Secret,
                    id("licenseNumber"),
                ));
            }
            e
        }
        _ => {
            let mut e = Entry::new(EntryKind::Custom);
            e.title = "Imported item".into();
            e
        }
    };
    let name = s(item, &["name"]);
    if !name.is_empty() {
        e.title = name.to_string();
    } else if e.title.is_empty() {
        e.title = "Imported item".into();
    }
    e.notes = s(item, &["notes"]).to_string();
    e.favorite = item
        .get("favorite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(fields) = item.get("fields").and_then(Value::as_array) {
        for f in fields {
            let label = s(f, &["name"]);
            let value = s(f, &["value"]);
            if label.is_empty() && value.is_empty() {
                continue;
            }
            // Bitwarden field type 0 = text, 1 = hidden, 2 = boolean.
            let kind = match f.get("type").and_then(Value::as_u64) {
                Some(0) | Some(2) => FieldKind::Text,
                _ => FieldKind::Secret,
            };
            e.fields.push(Field::with_value(
                if label.is_empty() { "Field" } else { label },
                kind,
                value,
            ));
        }
    }
    Some(e)
}

/// Produce a **plaintext** CSV of the whole vault. The caller is responsible
/// for warning the user and obtaining explicit confirmation.
///
/// Columns: `kind,title,url,username,email,password,totp,tags,notes,extra_fields`,
/// where `extra_fields` holds any other fields as `label=value` lines and
/// `tags` is `;`-separated. The format re-imports into VaultRust. Password
/// history and the trash are not exported.
pub fn export_csv(data: &VaultData) -> Zeroizing<Vec<u8>> {
    // Reserve generously up front so the buffer never reallocates.
    let estimate: usize = data
        .entries
        .iter()
        .map(|e| {
            64 + 2
                * (e.title.len()
                    + e.notes.len()
                    + e.fields
                        .iter()
                        .map(|f| f.label.len() + f.value.len() + 4)
                        .sum::<usize>())
        })
        .sum::<usize>()
        + 256;
    let mut buf = Zeroizing::new(Vec::with_capacity(estimate));
    {
        let mut w = csv::Writer::from_writer(&mut *buf);
        let _ = w.write_record([
            "kind",
            "title",
            "url",
            "username",
            "email",
            "password",
            "totp",
            "tags",
            "notes",
            "extra_fields",
        ]);
        for e in &data.entries {
            let mut used = vec![false; e.fields.len()];
            let mut take = |kind: FieldKind| -> String {
                for (i, f) in e.fields.iter().enumerate() {
                    if !used[i] && f.kind == kind && !f.value.is_empty() {
                        used[i] = true;
                        return f.value.clone();
                    }
                }
                String::new()
            };
            let url = Zeroizing::new(take(FieldKind::Url));
            let user = Zeroizing::new(take(FieldKind::Username));
            let email = Zeroizing::new(take(FieldKind::Email));
            let pass = Zeroizing::new(take(FieldKind::Password));
            let totp = Zeroizing::new(take(FieldKind::Totp));
            let tags = e.tags.join("; ");
            let mut extra = Zeroizing::new(String::new());
            for (i, f) in e.fields.iter().enumerate() {
                if !used[i] && !f.value.is_empty() {
                    if !extra.is_empty() {
                        extra.push('\n');
                    }
                    extra.push_str(&f.label.replace('=', "-"));
                    extra.push('=');
                    extra.push_str(&f.value);
                }
            }
            let _ = w.write_record([
                e.kind.label(),
                &e.title,
                &url,
                &user,
                &email,
                &pass,
                &totp,
                &tags,
                &e.notes,
                &extra,
            ]);
        }
        let _ = w.flush();
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_csv() {
        let csv = "name,url,username,password,note\nGitHub,https://github.com/login,alice,s3cret pass ,my note\n,,,,\n";
        let r = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.skipped, 1);
        let e = &r.entries[0];
        assert_eq!(e.title, "GitHub");
        assert_eq!(e.first_of(FieldKind::Username), Some("alice"));
        assert_eq!(e.primary_password(), Some("s3cret pass "));
        assert_eq!(e.first_of(FieldKind::Url), Some("https://github.com/login"));
        assert_eq!(e.notes, "my note");
    }

    #[test]
    fn bitwarden_csv_with_notes_and_totp() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   ,,login,Mail,,,0,https://www.mail.example/x,bob,pw1,JBSWY3DPEHPK3PXP\n\
                   ,,note,Recovery codes,\"a\nb\",,0,,,,\n";
        let r = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.entries[0].kind, EntryKind::Login);
        assert_eq!(r.entries[0].totp_secret(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(r.entries[1].kind, EntryKind::SecureNote);
        assert_eq!(r.entries[1].notes, "a\nb");
    }

    #[test]
    fn tags_and_totp_roundtrip_through_export() {
        let mut v = VaultData::new("t");
        let mut e = Entry::new(EntryKind::Login);
        e.title = "Mail".into();
        e.add_tag("Work");
        e.add_tag("Email");
        e.fields.push(Field::with_value(
            "2FA",
            FieldKind::Totp,
            "JBSWY3DPEHPK3PXP",
        ));
        v.entries.push(e);
        let r = import_csv(&export_csv(&v)).unwrap();
        assert_eq!(r.entries[0].tags, ["Work", "Email"]);
        assert_eq!(r.entries[0].totp_secret(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn folder_column_becomes_a_tag() {
        let csv = "folder,name,login_username,login_password
Banking,Bank,me,pw
";
        let r = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(r.entries[0].tags, ["Banking"]);
    }

    #[test]
    fn kdbx_is_detected_by_content() {
        let bytes = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 4, 0];
        assert!(matches!(
            import_auto(Path::new("x.csv"), &bytes),
            Err(ImportError::KdbxNeedsPassword)
        ));
    }

    #[test]
    fn title_falls_back_to_host() {
        let csv = "url,username,password\nhttps://www.example.com/a?b,u,p\n";
        let r = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(r.entries[0].title, "example.com");
    }

    #[test]
    fn unrecognised_csv() {
        assert!(matches!(
            import_csv(b"foo,bar\n1,2\n"),
            Err(ImportError::Unrecognised)
        ));
    }

    #[test]
    fn bitwarden_json() {
        let json = r#"{"encrypted":false,"items":[
            {"type":1,"name":"Site","notes":null,"login":{"username":"u","password":"p","uris":[{"uri":"https://s"}]},
             "fields":[{"name":"PIN","value":"1234","type":1}]},
            {"type":3,"name":"Visa","card":{"cardholderName":"A B","number":"4111111111111111","expMonth":"3","expYear":"2030","code":"123","brand":"Visa"}},
            {"type":2,"name":"Note","notes":"hello"}
        ]}"#;
        let r = import_json(json.as_bytes()).unwrap();
        assert_eq!(r.entries.len(), 3);
        assert_eq!(r.entries[0].primary_password(), Some("p"));
        assert!(r.entries[0]
            .fields
            .iter()
            .any(|f| f.label == "PIN" && f.kind == FieldKind::Secret));
        let card = &r.entries[1];
        assert!(card
            .fields
            .iter()
            .any(|f| f.label == "Expiry (MM/YY)" && f.value == "03/30"));
        assert_eq!(r.entries[2].notes, "hello");
    }

    #[test]
    fn encrypted_json_rejected() {
        assert!(matches!(
            import_json(br#"{"encrypted":true,"data":"..."}"#),
            Err(ImportError::EncryptedExport)
        ));
    }

    #[test]
    fn export_reimport_roundtrip() {
        let mut v = VaultData::new("t");
        let mut e = Entry::new(EntryKind::Server);
        e.title = "prod, \"db\"".into();
        e.fields[0].value = "10.0.0.1".into();
        e.fields[2].value = "root".into();
        e.fields[3].value = "p,a\"ss\nword".into();
        v.entries.push(e);
        let csv = export_csv(&v);
        let r = import_csv(&csv).unwrap();
        assert_eq!(r.entries.len(), 1);
        let back = &r.entries[0];
        assert_eq!(back.kind, EntryKind::Server);
        assert_eq!(back.title, "prod, \"db\"");
        assert_eq!(back.primary_password(), Some("p,a\"ss\nword"));
        assert_eq!(back.first_of(FieldKind::Username), Some("root"));
        assert!(back
            .fields
            .iter()
            .any(|f| f.label == "Host" && f.value == "10.0.0.1"));
    }
}
