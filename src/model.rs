//! Decrypted vault contents.
//!
//! These structures only ever exist in memory. They are serialized with
//! `postcard` and encrypted as a single payload before touching disk. All
//! string data is wiped on drop via `ZeroizeOnDrop` (see `docs/SECURITY.md`
//! for what that does and does not guarantee).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::random_array;
use crate::generator::{GeneratorOptions, PassphraseOptions};
use crate::timeutil::now_unix;

/// Payload schema version (independent of the outer file format version).
///
/// * 1 — initial layout.
/// * 2 — adds `VaultSettings::hide_from_capture` and `reveal_timeout_secs`.
/// * 3 — adds `VaultData::last_backup`.
pub const SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntryKind {
    Login,
    Email,
    SecureNote,
    CreditCard,
    Identity,
    ApiKey,
    Server,
    Database,
    Wifi,
    Custom,
}

impl EntryKind {
    pub const ALL: [EntryKind; 10] = [
        EntryKind::Login,
        EntryKind::Email,
        EntryKind::SecureNote,
        EntryKind::CreditCard,
        EntryKind::Identity,
        EntryKind::ApiKey,
        EntryKind::Server,
        EntryKind::Database,
        EntryKind::Wifi,
        EntryKind::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            EntryKind::Login => "Login",
            EntryKind::Email => "Email account",
            EntryKind::SecureNote => "Secure note",
            EntryKind::CreditCard => "Credit card",
            EntryKind::Identity => "Identity",
            EntryKind::ApiKey => "API key",
            EntryKind::Server => "Server",
            EntryKind::Database => "Database",
            EntryKind::Wifi => "Wi-Fi",
            EntryKind::Custom => "Custom",
        }
    }

    /// Lower-case noun for use in sentences ("New API key").
    pub fn noun(self) -> &'static str {
        match self {
            EntryKind::Login => "login",
            EntryKind::Email => "email account",
            EntryKind::SecureNote => "secure note",
            EntryKind::CreditCard => "credit card",
            EntryKind::Identity => "identity",
            EntryKind::ApiKey => "API key",
            EntryKind::Server => "server",
            EntryKind::Database => "database",
            EntryKind::Wifi => "Wi-Fi network",
            EntryKind::Custom => "custom item",
        }
    }

    /// Default fields for a new entry of this kind.
    pub fn template(self) -> Vec<Field> {
        use FieldKind::*;
        let spec: &[(&str, FieldKind)] = match self {
            EntryKind::Login => &[
                ("Website", Url),
                ("Username", Username),
                ("Email", Email),
                ("Password", Password),
            ],
            EntryKind::Email => &[
                ("Email address", Email),
                ("Password", Password),
                ("Mail server", Text),
                ("Recovery email", Email),
            ],
            EntryKind::SecureNote => &[],
            EntryKind::CreditCard => &[
                ("Cardholder name", Text),
                ("Card number", Secret),
                ("Expiry (MM/YY)", Text),
                ("Security code (CVV)", Secret),
                ("PIN", Secret),
                ("Issuer", Text),
            ],
            EntryKind::Identity => &[
                ("Full name", Text),
                ("Email", Email),
                ("Phone", Text),
                ("Address", Note),
                ("Date of birth", Text),
                ("ID / passport number", Secret),
                ("Tax / social security number", Secret),
            ],
            EntryKind::ApiKey => &[
                ("Service", Text),
                ("API key", Secret),
                ("API secret", Secret),
                ("Endpoint", Url),
                ("Expires", Text),
            ],
            EntryKind::Server => &[
                ("Host", Text),
                ("Port", Text),
                ("Username", Username),
                ("Password", Password),
                ("SSH private key", SecretNote),
            ],
            EntryKind::Database => &[
                ("Engine", Text),
                ("Host", Text),
                ("Port", Text),
                ("Database", Text),
                ("Username", Username),
                ("Password", Password),
                ("Connection string", Secret),
            ],
            EntryKind::Wifi => &[
                ("Network name (SSID)", Text),
                ("Password", Password),
                ("Security", Text),
            ],
            EntryKind::Custom => &[],
        };
        spec.iter().map(|(l, k)| Field::new(l, *k)).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldKind {
    Text,
    Username,
    Email,
    Url,
    /// A password: concealed, checked for strength and reuse.
    Password,
    /// Concealed single-line secret (card number, API key, PIN...).
    Secret,
    /// Multi-line plain text.
    Note,
    /// Concealed multi-line secret (private keys, recovery codes).
    SecretNote,
}

impl FieldKind {
    pub const ALL: [FieldKind; 8] = [
        FieldKind::Text,
        FieldKind::Username,
        FieldKind::Email,
        FieldKind::Url,
        FieldKind::Password,
        FieldKind::Secret,
        FieldKind::Note,
        FieldKind::SecretNote,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FieldKind::Text => "Text",
            FieldKind::Username => "Username",
            FieldKind::Email => "Email",
            FieldKind::Url => "URL",
            FieldKind::Password => "Password",
            FieldKind::Secret => "Hidden",
            FieldKind::Note => "Multi-line",
            FieldKind::SecretNote => "Hidden multi-line",
        }
    }

    pub fn is_concealed(self) -> bool {
        matches!(
            self,
            FieldKind::Password | FieldKind::Secret | FieldKind::SecretNote
        )
    }

    pub fn is_multiline(self) -> bool {
        matches!(self, FieldKind::Note | FieldKind::SecretNote)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    pub label: String,
    pub value: String,
    #[zeroize(skip)]
    pub kind: FieldKind,
}

impl Field {
    pub fn new(label: &str, kind: FieldKind) -> Self {
        Field {
            label: label.to_string(),
            value: String::new(),
            kind,
        }
    }

    pub fn with_value(label: &str, kind: FieldKind, value: &str) -> Self {
        Field {
            label: label.to_string(),
            value: value.to_string(),
            kind,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: u64,
    #[zeroize(skip)]
    pub kind: EntryKind,
    pub title: String,
    pub fields: Vec<Field>,
    pub notes: String,
    pub favorite: bool,
    pub created: i64,
    pub modified: i64,
    /// When a password field last changed (for "old password" warnings).
    pub password_changed: i64,
}

impl Entry {
    pub fn new(kind: EntryKind) -> Self {
        let now = now_unix();
        Entry {
            id: new_id(),
            kind,
            title: String::new(),
            fields: kind.template(),
            notes: String::new(),
            favorite: false,
            created: now,
            modified: now,
            password_changed: now,
        }
    }

    /// The first non-empty password field, if any.
    pub fn primary_password(&self) -> Option<&str> {
        self.passwords().next()
    }

    /// All non-empty password-type field values.
    pub fn passwords(&self) -> impl Iterator<Item = &str> {
        self.fields
            .iter()
            .filter(|f| f.kind == FieldKind::Password && !f.value.is_empty())
            .map(|f| f.value.as_str())
    }

    pub fn first_of(&self, kind: FieldKind) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.kind == kind && !f.value.trim().is_empty())
            .map(|f| f.value.as_str())
    }

    /// Short, non-secret description shown in lists.
    pub fn subtitle(&self) -> String {
        match self.kind {
            EntryKind::CreditCard => {
                let number = self
                    .fields
                    .iter()
                    .find(|f| f.label == "Card number")
                    .map(|f| f.value.as_str())
                    .unwrap_or("");
                let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 4 {
                    format!("•••• {}", &digits[digits.len() - 4..])
                } else {
                    String::new()
                }
            }
            EntryKind::SecureNote => self
                .notes
                .lines()
                .find(|l| !l.trim().is_empty())
                .map(|l| truncate(l.trim(), 48))
                .unwrap_or_default(),
            _ => self
                .first_of(FieldKind::Username)
                .or_else(|| self.first_of(FieldKind::Email))
                .or_else(|| {
                    self.fields
                        .iter()
                        .find(|f| f.kind == FieldKind::Text && !f.value.trim().is_empty())
                        .map(|f| f.value.as_str())
                })
                .map(|s| truncate(s, 48))
                .unwrap_or_default(),
        }
    }

    pub fn display_title(&self) -> &str {
        if self.title.trim().is_empty() {
            "(untitled)"
        } else {
            &self.title
        }
    }

    /// Case-insensitive search over non-secret fields only.
    pub fn matches(&self, query_lower: &str) -> bool {
        if query_lower.is_empty() {
            return true;
        }
        let hit = |s: &str| s.to_lowercase().contains(query_lower);
        hit(&self.title)
            || hit(self.kind.label())
            || self
                .fields
                .iter()
                .filter(|f| !f.kind.is_concealed())
                .any(|f| hit(&f.value))
            || (self.kind == EntryKind::SecureNote && hit(&self.notes))
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max_chars - 1).collect();
        t.push('…');
        t
    }
}

pub fn new_id() -> u64 {
    u64::from_le_bytes(random_array::<8>())
}

/// Per-vault preferences. Stored inside the encrypted payload so that no
/// configuration file is needed next to the vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultSettings {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_secs: u32,
    pub lock_on_minimize: bool,
    pub generator: GeneratorOptions,
    pub passphrase: PassphraseOptions,
    /// Ask Windows to exclude the window from screenshots and screen sharing
    /// while the vault is unlocked. (Schema v2.)
    pub hide_from_capture: bool,
    /// Revealed secrets are masked again after this many seconds. (Schema v2.)
    pub reveal_timeout_secs: u32,
}

impl VaultSettings {
    pub const MIN_AUTO_LOCK_MINUTES: u32 = 1;
    pub const MAX_AUTO_LOCK_MINUTES: u32 = 240;
    pub const MIN_CLIPBOARD_SECS: u32 = 5;
    pub const MAX_CLIPBOARD_SECS: u32 = 600;
    pub const MIN_REVEAL_SECS: u32 = 5;
    pub const MAX_REVEAL_SECS: u32 = 300;

    pub fn sanitize(&mut self) {
        self.auto_lock_minutes = self
            .auto_lock_minutes
            .clamp(Self::MIN_AUTO_LOCK_MINUTES, Self::MAX_AUTO_LOCK_MINUTES);
        self.clipboard_clear_secs = self
            .clipboard_clear_secs
            .clamp(Self::MIN_CLIPBOARD_SECS, Self::MAX_CLIPBOARD_SECS);
        self.reveal_timeout_secs = self
            .reveal_timeout_secs
            .clamp(Self::MIN_REVEAL_SECS, Self::MAX_REVEAL_SECS);
        self.generator.sanitize();
        self.passphrase.sanitize();
    }
}

impl Default for VaultSettings {
    fn default() -> Self {
        VaultSettings {
            auto_lock_minutes: 5,
            clipboard_clear_secs: 30,
            lock_on_minimize: false,
            generator: GeneratorOptions::default(),
            passphrase: PassphraseOptions::default(),
            hide_from_capture: true,
            reveal_timeout_secs: 30,
        }
    }
}

/// Schema v1 layouts, kept so vaults written by earlier versions still open.
/// postcard is not self-describing, so every past layout must be preserved
/// exactly and converted on load.
pub(crate) mod v1 {
    use super::*;

    #[derive(Deserialize, Serialize)]
    pub struct VaultSettingsV1 {
        pub auto_lock_minutes: u32,
        pub clipboard_clear_secs: u32,
        pub lock_on_minimize: bool,
        pub generator: GeneratorOptions,
        pub passphrase: PassphraseOptions,
    }

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultDataV1 {
        pub schema: u32,
        pub name: String,
        pub created: i64,
        pub entries: Vec<Entry>,
        #[zeroize(skip)]
        pub settings: VaultSettingsV1,
    }

    impl VaultDataV1 {
        pub fn upgrade(&self) -> VaultData {
            let s = &self.settings;
            VaultData {
                schema: SCHEMA_VERSION,
                name: self.name.clone(),
                created: self.created,
                entries: self.entries.clone(),
                settings: VaultSettings {
                    auto_lock_minutes: s.auto_lock_minutes,
                    clipboard_clear_secs: s.clipboard_clear_secs,
                    lock_on_minimize: s.lock_on_minimize,
                    generator: s.generator.clone(),
                    passphrase: s.passphrase.clone(),
                    ..VaultSettings::default()
                },
                last_backup: 0,
            }
        }
    }
}

/// Schema v2 layout (identical to v3 minus `last_backup`).
pub(crate) mod v2 {
    use super::*;

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultDataV2 {
        pub schema: u32,
        pub name: String,
        pub created: i64,
        pub entries: Vec<Entry>,
        #[zeroize(skip)]
        pub settings: VaultSettings,
    }

    impl VaultDataV2 {
        pub fn upgrade(&self) -> VaultData {
            VaultData {
                schema: SCHEMA_VERSION,
                name: self.name.clone(),
                created: self.created,
                entries: self.entries.clone(),
                settings: self.settings.clone(),
                last_backup: 0,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    pub schema: u32,
    pub name: String,
    pub created: i64,
    pub entries: Vec<Entry>,
    #[zeroize(skip)]
    pub settings: VaultSettings,
    /// When an encrypted backup was last written from this vault (unix
    /// seconds, 0 = never). (Schema v3.)
    pub last_backup: i64,
}

impl VaultData {
    pub fn new(name: &str) -> Self {
        VaultData {
            schema: SCHEMA_VERSION,
            name: name.to_string(),
            created: now_unix(),
            entries: Vec::new(),
            settings: VaultSettings::default(),
            last_backup: 0,
        }
    }

    pub fn entry(&self, id: u64) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn entry_mut(&mut self, id: u64) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    /// Insert or replace an entry by id, maintaining timestamps.
    pub fn upsert(&mut self, mut entry: Entry) {
        let now = now_unix();
        entry.modified = now;
        if let Some(existing) = self.entry_mut(entry.id) {
            let old: Vec<&str> = existing.passwords().collect();
            let new: Vec<&str> = entry.passwords().collect();
            if old != new {
                entry.password_changed = now;
            }
            entry.created = existing.created;
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.entries.len() != before
    }

    pub fn count(&self, kind: EntryKind) -> usize {
        self.entries.iter().filter(|e| e.kind == kind).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_have_expected_secret_fields() {
        let card = Entry::new(EntryKind::CreditCard);
        assert!(card
            .fields
            .iter()
            .any(|f| f.label == "Card number" && f.kind.is_concealed()));
        let login = Entry::new(EntryKind::Login);
        assert!(login.fields.iter().any(|f| f.kind == FieldKind::Password));
        assert!(Entry::new(EntryKind::Custom).fields.is_empty());
    }

    #[test]
    fn subtitle_masks_card_number() {
        let mut card = Entry::new(EntryKind::CreditCard);
        card.fields[1].value = "4111 1111 1111 1234".into();
        assert_eq!(card.subtitle(), "•••• 1234");
    }

    #[test]
    fn search_ignores_concealed_fields() {
        let mut e = Entry::new(EntryKind::Login);
        e.title = "Example".into();
        e.fields[3].value = "hunter2".into();
        assert!(e.matches("examp"));
        assert!(!e.matches("hunter2"));
    }

    #[test]
    fn upsert_tracks_password_change() {
        let mut v = VaultData::new("t");
        let mut e = Entry::new(EntryKind::Login);
        e.password_changed = 0;
        e.created = 5;
        v.upsert(e.clone());
        assert_eq!(v.entries[0].password_changed, 0);
        e.fields[3].value = "new".into();
        v.upsert(e);
        assert!(v.entries[0].password_changed > 0);
        assert_eq!(v.entries[0].created, 5);
    }

    #[test]
    fn zeroize_clears_strings() {
        let mut e = Entry::new(EntryKind::Login);
        e.title = "secret title".into();
        e.fields[3].value = "secret password".into();
        e.zeroize();
        assert!(e.title.is_empty());
        assert!(e.fields.is_empty());
    }
}
