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
/// * 4 — adds entry tags, password history and last-used time, the trash,
///   and settings for session locking, automatic backups, sorting and the
///   breached-password list. Also introduces [`FieldKind::Totp`].
/// * 5 — adds entry expiry dates and custom auto-type sequences, and the
///   activity log.
/// * 6 — adds file attachments.
/// * 7 — adds entry icons and colours, and per-site password rules.
pub const SCHEMA_VERSION: u32 = 7;

/// Largest file that can be attached to an item.
pub const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;
/// Largest total size of all attachments in a vault (the vault is rewritten
/// and backed up whole on every save, so it is kept moderate).
pub const MAX_TOTAL_ATTACHMENT_BYTES: usize = 50 * 1024 * 1024;

/// Activity-log events kept (oldest dropped first).
pub const MAX_AUDIT: usize = 500;
/// Items expiring within this many days are flagged as "expiring soon".
pub const EXPIRY_WARNING_DAYS: i64 = 14;

/// Password-history entries kept per item.
pub const MAX_HISTORY: usize = 10;
/// Items in the trash are deleted for good after this many days.
pub const TRASH_RETENTION_DAYS: i64 = 30;

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
            EntryKind::Login => crate::i18n::tr("Login"),
            EntryKind::Email => crate::i18n::tr("Email account"),
            EntryKind::SecureNote => crate::i18n::tr("Secure note"),
            EntryKind::CreditCard => crate::i18n::tr("Credit card"),
            EntryKind::Identity => crate::i18n::tr("Identity"),
            EntryKind::ApiKey => crate::i18n::tr("API key"),
            EntryKind::Server => crate::i18n::tr("Server"),
            EntryKind::Database => crate::i18n::tr("Database"),
            EntryKind::Wifi => crate::i18n::tr("Wi-Fi"),
            EntryKind::Custom => crate::i18n::tr("Custom"),
        }
    }

    /// Lower-case noun for use in sentences ("New API key").
    pub fn noun(self) -> &'static str {
        match self {
            EntryKind::Login => crate::i18n::tr("login"),
            EntryKind::Email => crate::i18n::tr("email account"),
            EntryKind::SecureNote => crate::i18n::tr("secure note"),
            EntryKind::CreditCard => crate::i18n::tr("credit card"),
            EntryKind::Identity => crate::i18n::tr("identity"),
            EntryKind::ApiKey => crate::i18n::tr("API key"),
            EntryKind::Server => crate::i18n::tr("server"),
            EntryKind::Database => crate::i18n::tr("database"),
            EntryKind::Wifi => crate::i18n::tr("Wi-Fi network"),
            EntryKind::Custom => crate::i18n::tr("custom item"),
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
                ("City", Text),
                ("State / region", Text),
                ("Postal code", Text),
                ("Country", Text),
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
        // Field names are written in the interface language of the time.
        spec.iter()
            .map(|(l, k)| Field::new(crate::i18n::tr(l), *k))
            .collect()
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
    /// One-time code: a Base32 TOTP secret or `otpauth://` URI. The secret
    /// is concealed; the UI shows the current code. (Schema v4; appended so
    /// the encoding of the earlier variants is unchanged.)
    Totp,
}

impl FieldKind {
    pub const ALL: [FieldKind; 9] = [
        FieldKind::Text,
        FieldKind::Username,
        FieldKind::Email,
        FieldKind::Url,
        FieldKind::Password,
        FieldKind::Secret,
        FieldKind::Note,
        FieldKind::SecretNote,
        FieldKind::Totp,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FieldKind::Text => crate::i18n::tr("Text"),
            FieldKind::Username => crate::i18n::tr("Username"),
            FieldKind::Email => crate::i18n::tr("Email"),
            FieldKind::Url => crate::i18n::tr("URL"),
            FieldKind::Password => crate::i18n::tr("Password"),
            FieldKind::Secret => crate::i18n::tr("Hidden"),
            FieldKind::Note => crate::i18n::tr("Multi-line"),
            FieldKind::SecretNote => crate::i18n::tr("Hidden multi-line"),
            FieldKind::Totp => crate::i18n::tr("One-time code"),
        }
    }

    pub fn is_concealed(self) -> bool {
        matches!(
            self,
            FieldKind::Password | FieldKind::Secret | FieldKind::SecretNote | FieldKind::Totp
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

/// A password that was replaced, kept so a half-finished password change on
/// a website can be recovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HistoryItem {
    /// Label of the field the password came from.
    pub label: String,
    pub value: String,
    /// When it was replaced (unix seconds).
    pub replaced: i64,
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
    /// Free-form labels for grouping. (Schema v4.)
    pub tags: Vec<String>,
    /// Previous passwords, newest last, at most [`MAX_HISTORY`]. (Schema v4.)
    pub history: Vec<HistoryItem>,
    /// When a value was last copied from this item (0 = never). (Schema v4.)
    pub last_used: i64,
    /// When the item expires or its password should be changed (unix
    /// seconds, 0 = never). (Schema v5.)
    pub expires: i64,
    /// Custom auto-type sequence such as `{USERNAME}{ENTER}{DELAY 1000}
    /// {PASSWORD}{ENTER}` ("" = the default). (Schema v5.)
    pub auto_type: String,
    /// Files stored inside the vault. (Schema v6.)
    pub attachments: Vec<Attachment>,
    /// Icon shown in lists, as a key from the UI's icon set ("" = the
    /// item's first letter). (Schema v7.)
    pub icon: String,
    /// Tile colour, 1-based index into the UI's palette (0 = picked from the
    /// website or title). (Schema v7.)
    pub color: u8,
}

/// A file stored, encrypted, inside an item.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Attachment {
    pub name: String,
    pub data: Vec<u8>,
    /// When it was attached (unix seconds).
    pub added: i64,
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .field("len", &self.data.len())
            .finish()
    }
}

impl Attachment {
    /// A file name safe to offer in a save dialog: no path separators or
    /// characters Windows rejects.
    pub fn safe_name(&self) -> String {
        let cleaned: String = self
            .name
            .chars()
            .map(|c| match c {
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                c if c.is_control() => '_',
                c => c,
            })
            .collect();
        let cleaned = cleaned.trim().trim_matches('.').to_string();
        if cleaned.is_empty() {
            "attachment".into()
        } else {
            cleaned
        }
    }
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
            tags: Vec::new(),
            history: Vec::new(),
            last_used: 0,
            expires: 0,
            auto_type: String::new(),
            attachments: Vec::new(),
            icon: String::new(),
            color: 0,
        }
    }

    /// The month (1–12) and four-digit year in a card's "Expiry (MM/YY)"
    /// field, if it parses (MM/YY, MM/YYYY, MM-YY).
    pub fn card_expiry_month(&self) -> Option<(u32, i64)> {
        if self.kind != EntryKind::CreditCard {
            return None;
        }
        let f = self.fields.iter().find(|f| {
            let l = f.label.to_lowercase();
            // "Expiry (MM/YY)" in English, "Λήξη (ΜΜ/ΕΕ)" in Greek.
            (l.contains("expir") || l.contains("valid") || l.contains("λήξ"))
                && !f.value.trim().is_empty()
        })?;
        let (m, y) = f.value.trim().split_once(['/', '-', ' '])?;
        let month: u32 = m.trim().parse().ok().filter(|m| (1..=12).contains(m))?;
        let mut year: i64 = y.trim().parse().ok()?;
        if year < 100 {
            year += 2000;
        }
        (2000..=2200).contains(&year).then_some((month, year))
    }

    /// The end of the month in a card's "Expiry (MM/YY)" field, if it parses
    /// (MM/YY, MM/YYYY, MM-YY).
    pub fn card_expiry(&self) -> Option<i64> {
        let (month, year) = self.card_expiry_month()?;
        // First day of the following month, minus one second.
        let (ny, nm) = if month == 12 {
            (year + 1, 1)
        } else {
            (year, month + 1)
        };
        Some(crate::timeutil::days_from_civil(ny, nm, 1) * 86_400 - 1)
    }

    /// The earliest of the explicit expiry date and a card's printed expiry.
    pub fn effective_expiry(&self) -> Option<i64> {
        let explicit = (self.expires > 0).then_some(self.expires);
        match (explicit, self.card_expiry()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Add a tag unless an equal one (ignoring case) is already present.
    pub fn add_tag(&mut self, tag: &str) -> bool {
        let tag = tag.trim();
        if tag.is_empty() || self.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
            return false;
        }
        self.tags.push(tag.to_string());
        true
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
                    .find(|f| crate::i18n::is_any(&f.label, "Card number"))
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
            crate::i18n::tr("(untitled)")
        } else {
            &self.title
        }
    }

    /// Case-insensitive search over non-secret fields only.
    pub fn matches(&self, query_lower: &str) -> bool {
        self.search_score(query_lower).is_some()
    }

    /// Fuzzy relevance of this entry for a lower-case query, or `None` if it
    /// does not match. Only non-secret text is searched. A match in the
    /// title counts more than one in a tag, which counts more than one in a
    /// field.
    pub fn search_score(&self, query_lower: &str) -> Option<i32> {
        if query_lower.is_empty() {
            return Some(0);
        }
        let score =
            |s: &str, weight: i32| fuzzy_score(&s.to_lowercase(), query_lower).map(|v| v * weight);
        let mut best = score(&self.title, 4);
        let mut consider = |v: Option<i32>| {
            if let Some(v) = v {
                best = Some(best.map_or(v, |b| b.max(v)));
            }
        };
        for t in &self.tags {
            consider(score(t, 3));
        }
        consider(score(self.kind.label(), 1));
        for f in self.fields.iter().filter(|f| !f.kind.is_concealed()) {
            consider(score(&f.value, 2));
        }
        if self.kind == EntryKind::SecureNote {
            consider(score(&self.notes, 1));
        }
        best
    }

    /// The first one-time-code field's value, if any.
    pub fn totp_secret(&self) -> Option<&str> {
        self.first_of(FieldKind::Totp)
    }
}

/// Fuzzy match of `needle` in `hay` (both already lower-case).
///
/// * A contiguous substring scores highest (100+), more so at the start or
///   at a word boundary.
/// * Otherwise the needle's characters must appear in order ("gml" finds
///   "gmail"); consecutive characters and word starts earn bonuses, gaps
///   cost points, and very scattered matches are rejected.
pub fn fuzzy_score(hay: &str, needle: &str) -> Option<i32> {
    if needle.is_empty() {
        return Some(0);
    }
    if let Some(pos) = hay.find(needle) {
        let boundary = pos == 0 || !hay[..pos].chars().last().is_some_and(char::is_alphanumeric);
        let bonus = if pos == 0 {
            40
        } else if boundary {
            20
        } else {
            0
        };
        return Some(100 + bonus - (pos.min(30) as i32));
    }
    let needle_len = needle.chars().count() as i32;
    if needle_len < 2 {
        return None;
    }
    let mut score = 0i32;
    let mut gaps = 0i32;
    let mut prev: Option<char> = None;
    let mut last_matched = false;
    let mut chars = needle.chars().peekable();
    for c in hay.chars() {
        let Some(&want) = chars.peek() else { break };
        if c == want {
            chars.next();
            score += 2;
            if last_matched {
                score += 4;
            }
            if prev.is_none_or(|p| !p.is_alphanumeric()) {
                score += 6;
            }
            last_matched = true;
        } else {
            if chars.peek().is_some() && score > 0 {
                gaps += 1;
            }
            last_matched = false;
        }
        prev = Some(c);
    }
    if chars.peek().is_some() || gaps > needle_len * 3 + 6 {
        return None;
    }
    Some((score - gaps).clamp(1, 99))
}

/// What an activity-log event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditKind {
    Unlocked,
    UnlockedWithHello,
    Exported,
    Imported,
    BackupCreated,
    Restored,
    PasswordChanged,
    CredentialsChanged,
    DeletedForever,
    TrashEmptied,
    HelloEnabled,
    HelloDisabled,
    CaptureProtectionOff,
    /// Appended in schema v6 (earlier variants keep their encoding).
    AttachmentSaved,
}

impl AuditKind {
    pub fn label(self) -> &'static str {
        match self {
            AuditKind::Unlocked => crate::i18n::tr("Unlocked with the master password"),
            AuditKind::UnlockedWithHello => crate::i18n::tr("Unlocked with Windows Hello"),
            AuditKind::Exported => crate::i18n::tr("Exported as plain CSV"),
            AuditKind::Imported => crate::i18n::tr("Imported items"),
            AuditKind::BackupCreated => crate::i18n::tr("Backup created"),
            AuditKind::Restored => crate::i18n::tr("Restored from a backup"),
            AuditKind::PasswordChanged => crate::i18n::tr("Password changed"),
            AuditKind::CredentialsChanged => crate::i18n::tr("Master password or key file changed"),
            AuditKind::DeletedForever => crate::i18n::tr("Item deleted forever"),
            AuditKind::TrashEmptied => crate::i18n::tr("Trash emptied"),
            AuditKind::HelloEnabled => crate::i18n::tr("Windows Hello unlock turned on"),
            AuditKind::HelloDisabled => crate::i18n::tr("Windows Hello unlock turned off"),
            AuditKind::AttachmentSaved => crate::i18n::tr("Attachment saved to a file"),
            AuditKind::CaptureProtectionOff => {
                crate::i18n::tr("Screen-capture protection turned off")
            }
        }
    }

    /// Events worth drawing attention to in the log.
    pub fn is_sensitive(self) -> bool {
        matches!(
            self,
            AuditKind::Exported | AuditKind::CaptureProtectionOff | AuditKind::HelloEnabled
        )
    }
}

/// One activity-log event. Stored inside the encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AuditEvent {
    pub at: i64,
    #[zeroize(skip)]
    pub kind: AuditKind,
    /// Item title, file name, count… ("" if none).
    pub detail: String,
}

/// An entry in the trash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TrashedEntry {
    pub entry: Entry,
    /// When it was deleted (unix seconds).
    pub deleted: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SortOrder {
    #[default]
    Name,
    RecentlyUsed,
    RecentlyModified,
    Created,
}

impl SortOrder {
    pub const ALL: [SortOrder; 4] = [
        SortOrder::Name,
        SortOrder::RecentlyUsed,
        SortOrder::RecentlyModified,
        SortOrder::Created,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SortOrder::Name => crate::i18n::tr("Name"),
            SortOrder::RecentlyUsed => crate::i18n::tr("Recently used"),
            SortOrder::RecentlyModified => crate::i18n::tr("Recently modified"),
            SortOrder::Created => crate::i18n::tr("Newest first"),
        }
    }

    pub fn compare(self, a: &Entry, b: &Entry) -> std::cmp::Ordering {
        let by_name = || a.title.to_lowercase().cmp(&b.title.to_lowercase());
        match self {
            SortOrder::Name => by_name(),
            SortOrder::RecentlyUsed => b.last_used.cmp(&a.last_used).then_with(by_name),
            SortOrder::RecentlyModified => b.modified.cmp(&a.modified).then_with(by_name),
            SortOrder::Created => b.created.cmp(&a.created).then_with(by_name),
        }
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
    /// Lock when Windows locks the session (Win+L, sleep with sign-in on
    /// wake, switching user). (Schema v4.)
    pub lock_on_session_lock: bool,
    /// Automatic encrypted backups kept next to the vault (0 = off).
    /// (Schema v4.)
    pub auto_backup_count: u32,
    /// Order of item lists. (Schema v4.)
    pub sort: SortOrder,
    /// Path of a local Have I Been Pwned SHA-1 list ("" = not set). Stored
    /// encrypted, like every other setting. (Schema v4.)
    pub breach_list: String,
    /// Generator options remembered for particular websites. (Schema v7.)
    pub site_rules: Vec<SiteRule>,
}

/// Password requirements of one website ("at most 16 characters, no
/// symbols"), used instead of the default generator options for items on
/// that site and its subdomains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteRule {
    /// Lower-case host without "www." ("example.com").
    pub host: String,
    pub options: GeneratorOptions,
}

/// Site rules kept per vault.
pub const MAX_SITE_RULES: usize = 500;

impl VaultSettings {
    pub const MIN_AUTO_LOCK_MINUTES: u32 = 1;
    pub const MAX_AUTO_LOCK_MINUTES: u32 = 240;
    pub const MIN_CLIPBOARD_SECS: u32 = 5;
    pub const MAX_CLIPBOARD_SECS: u32 = 600;
    pub const MIN_REVEAL_SECS: u32 = 5;
    pub const MAX_REVEAL_SECS: u32 = 300;
    pub const MAX_AUTO_BACKUPS: u32 = 100;

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
        self.auto_backup_count = self.auto_backup_count.min(Self::MAX_AUTO_BACKUPS);
        self.generator.sanitize();
        self.passphrase.sanitize();
        let mut seen = std::collections::HashSet::new();
        self.site_rules.retain_mut(|r| {
            r.host = crate::autotype::url_host(&r.host);
            r.options.sanitize();
            !r.host.is_empty() && seen.insert(r.host.clone())
        });
        self.site_rules.truncate(MAX_SITE_RULES);
    }

    /// The rule for a website: the one for its host, or for the closest
    /// parent domain ("example.com" covers "login.example.com").
    pub fn site_rule(&self, url: &str) -> Option<&SiteRule> {
        let host = crate::autotype::url_host(url);
        if host.is_empty() {
            return None;
        }
        self.site_rules
            .iter()
            .filter(|r| {
                host == r.host
                    || host
                        .strip_suffix(r.host.as_str())
                        .is_some_and(|p| p.ends_with('.'))
            })
            .max_by_key(|r| r.host.len())
    }

    /// The generator options for an item on `url` (the default options when
    /// no rule matches).
    pub fn generator_for(&self, url: Option<&str>) -> &GeneratorOptions {
        url.and_then(|u| self.site_rule(u))
            .map_or(&self.generator, |r| &r.options)
    }

    /// Remember `options` for the host of `url`, replacing an earlier rule
    /// for the same host. Returns the host, or `None` if `url` has none (or
    /// the vault already holds [`MAX_SITE_RULES`]).
    pub fn set_site_rule(&mut self, url: &str, options: GeneratorOptions) -> Option<String> {
        let host = crate::autotype::url_host(url);
        if host.is_empty() {
            return None;
        }
        let mut options = options;
        options.sanitize();
        match self.site_rules.iter_mut().find(|r| r.host == host) {
            Some(r) => r.options = options,
            None => {
                if self.site_rules.len() >= MAX_SITE_RULES {
                    return None;
                }
                self.site_rules.push(SiteRule {
                    host: host.clone(),
                    options,
                });
                self.site_rules.sort_by(|a, b| a.host.cmp(&b.host));
            }
        }
        Some(host)
    }

    pub fn remove_site_rule(&mut self, host: &str) -> bool {
        let before = self.site_rules.len();
        self.site_rules.retain(|r| r.host != host);
        self.site_rules.len() != before
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
            lock_on_session_lock: true,
            auto_backup_count: 10,
            sort: SortOrder::Name,
            breach_list: String::new(),
            site_rules: Vec::new(),
        }
    }
}

/// Schema v3 layouts (also embedded unchanged in v1 and v2 payloads).
/// postcard is not self-describing, so these must never change.
pub(crate) mod v3 {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct EntryV3 {
        pub id: u64,
        #[zeroize(skip)]
        pub kind: EntryKind,
        pub title: String,
        pub fields: Vec<Field>,
        pub notes: String,
        pub favorite: bool,
        pub created: i64,
        pub modified: i64,
        pub password_changed: i64,
    }

    impl EntryV3 {
        pub fn upgrade(&self) -> Entry {
            Entry {
                id: self.id,
                kind: self.kind,
                title: self.title.clone(),
                fields: self.fields.clone(),
                notes: self.notes.clone(),
                favorite: self.favorite,
                created: self.created,
                modified: self.modified,
                password_changed: self.password_changed,
                tags: Vec::new(),
                history: Vec::new(),
                last_used: 0,
                expires: 0,
                auto_type: String::new(),
                attachments: Vec::new(),
                icon: String::new(),
                color: 0,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct VaultSettingsV3 {
        pub auto_lock_minutes: u32,
        pub clipboard_clear_secs: u32,
        pub lock_on_minimize: bool,
        pub generator: GeneratorOptions,
        pub passphrase: PassphraseOptions,
        pub hide_from_capture: bool,
        pub reveal_timeout_secs: u32,
    }

    impl Default for VaultSettingsV3 {
        fn default() -> Self {
            let d = VaultSettings::default();
            VaultSettingsV3 {
                auto_lock_minutes: d.auto_lock_minutes,
                clipboard_clear_secs: d.clipboard_clear_secs,
                lock_on_minimize: d.lock_on_minimize,
                generator: d.generator,
                passphrase: d.passphrase,
                hide_from_capture: d.hide_from_capture,
                reveal_timeout_secs: d.reveal_timeout_secs,
            }
        }
    }

    impl VaultSettingsV3 {
        pub fn upgrade(&self) -> VaultSettings {
            VaultSettings {
                auto_lock_minutes: self.auto_lock_minutes,
                clipboard_clear_secs: self.clipboard_clear_secs,
                lock_on_minimize: self.lock_on_minimize,
                generator: self.generator.clone(),
                passphrase: self.passphrase.clone(),
                hide_from_capture: self.hide_from_capture,
                reveal_timeout_secs: self.reveal_timeout_secs,
                ..VaultSettings::default()
            }
        }
    }

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultDataV3 {
        pub schema: u32,
        pub name: String,
        pub created: i64,
        pub entries: Vec<EntryV3>,
        #[zeroize(skip)]
        pub settings: VaultSettingsV3,
        pub last_backup: i64,
    }

    impl VaultDataV3 {
        pub fn upgrade(&self) -> VaultData {
            VaultData {
                schema: SCHEMA_VERSION,
                name: self.name.clone(),
                created: self.created,
                entries: self.entries.iter().map(EntryV3::upgrade).collect(),
                settings: self.settings.upgrade(),
                last_backup: self.last_backup,
                trash: Vec::new(),
                audit: Vec::new(),
            }
        }
    }
}

/// Schema v4 layouts. `VaultSettingsV4` is also the settings layout of
/// schemas 5 and 6.
pub(crate) mod v4 {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct VaultSettingsV4 {
        pub auto_lock_minutes: u32,
        pub clipboard_clear_secs: u32,
        pub lock_on_minimize: bool,
        pub generator: GeneratorOptions,
        pub passphrase: PassphraseOptions,
        pub hide_from_capture: bool,
        pub reveal_timeout_secs: u32,
        pub lock_on_session_lock: bool,
        pub auto_backup_count: u32,
        pub sort: SortOrder,
        pub breach_list: String,
    }

    impl Default for VaultSettingsV4 {
        fn default() -> Self {
            let d = VaultSettings::default();
            VaultSettingsV4 {
                auto_lock_minutes: d.auto_lock_minutes,
                clipboard_clear_secs: d.clipboard_clear_secs,
                lock_on_minimize: d.lock_on_minimize,
                generator: d.generator,
                passphrase: d.passphrase,
                hide_from_capture: d.hide_from_capture,
                reveal_timeout_secs: d.reveal_timeout_secs,
                lock_on_session_lock: d.lock_on_session_lock,
                auto_backup_count: d.auto_backup_count,
                sort: d.sort,
                breach_list: d.breach_list,
            }
        }
    }

    impl VaultSettingsV4 {
        pub fn upgrade(&self) -> VaultSettings {
            VaultSettings {
                auto_lock_minutes: self.auto_lock_minutes,
                clipboard_clear_secs: self.clipboard_clear_secs,
                lock_on_minimize: self.lock_on_minimize,
                generator: self.generator.clone(),
                passphrase: self.passphrase.clone(),
                hide_from_capture: self.hide_from_capture,
                reveal_timeout_secs: self.reveal_timeout_secs,
                lock_on_session_lock: self.lock_on_session_lock,
                auto_backup_count: self.auto_backup_count,
                sort: self.sort,
                breach_list: self.breach_list.clone(),
                site_rules: Vec::new(),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct EntryV4 {
        pub id: u64,
        #[zeroize(skip)]
        pub kind: EntryKind,
        pub title: String,
        pub fields: Vec<Field>,
        pub notes: String,
        pub favorite: bool,
        pub created: i64,
        pub modified: i64,
        pub password_changed: i64,
        pub tags: Vec<String>,
        pub history: Vec<HistoryItem>,
        pub last_used: i64,
    }

    impl EntryV4 {
        pub fn upgrade(&self) -> Entry {
            Entry {
                id: self.id,
                kind: self.kind,
                title: self.title.clone(),
                fields: self.fields.clone(),
                notes: self.notes.clone(),
                favorite: self.favorite,
                created: self.created,
                modified: self.modified,
                password_changed: self.password_changed,
                tags: self.tags.clone(),
                history: self.history.clone(),
                last_used: self.last_used,
                expires: 0,
                auto_type: String::new(),
                attachments: Vec::new(),
                icon: String::new(),
                color: 0,
            }
        }
    }

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct TrashedEntryV4 {
        pub entry: EntryV4,
        pub deleted: i64,
    }

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultDataV4 {
        pub schema: u32,
        pub name: String,
        pub created: i64,
        pub entries: Vec<EntryV4>,
        #[zeroize(skip)]
        pub settings: VaultSettingsV4,
        pub last_backup: i64,
        pub trash: Vec<TrashedEntryV4>,
    }

    impl VaultDataV4 {
        pub fn upgrade(&self) -> VaultData {
            VaultData {
                schema: SCHEMA_VERSION,
                name: self.name.clone(),
                created: self.created,
                entries: self.entries.iter().map(EntryV4::upgrade).collect(),
                settings: self.settings.upgrade(),
                last_backup: self.last_backup,
                trash: self
                    .trash
                    .iter()
                    .map(|t| TrashedEntry {
                        entry: t.entry.upgrade(),
                        deleted: t.deleted,
                    })
                    .collect(),
                audit: Vec::new(),
            }
        }
    }
}

/// Schema v5 layout (v6 minus attachments).
pub(crate) mod v5 {
    use super::v4::VaultSettingsV4;
    use super::*;

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct EntryV5 {
        pub id: u64,
        #[zeroize(skip)]
        pub kind: EntryKind,
        pub title: String,
        pub fields: Vec<Field>,
        pub notes: String,
        pub favorite: bool,
        pub created: i64,
        pub modified: i64,
        pub password_changed: i64,
        pub tags: Vec<String>,
        pub history: Vec<HistoryItem>,
        pub last_used: i64,
        pub expires: i64,
        pub auto_type: String,
    }

    impl EntryV5 {
        pub fn upgrade(&self) -> Entry {
            Entry {
                id: self.id,
                kind: self.kind,
                title: self.title.clone(),
                fields: self.fields.clone(),
                notes: self.notes.clone(),
                favorite: self.favorite,
                created: self.created,
                modified: self.modified,
                password_changed: self.password_changed,
                tags: self.tags.clone(),
                history: self.history.clone(),
                last_used: self.last_used,
                expires: self.expires,
                auto_type: self.auto_type.clone(),
                attachments: Vec::new(),
                icon: String::new(),
                color: 0,
            }
        }
    }

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct TrashedEntryV5 {
        pub entry: EntryV5,
        pub deleted: i64,
    }

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultDataV5 {
        pub schema: u32,
        pub name: String,
        pub created: i64,
        pub entries: Vec<EntryV5>,
        #[zeroize(skip)]
        pub settings: VaultSettingsV4,
        pub last_backup: i64,
        pub trash: Vec<TrashedEntryV5>,
        pub audit: Vec<AuditEvent>,
    }

    impl VaultDataV5 {
        pub fn upgrade(&self) -> VaultData {
            VaultData {
                schema: SCHEMA_VERSION,
                name: self.name.clone(),
                created: self.created,
                entries: self.entries.iter().map(EntryV5::upgrade).collect(),
                settings: self.settings.upgrade(),
                last_backup: self.last_backup,
                trash: self
                    .trash
                    .iter()
                    .map(|t| TrashedEntry {
                        entry: t.entry.upgrade(),
                        deleted: t.deleted,
                    })
                    .collect(),
                audit: self.audit.clone(),
            }
        }
    }
}

/// Schema v6 layout (current minus entry icons and site rules).
pub(crate) mod v6 {
    use super::v4::VaultSettingsV4;
    use super::*;

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct EntryV6 {
        pub id: u64,
        #[zeroize(skip)]
        pub kind: EntryKind,
        pub title: String,
        pub fields: Vec<Field>,
        pub notes: String,
        pub favorite: bool,
        pub created: i64,
        pub modified: i64,
        pub password_changed: i64,
        pub tags: Vec<String>,
        pub history: Vec<HistoryItem>,
        pub last_used: i64,
        pub expires: i64,
        pub auto_type: String,
        pub attachments: Vec<Attachment>,
    }

    impl EntryV6 {
        pub fn upgrade(&self) -> Entry {
            Entry {
                id: self.id,
                kind: self.kind,
                title: self.title.clone(),
                fields: self.fields.clone(),
                notes: self.notes.clone(),
                favorite: self.favorite,
                created: self.created,
                modified: self.modified,
                password_changed: self.password_changed,
                tags: self.tags.clone(),
                history: self.history.clone(),
                last_used: self.last_used,
                expires: self.expires,
                auto_type: self.auto_type.clone(),
                attachments: self.attachments.clone(),
                icon: String::new(),
                color: 0,
            }
        }
    }

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct TrashedEntryV6 {
        pub entry: EntryV6,
        pub deleted: i64,
    }

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultDataV6 {
        pub schema: u32,
        pub name: String,
        pub created: i64,
        pub entries: Vec<EntryV6>,
        #[zeroize(skip)]
        pub settings: VaultSettingsV4,
        pub last_backup: i64,
        pub trash: Vec<TrashedEntryV6>,
        pub audit: Vec<AuditEvent>,
    }

    impl VaultDataV6 {
        pub fn upgrade(&self) -> VaultData {
            VaultData {
                schema: SCHEMA_VERSION,
                name: self.name.clone(),
                created: self.created,
                entries: self.entries.iter().map(EntryV6::upgrade).collect(),
                settings: self.settings.upgrade(),
                last_backup: self.last_backup,
                trash: self
                    .trash
                    .iter()
                    .map(|t| TrashedEntry {
                        entry: t.entry.upgrade(),
                        deleted: t.deleted,
                    })
                    .collect(),
                audit: self.audit.clone(),
            }
        }
    }
}

/// Schema v1 layouts, kept so vaults written by earlier versions still open.
/// postcard is not self-describing, so every past layout must be preserved
/// exactly and converted on load.
pub(crate) mod v1 {
    use super::v3::{EntryV3, VaultSettingsV3};
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
        pub entries: Vec<EntryV3>,
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
                entries: self.entries.iter().map(EntryV3::upgrade).collect(),
                settings: VaultSettingsV3 {
                    auto_lock_minutes: s.auto_lock_minutes,
                    clipboard_clear_secs: s.clipboard_clear_secs,
                    lock_on_minimize: s.lock_on_minimize,
                    generator: s.generator.clone(),
                    passphrase: s.passphrase.clone(),
                    ..VaultSettingsV3::default()
                }
                .upgrade(),
                last_backup: 0,
                trash: Vec::new(),
                audit: Vec::new(),
            }
        }
    }
}

/// Schema v2 layout (identical to v3 minus `last_backup`).
pub(crate) mod v2 {
    use super::v3::{EntryV3, VaultSettingsV3};
    use super::*;

    #[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultDataV2 {
        pub schema: u32,
        pub name: String,
        pub created: i64,
        pub entries: Vec<EntryV3>,
        #[zeroize(skip)]
        pub settings: VaultSettingsV3,
    }

    impl VaultDataV2 {
        pub fn upgrade(&self) -> VaultData {
            VaultData {
                schema: SCHEMA_VERSION,
                name: self.name.clone(),
                created: self.created,
                entries: self.entries.iter().map(EntryV3::upgrade).collect(),
                settings: self.settings.upgrade(),
                last_backup: 0,
                trash: Vec::new(),
                audit: Vec::new(),
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
    /// Deleted items, restorable for [`TRASH_RETENTION_DAYS`]. (Schema v4.)
    pub trash: Vec<TrashedEntry>,
    /// Activity log, oldest first, at most [`MAX_AUDIT`]. (Schema v5.)
    pub audit: Vec<AuditEvent>,
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
            trash: Vec::new(),
            audit: Vec::new(),
        }
    }

    /// Total size of every attachment, including items in the trash.
    pub fn attachment_bytes(&self) -> usize {
        self.entries
            .iter()
            .chain(self.trash.iter().map(|t| &t.entry))
            .flat_map(|e| &e.attachments)
            .map(|a| a.data.len())
            .sum()
    }

    /// Append an activity-log event.
    pub fn log(&mut self, kind: AuditKind, detail: &str) {
        self.audit.push(AuditEvent {
            at: now_unix(),
            kind,
            detail: detail.to_string(),
        });
        let excess = self.audit.len().saturating_sub(MAX_AUDIT);
        self.audit.drain(..excess);
    }

    /// An entry in the vault that looks like the same account as `e`: same
    /// title, same username (or email) and same website host. Returns its id
    /// and whether the password is also identical.
    pub fn find_duplicate(&self, e: &Entry) -> Option<(u64, bool)> {
        let key = |x: &Entry| {
            (
                x.title.trim().to_lowercase(),
                x.first_of(FieldKind::Username)
                    .or_else(|| x.first_of(FieldKind::Email))
                    .unwrap_or("")
                    .trim()
                    .to_lowercase(),
                x.first_of(FieldKind::Url)
                    .map(crate::autotype::url_host)
                    .unwrap_or_default(),
            )
        };
        let k = key(e);
        self.entries
            .iter()
            .filter(|x| x.kind == e.kind)
            .find(|x| key(x) == k)
            .map(|x| (x.id, x.primary_password() == e.primary_password()))
    }

    /// Move an entry to the trash.
    pub fn trash_entry(&mut self, id: u64) -> bool {
        let Some(pos) = self.entries.iter().position(|e| e.id == id) else {
            return false;
        };
        let entry = self.entries.remove(pos);
        self.trash.push(TrashedEntry {
            entry,
            deleted: now_unix(),
        });
        true
    }

    /// Put a trashed entry back.
    pub fn restore_entry(&mut self, id: u64) -> bool {
        self.restore_entry_id(id).is_some()
    }

    /// Put a trashed entry back, returning its id in the vault (a new one if
    /// its old id has been taken meanwhile).
    pub fn restore_entry_id(&mut self, id: u64) -> Option<u64> {
        let pos = self.trash.iter().position(|t| t.entry.id == id)?;
        let t = self.trash.remove(pos);
        let mut entry = t.entry.clone();
        if self.entry(entry.id).is_some() {
            entry.id = new_id();
        }
        let id = entry.id;
        self.entries.push(entry);
        Some(id)
    }

    /// Delete a trashed entry for good.
    pub fn purge_entry(&mut self, id: u64) -> bool {
        let before = self.trash.len();
        self.trash.retain(|t| t.entry.id != id);
        self.trash.len() != before
    }

    pub fn empty_trash(&mut self) -> usize {
        let n = self.trash.len();
        self.trash.clear();
        n
    }

    /// Drop trashed entries older than [`TRASH_RETENTION_DAYS`]. Returns how
    /// many were removed.
    pub fn purge_expired_trash(&mut self, now: i64) -> usize {
        let before = self.trash.len();
        let cutoff = now - TRASH_RETENTION_DAYS * 86_400;
        self.trash.retain(|t| t.deleted > cutoff);
        before - self.trash.len()
    }

    /// Record that a value was copied from an entry.
    pub fn mark_used(&mut self, id: u64, now: i64) {
        if let Some(e) = self.entry_mut(id) {
            e.last_used = now;
        }
    }

    /// Every tag in use with its item count, sorted by name.
    pub fn tags(&self) -> Vec<(String, usize)> {
        let mut map: std::collections::BTreeMap<String, (String, usize)> = Default::default();
        for t in self.entries.iter().flat_map(|e| e.tags.iter()) {
            let slot = map
                .entry(t.to_lowercase())
                .or_insert_with(|| (t.clone(), 0));
            slot.1 += 1;
        }
        map.into_values().collect()
    }

    pub fn entry(&self, id: u64) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn entry_mut(&mut self, id: u64) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    /// Insert or replace an entry by id, maintaining timestamps and the
    /// password history (replaced passwords are kept, at most
    /// [`MAX_HISTORY`] per entry).
    pub fn upsert(&mut self, mut entry: Entry) {
        let now = now_unix();
        entry.modified = now;
        let mut changed_title = None;
        if let Some(existing) = self.entry_mut(entry.id) {
            // History and usage belong to the stored entry, not to whatever
            // copy an editor was holding.
            let mut history = existing.history.clone();
            let changed = {
                let old: Vec<&str> = existing.passwords().collect();
                let new: Vec<&str> = entry.passwords().collect();
                for f in existing.fields.iter().filter(|f| {
                    f.kind == FieldKind::Password
                        && !f.value.is_empty()
                        && !new.contains(&f.value.as_str())
                }) {
                    history.push(HistoryItem {
                        label: f.label.clone(),
                        value: f.value.clone(),
                        replaced: now,
                    });
                }
                old != new
            };
            if changed {
                entry.password_changed = now;
                changed_title = Some(entry.title.clone());
            }
            let excess = history.len().saturating_sub(MAX_HISTORY);
            history.drain(..excess);
            entry.history = history;
            entry.last_used = entry.last_used.max(existing.last_used);
            entry.created = existing.created;
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
        if let Some(title) = changed_title {
            self.log(AuditKind::PasswordChanged, &title);
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
    fn attachment_names_are_safe_for_saving() {
        let a = |name: &str| Attachment {
            name: name.into(),
            data: Vec::new(),
            added: 0,
        };
        assert_eq!(a(r"..\..\evil.exe").safe_name(), "_.._evil.exe");
        assert_eq!(a("C:/x?.txt").safe_name(), "C__x_.txt");
        assert_eq!(a("...").safe_name(), "attachment");
        assert_eq!(a("keys.pdf").safe_name(), "keys.pdf");
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
    fn upsert_keeps_replaced_passwords_in_history() {
        let mut v = VaultData::new("t");
        let mut e = Entry::new(EntryKind::Login);
        e.fields[3].value = "first".into();
        v.upsert(e.clone());
        assert!(v.entries[0].history.is_empty());
        for i in 0..15 {
            let mut edit = v.entries[0].clone();
            edit.fields[3].value = format!("pw{i}");
            // An editor's stale history must not overwrite the stored one.
            edit.history.clear();
            v.upsert(edit);
        }
        let h = &v.entries[0].history;
        assert_eq!(h.len(), MAX_HISTORY);
        assert_eq!(h.last().unwrap().value, "pw13");
        assert_eq!(h[0].value, "pw4");
        assert_eq!(h[0].label, "Password");
        // Changing something other than the password adds nothing.
        let mut edit = v.entries[0].clone();
        edit.title = "renamed".into();
        v.upsert(edit);
        assert_eq!(v.entries[0].history.len(), MAX_HISTORY);
    }

    #[test]
    fn trash_restore_and_purge() {
        let mut v = VaultData::new("t");
        let e = Entry::new(EntryKind::Login);
        let id = e.id;
        v.upsert(e);
        assert!(v.trash_entry(id));
        assert!(v.entries.is_empty());
        assert_eq!(v.trash.len(), 1);
        assert!(v.restore_entry(id));
        assert_eq!(v.entries[0].id, id);
        assert!(v.trash_entry(id));
        let now = now_unix();
        assert_eq!(v.purge_expired_trash(now), 0);
        assert_eq!(
            v.purge_expired_trash(now + TRASH_RETENTION_DAYS * 86_400 + 1),
            1
        );
        assert!(v.trash.is_empty());
        assert!(!v.purge_entry(id));
    }

    #[test]
    fn tags_are_deduplicated_and_counted() {
        let mut v = VaultData::new("t");
        let mut a = Entry::new(EntryKind::Login);
        assert!(a.add_tag(" Work "));
        assert!(!a.add_tag("work"));
        assert!(!a.add_tag("  "));
        a.add_tag("Finance");
        let mut b = Entry::new(EntryKind::Login);
        b.add_tag("WORK");
        v.upsert(a);
        v.upsert(b);
        assert_eq!(
            v.tags(),
            vec![("Finance".to_string(), 1), ("Work".to_string(), 2)]
        );
    }

    #[test]
    fn fuzzy_matching() {
        assert!(fuzzy_score("gmail", "gml").is_some());
        assert!(fuzzy_score("github", "gh").is_some());
        assert!(fuzzy_score("github", "hg").is_none());
        assert!(fuzzy_score("a very long title with scattered letters", "aq").is_none());
        // Substrings beat subsequences; prefixes beat inner matches.
        assert!(fuzzy_score("gmail", "gma") > fuzzy_score("gmail", "gml"));
        assert!(fuzzy_score("gitlab", "git") > fuzzy_score("digit", "git"));
        assert!(fuzzy_score("my bank", "bank") > fuzzy_score("mybank", "bank"));

        let mut e = Entry::new(EntryKind::Login);
        e.title = "GitHub".into();
        e.tags.push("work".into());
        e.fields[3].value = "secretpw".into();
        assert!(e.matches("gthb"));
        assert!(e.matches("work"));
        assert!(
            !e.matches("secretpw"),
            "concealed fields are never searched"
        );
        assert!(e.search_score("github") > e.search_score("work"));
    }

    #[test]
    fn sort_orders() {
        let mut a = Entry::new(EntryKind::Login);
        a.title = "b".into();
        a.last_used = 10;
        let mut b = Entry::new(EntryKind::Login);
        b.title = "a".into();
        b.last_used = 20;
        use std::cmp::Ordering::*;
        assert_eq!(SortOrder::Name.compare(&a, &b), Greater);
        assert_eq!(SortOrder::RecentlyUsed.compare(&a, &b), Greater);
        assert_eq!(SortOrder::RecentlyUsed.compare(&b, &a), Less);
    }

    #[test]
    fn card_and_explicit_expiry() {
        let mut card = Entry::new(EntryKind::CreditCard);
        card.fields[2].value = "03/27".into();
        let end_of_march_2027 = crate::timeutil::days_from_civil(2027, 4, 1) * 86_400 - 1;
        assert_eq!(card.card_expiry(), Some(end_of_march_2027));
        card.fields[2].value = "12/2030".into();
        assert_eq!(
            card.card_expiry(),
            Some(crate::timeutil::days_from_civil(2031, 1, 1) * 86_400 - 1)
        );
        card.fields[2].value = "13/30".into();
        assert_eq!(card.card_expiry(), None);
        card.expires = 1_000;
        assert_eq!(card.effective_expiry(), Some(1_000));
        let mut login = Entry::new(EntryKind::Login);
        assert_eq!(login.effective_expiry(), None);
        login.expires = 5;
        assert_eq!(login.effective_expiry(), Some(5));
    }

    #[test]
    fn audit_log_is_capped() {
        let mut v = VaultData::new("t");
        for i in 0..MAX_AUDIT + 20 {
            v.log(AuditKind::Unlocked, &i.to_string());
        }
        assert_eq!(v.audit.len(), MAX_AUDIT);
        assert_eq!(v.audit[0].detail, "20");
    }

    #[test]
    fn duplicates_are_found_by_title_user_and_host() {
        let mut v = VaultData::new("t");
        let mut a = Entry::new(EntryKind::Login);
        a.title = "GitHub".into();
        a.fields[0].value = "https://github.com/login".into();
        a.fields[1].value = "Alice".into();
        a.fields[3].value = "pw1".into();
        let id = a.id;
        v.upsert(a.clone());
        let mut same = a.clone();
        same.id = new_id();
        same.fields[0].value = "https://www.github.com/".into();
        same.fields[1].value = "alice".into();
        assert_eq!(v.find_duplicate(&same), Some((id, true)));
        same.fields[3].value = "pw2".into();
        assert_eq!(v.find_duplicate(&same), Some((id, false)));
        same.fields[1].value = "bob".into();
        assert_eq!(v.find_duplicate(&same), None);
    }

    #[test]
    fn site_rules_cover_subdomains_and_prefer_the_closest() {
        let mut s = VaultSettings::default();
        let short = GeneratorOptions {
            length: 12,
            ..Default::default()
        };
        let digits = GeneratorOptions {
            length: 6,
            ..Default::default()
        };
        assert_eq!(
            s.set_site_rule("https://www.Example.com/login", short.clone()),
            Some("example.com".into())
        );
        s.set_site_rule("bank.example.com", digits.clone());
        assert_eq!(s.generator_for(Some("https://example.com")), &short);
        assert_eq!(s.generator_for(Some("https://mail.example.com")), &short);
        assert_eq!(s.generator_for(Some("https://x.bank.example.com")), &digits);
        assert_eq!(
            s.generator_for(Some("https://notexample.com")),
            &s.generator
        );
        assert_eq!(s.generator_for(None), &s.generator);
        assert_eq!(s.set_site_rule("", short), None);
        assert!(s.remove_site_rule("example.com"));
        assert_eq!(s.generator_for(Some("https://example.com")), &s.generator);
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
