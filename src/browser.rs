//! The browser extension (`browser-extension/`): it fills in logins, offers
//! to save new ones, generates passwords and searches the vault, all through
//! the running app.
//!
//! The browser starts `VaultRust.exe` as a *native messaging host*
//! (`run_host`) and talks to it over stdin/stdout. That helper only relays
//! each message over a named pipe (`os_protect::serve_pipe`, open to the
//! current user only) to the running app, which answers:
//!
//! * only while browser filling is turned on in its settings;
//! * only to browsers the user approved once in the app (each sends a random
//!   token; the app keeps its SHA-256 in the preferences);
//! * only while a vault is unlocked.
//!
//! What a page can get filled in is limited to the logins whose website
//! matches it (subdomains included; never an `https` login for an `http`
//! page). The popup can also search the whole vault, but only titles,
//! usernames and websites are sent; a password or code chosen there is
//! copied by the app (cleared after the vault's clipboard timeout, kept out
//! of clipboard history), never handed to the browser.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::autofill;
use crate::autotype::{site_name, url_host};
use crate::model::{Entry, EntryKind, Field, FieldKind, VaultData};

/// The native messaging host's name, as the extension knows it.
pub const HOST_NAME: &str = "com.vaultrust.browser";

/// The extension's ID, fixed by the public key in its manifest. If the
/// extension is ever published in a store under another ID, add it to
/// [`ALLOWED_EXTENSIONS`].
pub const EXTENSION_ID: &str = "kbbgmknjmnadcnmfllepkafdammfomco";

/// Extensions allowed to start the helper.
pub const ALLOWED_EXTENSIONS: &[&str] = &[EXTENSION_ID];

/// The Firefox add-on's ID (`browser_specific_settings.gecko.id` in the
/// manifest), which Firefox allows to start the helper.
pub const FIREFOX_EXTENSION_ID: &str = "browser@vaultrust.app";

/// Firefox only adds extensions signed by Mozilla, so the add-on is signed
/// when a release is made (docs/RELEASING.md) and downloaded from there.
pub fn firefox_addon_url() -> String {
    format!(
        "https://github.com/{}/releases/latest/download/VaultRust-Firefox.xpi",
        crate::update::REPO
    )
}

/// The signed add-on is far smaller than this.
const MAX_ADDON: usize = 5 * 1024 * 1024;

/// Requests and replies are small; anything bigger is refused.
const MAX_MESSAGE: usize = 64 * 1024;

/// How long the helper waits for the app's window thread to answer.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// Most items a search returns.
const MAX_RESULTS: usize = 50;

/// One message from the extension.
#[derive(Debug, Default, Deserialize)]
pub struct Request {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub token: String,
    /// The page the request is about (the extension takes it from the
    /// browser, not from the page).
    #[serde(default)]
    pub url: String,
    /// An item's id.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub browser: String,
    /// Search text.
    #[serde(default)]
    pub query: String,
    /// What to copy: "username", "password", "code", or a card's "number"
    /// or "cvv". For `forms` and `new`: "card" or "identity".
    #[serde(default)]
    pub what: String,
    /// A login the user just used on a page (save / update).
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

impl Drop for Request {
    fn drop(&mut self) {
        self.password.zeroize();
        self.username.zeroize();
    }
}

/// Requests that need an unlocked vault, answered on the window thread.
const VAULT_REQUESTS: [&str; 10] = [
    "logins", "fill", "search", "copy", "generate", "check", "save", "new", "forms", "fillForm",
];

/// Bytes of a JSON reply, wiped when dropped (fill replies hold a password).
pub type Reply = Zeroizing<Vec<u8>>;

pub fn reply(value: &impl Serialize) -> Reply {
    Zeroizing::new(serde_json::to_vec(value).unwrap_or_default())
}

pub fn ok() -> Reply {
    reply(&serde_json::json!({ "ok": true }))
}

pub fn error(code: &str) -> Reply {
    reply(&serde_json::json!({ "error": code }))
}

// --- Framing: a 32-bit little-endian length, then that many bytes of JSON.

pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        r => r?,
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

pub fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)?;
    w.flush()
}

// --- Which logins belong to a page.

/// Whether a login saved for `item_url` may be filled into `page_url`: the
/// same host or a subdomain of it ("example.com" covers
/// "login.example.com"), and no `https` login on a plain `http` page.
pub fn url_matches(item_url: &str, page_url: &str) -> bool {
    let (item, page) = (url_host(item_url), url_host(page_url));
    if item.is_empty() || page.is_empty() {
        return false;
    }
    let page_is_http = page_url.trim().to_ascii_lowercase().starts_with("http://");
    let item_is_http = item_url.trim().to_ascii_lowercase().starts_with("http://");
    if page_is_http && !item_is_http {
        return false;
    }
    page == item
        || page
            .strip_suffix(item.as_str())
            .is_some_and(|p| p.ends_with('.'))
}

fn username(e: &Entry) -> &str {
    e.first_of(FieldKind::Username)
        .or_else(|| e.first_of(FieldKind::Email))
        .unwrap_or("")
}

/// The item has a website matching `page_url`.
fn for_site(e: &Entry, page_url: &str) -> bool {
    e.fields
        .iter()
        .any(|f| f.kind == FieldKind::Url && url_matches(&f.value, page_url))
}

fn fillable(e: &Entry, page_url: &str) -> bool {
    (e.primary_password().is_some() || !username(e).is_empty()) && for_site(e, page_url)
}

fn by_use(a: &&Entry, b: &&Entry) -> std::cmp::Ordering {
    b.last_used.cmp(&a.last_used).then_with(|| {
        a.display_title()
            .to_lowercase()
            .cmp(&b.display_title().to_lowercase())
    })
}

/// The logins for `page_url`, most recently used first.
pub fn logins_for<'a>(entries: &'a [Entry], page_url: &str) -> Vec<&'a Entry> {
    let mut v: Vec<&Entry> = entries.iter().filter(|e| fillable(e, page_url)).collect();
    v.sort_by(by_use);
    v
}

/// What the extension shows of an item: no secrets, only whether it has
/// them.
#[derive(Serialize)]
struct Summary<'a> {
    id: String,
    title: &'a str,
    username: &'a str,
    site: String,
    kind: &'a str,
    password: bool,
    code: bool,
}

fn summary(e: &Entry) -> Summary<'_> {
    Summary {
        id: e.id.to_string(),
        title: e.display_title(),
        username: username(e),
        site: e.first_of(FieldKind::Url).map(url_host).unwrap_or_default(),
        kind: e.kind.label(),
        password: e.primary_password().is_some(),
        code: e.totp_secret().is_some(),
    }
}

/// The reply to a `logins` request: the page's logins, no secrets.
pub fn logins_reply(entries: &[Entry], page_url: &str) -> Reply {
    let logins: Vec<Summary> = logins_for(entries, page_url)
        .into_iter()
        .map(summary)
        .collect();
    reply(&serde_json::json!({ "host": url_host(page_url), "logins": logins }))
}

/// The reply to a `search` request: the best matches for `query` across
/// the vault (the most recently used items for an empty query), no secrets.
pub fn search_reply(entries: &[Entry], query: &str) -> Reply {
    let q = query.trim().to_lowercase();
    let mut found: Vec<(i32, &Entry)> = entries
        .iter()
        .filter_map(|e| e.search_score(&q).map(|s| (s, e)))
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| by_use(&a.1, &b.1)));
    let items: Vec<Summary> = found
        .into_iter()
        .take(MAX_RESULTS)
        .map(|(_, e)| summary(e))
        .collect();
    reply(&serde_json::json!({ "items": items }))
}

fn current_code(e: &Entry, now: i64) -> Option<Zeroizing<String>> {
    e.totp_secret()
        .and_then(|s| crate::totp::Totp::parse(s).ok())
        .map(|t| Zeroizing::new(t.code_at(now)))
}

/// The item a `fill` used, and its current one-time code (copied by the
/// app after filling, as the next page often asks for it).
pub struct Used {
    pub id: u64,
    pub code: Option<Zeroizing<String>>,
}

/// The reply to a `fill` request and the item used. The item must still
/// match the page.
pub fn fill_reply(entries: &[Entry], page_url: &str, id: &str, now: i64) -> (Reply, Option<Used>) {
    #[derive(Serialize)]
    struct Fill<'a> {
        host: String,
        username: &'a str,
        password: &'a str,
        code: &'a str,
    }
    let found = id
        .parse::<u64>()
        .ok()
        .and_then(|id| entries.iter().find(|e| e.id == id))
        .filter(|e| fillable(e, page_url));
    let Some(e) = found else {
        return (error("not_found"), None);
    };
    let code = current_code(e, now);
    let fill = Fill {
        host: url_host(page_url),
        username: username(e),
        password: e.primary_password().unwrap_or(""),
        code: code.as_deref().map_or("", |c| c.as_str()),
    };
    (reply(&fill), Some(Used { id: e.id, code }))
}

/// The value of one of an item's fields for the `copy` request.
pub fn value_to_copy(e: &Entry, what: &str, now: i64) -> Option<Zeroizing<String>> {
    match what {
        "username" => Some(username(e))
            .filter(|u| !u.is_empty())
            .map(|u| Zeroizing::new(u.to_string())),
        "password" => e.primary_password().map(|p| Zeroizing::new(p.to_string())),
        "code" => current_code(e, now),
        "number" => autofill::card(e)
            .map(|c| c.number)
            .filter(|n| !n.is_empty()),
        "cvv" => autofill::card(e)
            .map(|c| Zeroizing::new(c.code.to_string()))
            .filter(|c| !c.is_empty()),
        _ => None,
    }
}

// --- Cards and addresses.

/// The kind of item a `forms` / `fillForm` request is about.
fn form_kind(what: &str) -> Option<EntryKind> {
    match what {
        "card" => Some(EntryKind::CreditCard),
        "identity" => Some(EntryKind::Identity),
        _ => None,
    }
}

/// Card details are only filled into pages that arrived encrypted (and
/// into a developer's own computer).
fn card_page(page_url: &str) -> bool {
    let url = page_url.trim().to_ascii_lowercase();
    let host = url_host(&url);
    url.starts_with("https://")
        || (url.starts_with("http://") && matches!(host.as_str(), "localhost" | "127.0.0.1"))
}

/// The reply to a `forms` request: the vault's cards or identities (`what`
/// is "card" or "identity"), most recently used first, no secrets.
pub fn forms_reply(entries: &[Entry], what: &str) -> Reply {
    #[derive(Serialize)]
    struct Item<'a> {
        id: String,
        title: &'a str,
        kind: &'a str,
        sub: String,
    }
    let Some(kind) = form_kind(what) else {
        return error("bad_request");
    };
    let mut found: Vec<&Entry> = entries.iter().filter(|e| e.kind == kind).collect();
    found.sort_by(by_use);
    let items: Vec<Item> = found
        .into_iter()
        .take(MAX_RESULTS)
        .map(|e| Item {
            id: e.id.to_string(),
            title: e.display_title(),
            kind: what,
            sub: match kind {
                EntryKind::CreditCard => autofill::card_summary(e),
                _ => autofill::identity_summary(e),
            },
        })
        .collect();
    reply(&serde_json::json!({ "items": items }))
}

/// The reply to a `fillForm` request: the details of card or identity
/// `id` for a payment or address form on `page_url`, and the item used.
/// Card details are only sent to `https` pages; identity numbers (passport,
/// tax) are never sent.
pub fn form_fill_reply(entries: &[Entry], page_url: &str, id: &str) -> (Reply, Option<u64>) {
    #[derive(Serialize)]
    struct CardFill<'a> {
        kind: &'a str,
        host: String,
        name: &'a str,
        number: &'a str,
        month: &'a str,
        year: &'a str,
        code: &'a str,
        brand: &'a str,
    }
    #[derive(Serialize)]
    struct IdentityFill<'a> {
        kind: &'a str,
        host: String,
        name: &'a str,
        given: &'a str,
        middle: &'a str,
        family: &'a str,
        email: &'a str,
        phone: &'a str,
        street: &'a [String],
        city: &'a str,
        region: &'a str,
        postcode: &'a str,
        country: &'a str,
    }
    let host = url_host(page_url);
    let found = id
        .parse::<u64>()
        .ok()
        .and_then(|id| entries.iter().find(|e| e.id == id))
        .filter(|_| !host.is_empty());
    let Some(e) = found else {
        return (error("not_found"), None);
    };
    match e.kind {
        EntryKind::CreditCard => {
            if !card_page(page_url) {
                return (error("insecure"), None);
            }
            let Some(c) = autofill::card(e) else {
                return (error("not_found"), None);
            };
            let fill = CardFill {
                kind: "card",
                host,
                name: c.name,
                number: &c.number,
                month: &c.month,
                year: &c.year,
                code: c.code,
                brand: c.brand,
            };
            (reply(&fill), Some(e.id))
        }
        EntryKind::Identity => {
            let Some(i) = autofill::identity(e) else {
                return (error("not_found"), None);
            };
            let fill = IdentityFill {
                kind: "identity",
                host,
                name: &i.name,
                given: &i.given,
                middle: &i.middle,
                family: &i.family,
                email: &i.email,
                phone: &i.phone,
                street: &i.street,
                city: &i.city,
                region: &i.region,
                postcode: &i.postcode,
                country: &i.country,
            };
            (reply(&fill), Some(e.id))
        }
        _ => (error("not_found"), None),
    }
}

/// What to offer after the user signed in on a page with `username` and
/// `password`: "same" (nothing to do), "update" (the login exists with
/// another password) or "new".
pub fn check_reply(entries: &[Entry], page_url: &str, user: &str, password: &str) -> Reply {
    if password.is_empty() || url_host(page_url).is_empty() {
        return reply(&serde_json::json!({ "state": "same" }));
    }
    let site: Vec<&Entry> = entries.iter().filter(|e| for_site(e, page_url)).collect();
    let same_user = |e: &&&Entry| user.is_empty() || username(e).eq_ignore_ascii_case(user.trim());
    if site
        .iter()
        .filter(same_user)
        .any(|e| e.passwords().any(|p| p == password))
    {
        return reply(&serde_json::json!({ "state": "same" }));
    }
    let candidates: Vec<&&Entry> = site
        .iter()
        .filter(|e| {
            if user.is_empty() {
                true
            } else {
                username(e).eq_ignore_ascii_case(user.trim())
            }
        })
        .collect();
    match candidates.as_slice() {
        [e] => reply(&serde_json::json!({
            "state": "update",
            "id": e.id.to_string(),
            "title": e.display_title(),
        })),
        [] => reply(&serde_json::json!({ "state": "new", "site": url_host(page_url) })),
        // Several accounts and no username to tell them apart.
        _ => reply(&serde_json::json!({ "state": "same" })),
    }
}

/// "https://login.example.com/a?b" -> "https://login.example.com".
pub fn origin(url: &str) -> String {
    let url = url.trim();
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
            format!("{}://{}", scheme.to_ascii_lowercase(), host)
        }
        None => url.split(['/', '?', '#']).next().unwrap_or(url).to_string(),
    }
}

/// "accounts.google.com" -> "Google".
pub fn site_title(url: &str) -> String {
    let host = url_host(url);
    let mut c = site_name(&host).chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => host,
    }
}

/// What a `save` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Saved {
    Created(u64),
    Updated(u64),
}

/// Save a login the user just used on `page_url`: update the password of
/// item `id` (which must belong to the site), or add a new login.
pub fn save_login(
    data: &mut VaultData,
    page_url: &str,
    user: &str,
    password: &str,
    id: &str,
) -> Result<Saved, &'static str> {
    if password.is_empty() || password.len() > 4096 || user.len() > 1024 {
        return Err("bad_request");
    }
    if url_host(page_url).is_empty() {
        return Err("bad_request");
    }
    if !id.is_empty() {
        let mut e = id
            .parse::<u64>()
            .ok()
            .and_then(|id| data.entry(id))
            .filter(|e| for_site(e, page_url))
            .cloned()
            .ok_or("not_found")?;
        match e.fields.iter_mut().find(|f| f.kind == FieldKind::Password) {
            Some(f) => f.value = password.to_string(),
            None => e.fields.push(Field::with_value(
                crate::i18n::tr("Password"),
                FieldKind::Password,
                password,
            )),
        }
        if username(&e).is_empty() && !user.trim().is_empty() {
            if let Some(f) = e.fields.iter_mut().find(|f| f.kind == FieldKind::Username) {
                f.value = user.trim().to_string();
            }
        }
        let id = e.id;
        data.upsert(e);
        return Ok(Saved::Updated(id));
    }
    let mut e = Entry::new(EntryKind::Login);
    e.title = site_title(page_url);
    for f in &mut e.fields {
        match f.kind {
            FieldKind::Url => f.value = origin(page_url),
            FieldKind::Username => f.value = user.trim().to_string(),
            FieldKind::Password => f.value = password.to_string(),
            _ => {}
        }
    }
    let id = e.id;
    data.upsert(e);
    Ok(Saved::Created(id))
}

// --- Pairing.

/// What the app keeps of a browser's token.
pub fn token_hash(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The six digits both the app and the extension show while pairing
/// ("123 456"), from the token's hash.
pub fn pairing_code(hash: &str) -> String {
    let byte = |i: usize| u32::from_str_radix(hash.get(i * 2..i * 2 + 2).unwrap_or("0"), 16);
    let n = match (byte(0), byte(1), byte(2)) {
        (Ok(a), Ok(b), Ok(c)) => ((a << 16) | (b << 8) | c) % 1_000_000,
        _ => 0,
    };
    let s = format!("{n:06}");
    format!("{} {}", &s[..3], &s[3..])
}

fn valid_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

// --- The app's side.

/// Work for the app's window thread.
pub enum Job {
    /// A browser asks to be approved.
    Pair { browser: String, hash: String },
    /// Bring the window forward (to unlock it).
    Show,
    /// Lock the vault.
    Lock,
    /// One of [`VAULT_REQUESTS`], answered from the unlocked vault.
    Vault { req: Request, reply: Sender<Reply> },
}

/// State shared between the pipe threads and the app.
pub struct Link {
    pub enabled: AtomicBool,
    /// A vault is unlocked. While it isn't, the pipe threads answer
    /// "locked" themselves (the window may be hidden and get no frames).
    pub unlocked: Arc<AtomicBool>,
    /// Token hashes of the approved browsers.
    pub paired: Mutex<Vec<String>>,
    jobs: Mutex<Sender<Job>>,
    /// Called after each job is queued: brings the window forward if
    /// needed and wakes the window thread.
    wake: Box<dyn Fn(bool) + Send + Sync>,
}

impl Link {
    /// `wake(show)` runs after a job is queued; `show` says the window
    /// should come forward.
    pub fn new(
        unlocked: Arc<AtomicBool>,
        wake: impl Fn(bool) + Send + Sync + 'static,
    ) -> (Arc<Link>, mpsc::Receiver<Job>) {
        let (tx, rx) = mpsc::channel();
        let link = Link {
            enabled: AtomicBool::new(false),
            unlocked,
            paired: Mutex::new(Vec::new()),
            jobs: Mutex::new(tx),
            wake: Box::new(wake),
        };
        (Arc::new(link), rx)
    }

    fn send(&self, job: Job, show: bool) -> bool {
        let sent = self
            .jobs
            .lock()
            .map(|tx| tx.send(job).is_ok())
            .unwrap_or(false);
        if sent {
            (self.wake)(show);
        }
        sent
    }

    /// Answer one request from the extension.
    pub fn answer(&self, req: Request) -> Reply {
        if !self.enabled.load(Ordering::Relaxed) {
            return error("disabled");
        }
        if !valid_token(&req.token) {
            return error("unpaired");
        }
        let hash = token_hash(&req.token);
        let paired = self
            .paired
            .lock()
            .map(|p| p.contains(&hash))
            .unwrap_or(false);
        if req.kind == "pair" {
            if paired {
                return ok();
            }
            let browser: String = req.browser.chars().take(40).collect();
            self.send(Job::Pair { browser, hash }, true);
            return error("unpaired");
        }
        if !paired {
            return error("unpaired");
        }
        let unlocked = self.unlocked.load(Ordering::Relaxed);
        match req.kind.as_str() {
            "status" => reply(&serde_json::json!({
                "state": if unlocked { "unlocked" } else { "locked" },
            })),
            "show" => {
                self.send(Job::Show, true);
                ok()
            }
            "lock" => {
                if unlocked {
                    self.send(Job::Lock, false);
                }
                ok()
            }
            kind if VAULT_REQUESTS.contains(&kind) => {
                if !unlocked {
                    return error("locked");
                }
                // "new" opens the app's editor.
                let show = kind == "new";
                let (tx, rx) = mpsc::channel();
                if !self.send(Job::Vault { req, reply: tx }, show) {
                    return error("no_reply");
                }
                rx.recv_timeout(ANSWER_TIMEOUT)
                    .unwrap_or_else(|_| error("no_reply"))
            }
            _ => error("bad_request"),
        }
    }

    /// Serve one connection from the helper until it closes.
    pub fn serve_client(&self, mut conn: impl Read + Write) {
        while let Ok(Some(msg)) = read_frame(&mut conn) {
            let answer = match serde_json::from_slice::<Request>(&msg) {
                Ok(req) => self.answer(req),
                Err(_) => error("bad_request"),
            };
            if write_frame(&mut conn, &answer).is_err() {
                return;
            }
        }
    }
}

/// Start answering the extension. Returns false if the pipe couldn't be
/// created.
pub fn serve(link: Arc<Link>) -> bool {
    match crate::os_protect::browser_pipe_name() {
        Some(name) => crate::os_protect::serve_pipe(&name, move |conn| link.serve_client(conn)),
        None => false,
    }
}

// --- The helper the browser starts.

/// Whether the program was started by a browser as the extension's helper
/// (Chromium passes the extension's origin, Firefox the add-on's ID).
pub fn is_host_invocation(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|a| a.starts_with("chrome-extension://") || a == FIREFOX_EXTENSION_ID)
}

/// Run as the extension's helper: relay each message from the browser to
/// the running app and its answer back, until the browser closes stdin.
pub fn run_host() {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut pipe = None;
    let name = crate::os_protect::browser_pipe_name();
    while let Ok(Some(msg)) = read_frame(&mut input) {
        let answer = match &name {
            Some(name) => relay(name, &msg, &mut pipe),
            None => error("not_running"),
        };
        if write_frame(&mut output, &answer).is_err() {
            return;
        }
    }
}

fn relay(name: &str, msg: &[u8], pipe: &mut Option<std::fs::File>) -> Reply {
    let kind = serde_json::from_slice::<Request>(msg)
        .map(|r| r.kind.clone())
        .unwrap_or_default();
    if kind == "launch" {
        return if launch_app() {
            ok()
        } else {
            error("not_running")
        };
    }
    // Reconnect once if the app restarted since the last message.
    for _ in 0..2 {
        if pipe.is_none() {
            match crate::os_protect::connect_pipe(name) {
                Ok(p) => *pipe = Some(p),
                Err(_) => return error("not_running"),
            }
        }
        let conn = pipe.as_mut().expect("connected above");
        if write_frame(conn, msg).is_ok() {
            if let Ok(Some(answer)) = read_frame(conn) {
                return answer;
            }
        }
        *pipe = None;
    }
    error("not_running")
}

/// Start the app itself (the user clicked "Start VaultRust").
fn launch_app() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    detached(std::process::Command::new(exe))
}

/// Start a program that outlives the browser that started the helper.
fn detached(mut cmd: std::process::Command) -> bool {
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        // Out of the browser's job, so closing the browser doesn't close
        // VaultRust; not every job allows that, so try without too.
        let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        if cmd
            .creation_flags(base | CREATE_BREAKAWAY_FROM_JOB)
            .spawn()
            .is_ok()
        {
            return true;
        }
        cmd.creation_flags(base);
    }
    cmd.spawn().is_ok()
}

// --- Setting up the browsers.

/// A browser the extension works in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Browser {
    /// As shown, and as the extension reports itself when pairing.
    pub name: &'static str,
    exe: &'static str,
    /// Its extensions page.
    pub extensions_page: &'static str,
    /// Where it looks for native messaging hosts (under HKEY_CURRENT_USER).
    registry: &'static str,
    /// Install folders under Program Files / Local AppData.
    folder: &'static str,
    /// Firefox: its helper manifest, and how the extension is added, differ.
    pub firefox: bool,
}

pub const BROWSERS: [Browser; 4] = [
    Browser {
        name: "Chrome",
        exe: "chrome.exe",
        extensions_page: "chrome://extensions",
        registry: r"Software\Google\Chrome\NativeMessagingHosts",
        folder: r"Google\Chrome\Application",
        firefox: false,
    },
    Browser {
        name: "Edge",
        exe: "msedge.exe",
        extensions_page: "edge://extensions",
        registry: r"Software\Microsoft\Edge\NativeMessagingHosts",
        folder: r"Microsoft\Edge\Application",
        firefox: false,
    },
    Browser {
        name: "Brave",
        exe: "brave.exe",
        extensions_page: "brave://extensions",
        registry: r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
        folder: r"BraveSoftware\Brave-Browser\Application",
        firefox: false,
    },
    Browser {
        name: "Firefox",
        exe: "firefox.exe",
        extensions_page: "about:addons",
        registry: r"Software\Mozilla\NativeMessagingHosts",
        folder: "Mozilla Firefox",
        firefox: true,
    },
];

/// Chromium builds read their own key.
const CHROMIUM_KEY: &str = r"Software\Chromium\NativeMessagingHosts";

impl Browser {
    /// The browser's program, if it is installed.
    pub fn program(&self) -> Option<PathBuf> {
        if let Some(p) = crate::os_protect::app_path(self.exe).filter(|p| p.is_file()) {
            return Some(p);
        }
        ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"]
            .iter()
            .filter_map(std::env::var_os)
            .map(|base| PathBuf::from(base).join(self.folder).join(self.exe))
            .find(|p| p.is_file())
    }

    /// Whether `name` (what a paired extension called its browser, e.g.
    /// "Microsoft Edge") is this browser.
    pub fn is(&self, name: &str) -> bool {
        name.to_ascii_lowercase()
            .contains(&self.name.to_ascii_lowercase())
    }

    /// Open a local page in the browser. (Browsers ignore their own
    /// `chrome://` pages when another program asks, so the extensions page
    /// can't be opened directly.)
    pub fn open(&self, page: &std::path::Path) -> bool {
        match self.program() {
            Some(exe) => {
                let mut cmd = std::process::Command::new(exe);
                cmd.arg(page);
                detached(cmd)
            }
            None => false,
        }
    }
}

/// Where the page with the steps for adding the extension is written.
pub fn setup_page_path() -> Option<PathBuf> {
    Some(data_dir()?.join("Add VaultRust to your browser.html"))
}

/// Text made safe to put in HTML.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Show the extension's folder selected in File Explorer, ready to be
/// dragged onto a browser's extensions page.
pub fn show_extension_folder() -> bool {
    let Some(dir) = extension_dir() else {
        return false;
    };
    let mut cmd = std::process::Command::new("explorer.exe");
    cmd.arg(format!("/select,{}", dir.display()));
    cmd.spawn().is_ok()
}

macro_rules! extension_files {
    ($($path:literal),* $(,)?) => {
        &[$(($path, include_bytes!(concat!("../browser-extension/", $path)))),*]
    };
}

/// The extension, built into the program so it can be set up anywhere and
/// stays in step with updates.
const EXTENSION_FILES: &[(&str, &[u8])] = extension_files![
    "manifest.json",
    "background.js",
    "content.js",
    "shared.js",
    "ui.css",
    "popup.html",
    "popup.js",
    "menu.html",
    "menu.js",
    "bar.html",
    "bar.js",
    "_locales/en/messages.json",
    "_locales/el/messages.json",
    "icons/icon-16.png",
    "icons/icon-32.png",
    "icons/icon-48.png",
    "icons/icon-128.png",
];

/// Files of older versions of the extension, removed when it is updated.
const OLD_EXTENSION_FILES: &[&str] = &["vaultrust.js", "popup.css"];

/// `%LOCALAPPDATA%\VaultRust`.
fn data_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("XDG_DATA_HOME"))
        .map(|d| PathBuf::from(d).join("VaultRust"))
}

/// The folder the user loads the extension from.
pub fn extension_dir() -> Option<PathBuf> {
    Some(data_dir()?.join("Browser extension"))
}

/// Firefox and Chromium each want their own host manifest.
fn host_manifest_path(firefox: bool) -> Option<PathBuf> {
    let name = if firefox {
        format!("{HOST_NAME}.firefox.json")
    } else {
        format!("{HOST_NAME}.json")
    };
    Some(data_dir()?.join(name))
}

/// The host manifest pointing the browsers (Chromium ones, or Firefox) at
/// `exe`.
pub fn host_manifest(exe: &std::path::Path, firefox: bool) -> String {
    let mut m = serde_json::json!({
        "name": HOST_NAME,
        "description": "VaultRust",
        "path": exe,
        "type": "stdio",
    });
    if firefox {
        m["allowed_extensions"] = serde_json::json!([FIREFOX_EXTENSION_ID]);
    } else {
        let origins: Vec<String> = ALLOWED_EXTENSIONS
            .iter()
            .map(|id| format!("chrome-extension://{id}/"))
            .collect();
        m["allowed_origins"] = origins.into();
    }
    serde_json::to_string_pretty(&m).unwrap_or_default()
}

/// Each registry key, and whether it is Firefox's.
fn registry_keys() -> impl Iterator<Item = (String, bool)> {
    BROWSERS
        .iter()
        .map(|b| (b.registry, b.firefox))
        .chain([(CHROMIUM_KEY, false)])
        .map(|(k, firefox)| (format!(r"{k}\{HOST_NAME}"), firefox))
}

/// Write the extension's files and register this program as its helper
/// with every Chromium browser and Firefox. Safe to repeat (it is, at every start, so a
/// moved or updated program stays registered). Returns the extension folder.
pub fn install() -> Result<PathBuf, String> {
    let failed = |e: io::Error| crate::trf!("Couldn't set up the browser extension: {e}", e);
    let no_dir = || crate::i18n::tr("No folder for app data").to_string();
    let dir = extension_dir().ok_or_else(no_dir)?;
    for (name, data) in EXTENSION_FILES {
        let path = dir.join(name);
        if std::fs::read(&path).is_ok_and(|old| old == *data) {
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(failed)?;
        }
        std::fs::write(&path, data).map_err(failed)?;
    }
    for old in OLD_EXTENSION_FILES {
        let _ = std::fs::remove_file(dir.join(old));
    }
    let exe = std::env::current_exe().map_err(failed)?;
    for firefox in [false, true] {
        let manifest = host_manifest_path(firefox).ok_or_else(no_dir)?;
        std::fs::write(&manifest, host_manifest(&exe, firefox)).map_err(failed)?;
    }
    for (key, firefox) in registry_keys() {
        let manifest = host_manifest_path(firefox).ok_or_else(no_dir)?;
        crate::os_protect::set_user_registry_default(&key, Some(&manifest.to_string_lossy()))?;
    }
    Ok(dir)
}

/// Unregister the helper (the extension then reports that VaultRust isn't
/// set up). The extension's folder is left for the browser to keep using
/// until the user removes it there.
pub fn uninstall() -> Result<(), String> {
    for (key, _) in registry_keys() {
        crate::os_protect::set_user_registry_default(&key, None)?;
    }
    for m in [false, true].into_iter().filter_map(host_manifest_path) {
        let _ = std::fs::remove_file(m);
    }
    Ok(())
}

/// Download the signed add-on and open it in Firefox, which asks whether to
/// add it. Blocks on the network, so run it off the window thread.
pub fn add_to_firefox(firefox: &Browser) -> Result<(), String> {
    let data =
        crate::os_protect::http_get(&firefox_addon_url(), MAX_ADDON).map_err(|e| e.to_string())?;
    // An .xpi is a zip file; anything else is an error page.
    if !data.starts_with(b"PK") {
        return Err(crate::i18n::tr("The download isn't a Firefox add-on").to_string());
    }
    let path = data_dir()
        .ok_or_else(|| crate::i18n::tr("No folder for app data").to_string())?
        .join("VaultRust-Firefox.xpi");
    std::fs::write(&path, data).map_err(|e| e.to_string())?;
    if firefox.open(&path) {
        Ok(())
    } else {
        let name = firefox.name;
        Err(crate::trf!("Couldn't open {name}", name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(id: u64, url: &str, user: &str, pw: &str) -> Entry {
        let mut e = Entry::new(EntryKind::Login);
        e.id = id;
        e.title = format!("Item {id}");
        e.fields[0].value = url.into();
        e.fields[1].value = user.into();
        e.fields[3].value = pw.into();
        e
    }

    fn json(r: &[u8]) -> serde_json::Value {
        serde_json::from_slice(r).unwrap()
    }

    #[test]
    fn sites_match_hosts_and_subdomains_only() {
        assert!(url_matches(
            "https://example.com",
            "https://example.com/login"
        ));
        assert!(url_matches("example.com", "https://accounts.example.com/"));
        assert!(url_matches(
            "https://www.example.com",
            "https://example.com"
        ));
        assert!(!url_matches(
            "https://login.example.com",
            "https://example.com"
        ));
        assert!(!url_matches(
            "https://example.com",
            "https://notexample.com"
        ));
        assert!(!url_matches(
            "https://example.com",
            "https://example.com.evil.net"
        ));
        // Never an https login on a plain http page.
        assert!(!url_matches("https://example.com", "http://example.com"));
        assert!(!url_matches("example.com", "http://example.com"));
        assert!(url_matches(
            "http://router.local",
            "http://router.local/admin"
        ));
        assert!(!url_matches("", "https://example.com"));
    }

    #[test]
    fn replies_list_matching_logins_and_fill_only_those() {
        let mut a = login(1, "https://github.com", "ann", "pw-a");
        a.last_used = 5;
        let b = login(2, "https://github.com", "bob", "pw-b");
        let other = login(3, "https://gitlab.com", "cat", "pw-c");
        let mut otp = login(4, "https://github.com", "dan", "pw-d");
        otp.fields.push(Field::with_value(
            "One-time code",
            FieldKind::Totp,
            "JBSWY3DPEHPK3PXP",
        ));
        otp.last_used = 9;
        let entries = vec![a, b, other, otp];

        let list = json(&logins_reply(&entries, "https://github.com/login"));
        assert_eq!(list["host"], "github.com");
        let ids: Vec<&str> = list["logins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["4", "1", "2"], "most recently used first");
        assert_eq!(list["logins"][0]["code"], true);
        assert!(
            !String::from_utf8_lossy(&logins_reply(&entries, "https://github.com")).contains("pw-")
        );

        let (r, used) = fill_reply(&entries, "https://github.com/login", "1", 0);
        let r = json(&r);
        assert_eq!(
            (r["username"].as_str(), r["password"].as_str()),
            (Some("ann"), Some("pw-a"))
        );
        assert_eq!(used.map(|u| u.id), Some(1));
        // An item of another site can't be asked for by id.
        let (r, used) = fill_reply(&entries, "https://github.com/login", "3", 0);
        assert_eq!(&*r, &*error("not_found"));
        assert!(used.is_none());
        let (r, used) = fill_reply(&entries, "https://github.com", "4", 59);
        assert_eq!(json(&r)["code"].as_str().unwrap().len(), 6);
        assert_eq!(used.unwrap().code.unwrap().len(), 6);
    }

    #[test]
    fn cards_and_identities_fill_forms() {
        let set = |e: &mut Entry, label: &str, value: &str| {
            e.fields
                .iter_mut()
                .find(|f| f.label == label)
                .unwrap()
                .value = value.into();
        };
        let mut card = Entry::new(EntryKind::CreditCard);
        card.id = 1;
        card.title = "Everyday card".into();
        set(&mut card, "Card number", "4242 4242 4242 4242");
        set(&mut card, "Expiry (MM/YY)", "08/27");
        set(&mut card, "Security code (CVV)", "123");
        set(&mut card, "PIN", "9999");
        let mut person = Entry::new(EntryKind::Identity);
        person.id = 2;
        person.title = "Me".into();
        set(&mut person, "Full name", "Jane Public");
        set(&mut person, "Address", "Ερμού 12");
        set(&mut person, "City", "Αθήνα");
        set(&mut person, "ID / passport number", "AB123456");
        let entries = vec![card, person, login(3, "https://shop.example", "u", "pw")];

        // Lists carry no secrets.
        let list = forms_reply(&entries, "card");
        let text = String::from_utf8(list.to_vec()).unwrap();
        assert!(text.contains("Visa •••• 4242 · 08/27"), "{text}");
        assert!(!text.contains("4242424242424242") && !text.contains("123"));
        let items = json(&list)["items"].as_array().unwrap().len();
        assert_eq!(items, 1);
        let ids = json(&forms_reply(&entries, "identity"));
        assert_eq!(ids["items"][0]["sub"], "Jane Public · Αθήνα");
        assert_eq!(
            json(&forms_reply(&entries, "login"))["error"],
            "bad_request"
        );

        let (r, used) = form_fill_reply(&entries, "https://shop.example/pay", "1");
        let r = json(&r);
        assert_eq!(used, Some(1));
        assert_eq!(r["number"], "4242424242424242");
        assert_eq!(
            (r["month"].as_str(), r["year"].as_str()),
            (Some("08"), Some("2027"))
        );
        assert_eq!(
            (r["code"].as_str(), r["brand"].as_str()),
            (Some("123"), Some("visa"))
        );
        assert_eq!(r["host"], "shop.example");
        assert!(r.get("pin").is_none());

        // Never to an unencrypted page.
        let (r, used) = form_fill_reply(&entries, "http://shop.example/pay", "1");
        assert_eq!((json(&r)["error"].as_str(), used), (Some("insecure"), None));
        assert!(form_fill_reply(&entries, "http://localhost:3000/", "1")
            .1
            .is_some());

        let (r, _) = form_fill_reply(&entries, "http://shop.example/address", "2");
        let text = String::from_utf8(r.to_vec()).unwrap();
        let r = json(&r);
        assert_eq!(
            (r["given"].as_str(), r["family"].as_str()),
            (Some("Jane"), Some("Public"))
        );
        assert_eq!(r["street"][0], "Ερμού 12");
        assert_eq!(r["city"], "Αθήνα");
        assert!(!text.contains("AB123456"));

        // Logins aren't forms, and the id must exist.
        assert_eq!(
            json(&form_fill_reply(&entries, "https://shop.example", "3").0)["error"],
            "not_found"
        );
        assert_eq!(
            json(&form_fill_reply(&entries, "https://shop.example", "9").0)["error"],
            "not_found"
        );
        let c = value_to_copy(&entries[0], "number", 0).unwrap();
        assert_eq!(c.as_str(), "4242424242424242");
        assert_eq!(
            value_to_copy(&entries[0], "cvv", 0).unwrap().as_str(),
            "123"
        );
        assert!(value_to_copy(&entries[1], "number", 0).is_none());
    }

    #[test]
    fn search_finds_any_item_without_secrets() {
        let entries = vec![
            login(1, "https://github.com", "ann", "pw-a"),
            login(2, "https://bank.example", "bob", "pw-b"),
        ];
        let r = json(&search_reply(&entries, "bank"));
        assert_eq!(r["items"].as_array().unwrap().len(), 1);
        assert_eq!(r["items"][0]["site"], "bank.example");
        assert_eq!(r["items"][0]["password"], true);
        let all = search_reply(&entries, "");
        assert_eq!(json(&all)["items"].as_array().unwrap().len(), 2);
        assert!(!String::from_utf8_lossy(&all).contains("pw-"));
        let e = &entries[0];
        assert_eq!(
            value_to_copy(e, "password", 0)
                .as_deref()
                .map(|s| s.as_str()),
            Some("pw-a")
        );
        assert_eq!(
            value_to_copy(e, "username", 0)
                .as_deref()
                .map(|s| s.as_str()),
            Some("ann")
        );
        assert!(value_to_copy(e, "code", 0).is_none());
        assert!(value_to_copy(e, "notes", 0).is_none());
    }

    #[test]
    fn signing_in_offers_to_save_or_update_only_when_needed() {
        let entries = vec![
            login(1, "https://example.com", "ann", "old"),
            login(2, "https://other.net", "ann", "x"),
        ];
        let state = |user: &str, pw: &str| {
            json(&check_reply(
                &entries,
                "https://example.com/login",
                user,
                pw,
            ))["state"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(state("ann", "old"), "same");
        assert_eq!(state("ANN", "new"), "update");
        assert_eq!(state("", "new"), "update", "the only login of the site");
        assert_eq!(state("bob", "pw"), "new");
        assert_eq!(state("ann", ""), "same", "nothing to save");

        let mut data = VaultData::new("t");
        for e in entries {
            data.upsert(e);
        }
        let url = "https://login.example.com/signin?next=/";
        let Saved::Created(id) = save_login(&mut data, url, "bob", "pw1", "").unwrap() else {
            panic!("expected a new login");
        };
        let e = data.entry(id).unwrap();
        assert_eq!(e.title, "Example");
        assert_eq!(
            e.first_of(FieldKind::Url),
            Some("https://login.example.com")
        );
        assert_eq!(e.first_of(FieldKind::Username), Some("bob"));
        assert_eq!(e.primary_password(), Some("pw1"));

        assert_eq!(
            save_login(&mut data, url, "ann", "new", "1"),
            Ok(Saved::Updated(1))
        );
        let e = data.entry(1).unwrap();
        assert_eq!(e.primary_password(), Some("new"));
        assert_eq!(e.history[0].value, "old");
        // An item of another site can't be changed from this page.
        assert_eq!(
            save_login(&mut data, url, "ann", "z", "2"),
            Err("not_found")
        );
        assert_eq!(
            save_login(&mut data, url, "ann", "", ""),
            Err("bad_request")
        );
    }

    #[test]
    fn pairing_codes_match_the_extension() {
        // The extension computes the same code from the same token (see
        // pairingCode in browser-extension/shared.js).
        let hash = token_hash("00".repeat(32).as_str());
        assert_eq!(hash.len(), 64);
        let n = u32::from_str_radix(&hash[..6], 16).unwrap() % 1_000_000;
        let code = pairing_code(&hash);
        assert_eq!(code.replace(' ', ""), format!("{n:06}"));
        assert_eq!(code.len(), 7);
    }

    #[test]
    fn the_link_answers_only_approved_browsers_while_unlocked() {
        let unlocked = Arc::new(AtomicBool::new(false));
        let shown = Arc::new(AtomicBool::new(false));
        let s = shown.clone();
        let (link, jobs) = Link::new(unlocked.clone(), move |show| {
            if show {
                s.store(true, Ordering::Relaxed);
            }
        });
        let token = "ab".repeat(32);
        let req = |kind: &str| {
            let mut r = Request::default();
            r.kind = kind.into();
            r.token = token.clone();
            r.url = "https://example.com".into();
            r.browser = "Edge".into();
            r
        };
        let code = |r: Reply| json(&r)["error"].as_str().map(str::to_string);
        assert_eq!(
            code(link.answer(req("logins"))).as_deref(),
            Some("disabled")
        );
        link.enabled.store(true, Ordering::Relaxed);
        assert_eq!(
            code(link.answer(req("logins"))).as_deref(),
            Some("unpaired")
        );

        // Asking to pair queues the question and brings the window forward.
        assert_eq!(code(link.answer(req("pair"))).as_deref(), Some("unpaired"));
        assert!(shown.load(Ordering::Relaxed));
        let Ok(Job::Pair { browser, hash }) = jobs.try_recv() else {
            panic!("expected a pairing request");
        };
        assert_eq!(
            (browser.as_str(), hash.clone()),
            ("Edge", token_hash(&token))
        );
        link.paired.lock().unwrap().push(hash);

        assert_eq!(code(link.answer(req("logins"))).as_deref(), Some("locked"));
        assert_eq!(json(&link.answer(req("status")))["state"], "locked");
        unlocked.store(true, Ordering::Relaxed);
        assert_eq!(json(&link.answer(req("status")))["state"], "unlocked");
        // The window thread answers.
        let answering = std::thread::spawn(move || {
            if let Ok(Job::Vault { req, reply }) = jobs.recv() {
                let entries = [login(1, "https://example.com", "u", "p")];
                let _ = reply.send(logins_reply(&entries, &req.url));
            }
        });
        let r = json(&link.answer(req("logins")));
        assert_eq!(r["logins"][0]["username"], "u");
        answering.join().unwrap();
        assert_eq!(
            code(link.answer(req("nonsense"))).as_deref(),
            Some("bad_request")
        );

        let mut stranger = req("fill");
        stranger.token = "cd".repeat(32);
        assert_eq!(code(link.answer(stranger)).as_deref(), Some("unpaired"));
    }

    #[cfg(windows)]
    #[test]
    fn the_helper_relays_to_the_app_and_reports_when_it_is_gone() {
        let name = format!(r"\\.\pipe\VaultRust-relay-test-{}", std::process::id());
        let mut pipe = None;
        let msg = br#"{"type":"logins","token":"x"}"#;
        assert_eq!(&*relay(&name, msg, &mut pipe), &*error("not_running"));
        let (link, _jobs) = Link::new(Arc::new(AtomicBool::new(true)), |_| {});
        link.enabled.store(true, Ordering::Relaxed);
        let served = link.clone();
        assert!(crate::os_protect::serve_pipe(&name, move |c| served.serve_client(c)));
        // An unknown browser is told to pair, over the same connection
        // each time.
        for _ in 0..2 {
            assert_eq!(&*relay(&name, msg, &mut pipe), &*error("unpaired"));
        }
        assert!(pipe.is_some());
        let junk = relay(&name, b"not json", &mut pipe);
        assert_eq!(&*junk, &*error("bad_request"));
    }

    #[test]
    fn frames_round_trip_and_refuse_huge_messages() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"type\":\"logins\"}").unwrap();
        let mut r = &buf[..];
        assert_eq!(
            &**read_frame(&mut r).unwrap().unwrap(),
            b"{\"type\":\"logins\"}"
        );
        assert!(read_frame(&mut r).unwrap().is_none());
        let huge = ((MAX_MESSAGE + 1) as u32).to_le_bytes();
        assert!(read_frame(&mut &huge[..]).is_err());
        assert!(is_host_invocation(&[
            "vaultrust.exe".into(),
            format!("chrome-extension://{EXTENSION_ID}/"),
        ]));
        // Firefox passes the host manifest's path and the add-on's ID.
        assert!(is_host_invocation(&[
            "vaultrust.exe".into(),
            r"C:\Users\you\AppData\Local\VaultRust\com.vaultrust.browser.firefox.json".into(),
            FIREFOX_EXTENSION_ID.into(),
        ]));
        assert!(!is_host_invocation(&[
            "vaultrust.exe".into(),
            "--startup".into()
        ]));
    }

    #[test]
    fn origins_titles_and_browsers() {
        assert_eq!(
            origin("HTTPS://a.example.com:8443/x?y#z"),
            "https://a.example.com:8443"
        );
        assert_eq!(site_title("https://accounts.google.com/"), "Google");
        assert!(BROWSERS[1].is("Microsoft Edge"));
        assert!(!BROWSERS[0].is("Microsoft Edge"));
        let firefox: Vec<_> = BROWSERS.iter().filter(|b| b.firefox).collect();
        assert_eq!(firefox.len(), 1);
        assert!(firefox[0].is("Firefox"));
    }

    /// Every message the extension shows exists in English and Greek.
    #[test]
    fn extension_messages_are_translated() {
        let locale = |lang: &str| -> serde_json::Value {
            let path = format!("_locales/{lang}/messages.json");
            let (_, data) = EXTENSION_FILES.iter().find(|(n, _)| *n == path).unwrap();
            serde_json::from_slice(data).unwrap()
        };
        let (en, el) = (locale("en"), locale("el"));
        let mut keys: Vec<String> = Vec::new();
        for (name, data) in EXTENSION_FILES {
            let text = String::from_utf8_lossy(data);
            if name.ends_with(".js") {
                let parts: Vec<&str> = text.split("t(\"").collect();
                for (before, part) in parts.iter().zip(&parts[1..]) {
                    // Only `t("…")` itself, not `get("…")`.
                    if before.ends_with(|c: char| c.is_alphanumeric() || c == '_' || c == '.') {
                        continue;
                    }
                    keys.push(part.split('"').next().unwrap().to_string());
                }
            }
            for part in text.split("__MSG_").skip(1) {
                keys.push(part.split("__").next().unwrap().to_string());
            }
        }
        assert!(keys.len() > 40);
        for key in &keys {
            assert!(en[key]["message"].is_string(), "{key} missing in English");
            assert!(el[key]["message"].is_string(), "{key} missing in Greek");
        }
        for (key, value) in en.as_object().unwrap() {
            let holes = |v: &serde_json::Value| v["placeholders"].as_object().map(|p| p.len());
            assert_eq!(
                holes(value),
                holes(&el[key]),
                "placeholders differ for {key}"
            );
        }
    }

    #[test]
    fn host_manifest_allows_only_the_extension() {
        let exe = std::path::Path::new(r"C:\Apps\VaultRust.exe");
        let m: serde_json::Value = serde_json::from_str(&host_manifest(exe, false)).unwrap();
        assert_eq!(m["name"], HOST_NAME);
        assert_eq!(m["path"], r"C:\Apps\VaultRust.exe");
        assert_eq!(
            m["allowed_origins"][0],
            format!("chrome-extension://{EXTENSION_ID}/")
        );
        assert!(m.get("allowed_extensions").is_none());
        let m: serde_json::Value = serde_json::from_str(&host_manifest(exe, true)).unwrap();
        assert_eq!(m["name"], HOST_NAME);
        assert_eq!(
            m["allowed_extensions"],
            serde_json::json!([FIREFOX_EXTENSION_ID])
        );
        assert!(m.get("allowed_origins").is_none());
        // The built-in copy of the extension has the key that gives it this
        // ID in Chromium, and the add-on ID Firefox knows it by.
        let manifest: serde_json::Value = serde_json::from_slice(EXTENSION_FILES[0].1).unwrap();
        assert_eq!(
            manifest["browser_specific_settings"]["gecko"]["id"],
            FIREFOX_EXTENSION_ID
        );
        let key = manifest["key"].as_str().unwrap();
        let der = crate::encoding::base64_decode(key).unwrap();
        let id: String = Sha256::digest(&der[..])[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 15])
            .map(|n| (b'a' + n) as char)
            .collect();
        assert_eq!(id, EXTENSION_ID);
        // Every file the manifest and pages refer to is built in.
        let names: Vec<&str> = EXTENSION_FILES.iter().map(|(n, _)| *n).collect();
        for (_, data) in EXTENSION_FILES {
            let text = String::from_utf8_lossy(data);
            for name in [
                "content.js",
                "menu.html",
                "bar.html",
                "popup.html",
                "shared.js",
                "ui.css",
            ] {
                if text.contains(name) {
                    assert!(names.contains(&name), "{name} is missing");
                }
            }
        }
    }
}
