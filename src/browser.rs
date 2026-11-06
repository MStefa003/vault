//! The browser extension (`browser-extension/`): it fills in the login for
//! the site in the current tab.
//!
//! The browser starts `VaultRust.exe` as a *native messaging host*
//! (`run_host`) and talks to it over stdin/stdout. That helper only relays
//! each message over a named pipe (`os_protect::serve_pipe`, open to the
//! current user only) to the running app, which answers:
//!
//! * only while browser filling is turned on in its settings;
//! * only to browsers the user approved once in the app (each sends a random
//!   token; the app keeps its SHA-256 in the preferences);
//! * only while a vault is unlocked;
//! * with the logins whose website matches the tab's site (subdomains
//!   included; never an `https` login for an `http` page).
//!
//! The extension can't ask for anything else (no search, no other items),
//! and it keeps nothing but its token.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::autotype::url_host;
use crate::model::{Entry, FieldKind};

/// The native messaging host's name, as the extension knows it.
pub const HOST_NAME: &str = "com.vaultrust.browser";

/// The extension's ID, fixed by the public key in its manifest.
pub const EXTENSION_ID: &str = "kbbgmknjmnadcnmfllepkafdammfomco";

/// Requests and replies are small; anything bigger is refused.
const MAX_MESSAGE: usize = 64 * 1024;

/// How long the helper waits for the app's window thread to answer.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// One message from the extension.
#[derive(Debug, Default, Deserialize)]
pub struct Request {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub browser: String,
}

/// Bytes of a JSON reply, wiped when dropped (fill replies hold a password).
pub type Reply = Zeroizing<Vec<u8>>;

fn reply(value: &impl Serialize) -> Reply {
    Zeroizing::new(serde_json::to_vec(value).unwrap_or_default())
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

fn fillable(e: &Entry, page_url: &str) -> bool {
    (e.primary_password().is_some() || !username(e).is_empty())
        && e.fields
            .iter()
            .any(|f| f.kind == FieldKind::Url && url_matches(&f.value, page_url))
}

/// The logins for `page_url`, most recently used first.
pub fn logins_for<'a>(entries: &'a [Entry], page_url: &str) -> Vec<&'a Entry> {
    let mut v: Vec<&Entry> = entries.iter().filter(|e| fillable(e, page_url)).collect();
    v.sort_by(|a, b| {
        b.last_used.cmp(&a.last_used).then_with(|| {
            a.display_title()
                .to_lowercase()
                .cmp(&b.display_title().to_lowercase())
        })
    });
    v
}

/// The reply to a `logins` request: titles and usernames, no secrets.
pub fn logins_reply(entries: &[Entry], page_url: &str) -> Reply {
    #[derive(Serialize)]
    struct Login<'a> {
        id: String,
        title: &'a str,
        username: &'a str,
    }
    let logins: Vec<Login> = logins_for(entries, page_url)
        .into_iter()
        .map(|e| Login {
            id: e.id.to_string(),
            title: e.display_title(),
            username: username(e),
        })
        .collect();
    reply(&serde_json::json!({ "host": url_host(page_url), "logins": logins }))
}

/// The reply to a `fill` request, and the id of the item used. The item
/// must still match the page.
pub fn fill_reply(entries: &[Entry], page_url: &str, id: &str, now: i64) -> (Reply, Option<u64>) {
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
    let code = Zeroizing::new(
        e.totp_secret()
            .and_then(|s| crate::totp::Totp::parse(s).ok())
            .map(|t| t.code_at(now))
            .unwrap_or_default(),
    );
    let fill = Fill {
        host: url_host(page_url),
        username: username(e),
        password: e.primary_password().unwrap_or(""),
        code: &code,
    };
    (reply(&fill), Some(e.id))
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
    Pair {
        browser: String,
        hash: String,
    },
    /// Bring the window forward (to unlock it).
    Show,
    Logins {
        url: String,
        reply: Sender<Reply>,
    },
    Fill {
        url: String,
        id: String,
        reply: Sender<Reply>,
    },
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

    fn ask(&self, make: impl FnOnce(Sender<Reply>) -> Job) -> Reply {
        let (tx, rx) = mpsc::channel();
        if !self.send(make(tx), false) {
            return error("no_reply");
        }
        rx.recv_timeout(ANSWER_TIMEOUT)
            .unwrap_or_else(|_| error("no_reply"))
    }

    /// Answer one request from the extension.
    pub fn answer(&self, req: &Request) -> Reply {
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
                return reply(&serde_json::json!({ "ok": true }));
            }
            let browser: String = req.browser.chars().take(40).collect();
            self.send(Job::Pair { browser, hash }, true);
            return error("unpaired");
        }
        if !paired {
            return error("unpaired");
        }
        if req.kind == "show" {
            self.send(Job::Show, true);
            return reply(&serde_json::json!({ "ok": true }));
        }
        if !self.unlocked.load(Ordering::Relaxed) {
            return error("locked");
        }
        let url = req.url.chars().take(4096).collect::<String>();
        match req.kind.as_str() {
            "logins" => self.ask(|reply| Job::Logins { url, reply }),
            "fill" => self.ask(|reply| Job::Fill {
                url,
                id: req.id.clone(),
                reply,
            }),
            _ => error("bad_request"),
        }
    }

    /// Serve one connection from the helper until it closes.
    pub fn serve_client(&self, mut conn: impl Read + Write) {
        while let Ok(Some(msg)) = read_frame(&mut conn) {
            let answer = match serde_json::from_slice::<Request>(&msg) {
                Ok(req) => self.answer(&req),
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
/// (Chromium passes the extension's origin).
pub fn is_host_invocation(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|a| a.starts_with("chrome-extension://"))
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
        .map(|r| r.kind)
        .unwrap_or_default();
    if kind == "launch" {
        return if launch_app() {
            reply(&serde_json::json!({ "ok": true }))
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
    let mut cmd = std::process::Command::new(exe);
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

/// Where each Chromium browser looks for native messaging hosts (under
/// HKEY_CURRENT_USER).
const BROWSER_KEYS: [&str; 4] = [
    r"Software\Google\Chrome\NativeMessagingHosts",
    r"Software\Microsoft\Edge\NativeMessagingHosts",
    r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
    r"Software\Chromium\NativeMessagingHosts",
];

/// The extension, built into the program so it can be set up anywhere and
/// stays in step with updates.
const EXTENSION_FILES: &[(&str, &[u8])] = &[
    (
        "manifest.json",
        include_bytes!("../browser-extension/manifest.json"),
    ),
    (
        "background.js",
        include_bytes!("../browser-extension/background.js"),
    ),
    (
        "vaultrust.js",
        include_bytes!("../browser-extension/vaultrust.js"),
    ),
    (
        "popup.html",
        include_bytes!("../browser-extension/popup.html"),
    ),
    (
        "popup.css",
        include_bytes!("../browser-extension/popup.css"),
    ),
    ("popup.js", include_bytes!("../browser-extension/popup.js")),
    (
        "_locales/en/messages.json",
        include_bytes!("../browser-extension/_locales/en/messages.json"),
    ),
    (
        "_locales/el/messages.json",
        include_bytes!("../browser-extension/_locales/el/messages.json"),
    ),
    (
        "icons/icon-16.png",
        include_bytes!("../browser-extension/icons/icon-16.png"),
    ),
    (
        "icons/icon-32.png",
        include_bytes!("../browser-extension/icons/icon-32.png"),
    ),
    (
        "icons/icon-48.png",
        include_bytes!("../browser-extension/icons/icon-48.png"),
    ),
    (
        "icons/icon-128.png",
        include_bytes!("../browser-extension/icons/icon-128.png"),
    ),
];

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

fn host_manifest_path() -> Option<PathBuf> {
    Some(data_dir()?.join(format!("{HOST_NAME}.json")))
}

/// The host manifest pointing the browsers at `exe`.
pub fn host_manifest(exe: &std::path::Path) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "name": HOST_NAME,
        "description": "VaultRust",
        "path": exe,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    }))
    .unwrap_or_default()
}

/// Write the extension's files and register this program as its helper
/// with every Chromium browser. Safe to repeat (it is, at every start, so a
/// moved or updated program stays registered). Returns the extension folder.
pub fn install() -> Result<PathBuf, String> {
    let failed = |e: io::Error| crate::trf!("Couldn't set up the browser extension: {e}", e);
    let dir =
        extension_dir().ok_or_else(|| crate::i18n::tr("No folder for app data").to_string())?;
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
    let exe = std::env::current_exe().map_err(failed)?;
    let manifest = host_manifest_path()
        .ok_or_else(|| crate::i18n::tr("No folder for app data").to_string())?;
    std::fs::write(&manifest, host_manifest(&exe)).map_err(failed)?;
    let manifest = manifest.to_string_lossy();
    for key in BROWSER_KEYS {
        crate::os_protect::set_user_registry_default(
            &format!(r"{key}\{HOST_NAME}"),
            Some(&manifest),
        )?;
    }
    Ok(dir)
}

/// Unregister the helper (the extension then reports that VaultRust isn't
/// set up). The extension's folder is left for the browser to keep using
/// until the user removes it there.
pub fn uninstall() -> Result<(), String> {
    for key in BROWSER_KEYS {
        crate::os_protect::set_user_registry_default(&format!(r"{key}\{HOST_NAME}"), None)?;
    }
    if let Some(m) = host_manifest_path() {
        let _ = std::fs::remove_file(m);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EntryKind;

    fn login(id: u64, url: &str, user: &str, pw: &str) -> Entry {
        let mut e = Entry::new(EntryKind::Login);
        e.id = id;
        e.title = format!("Item {id}");
        e.fields[0].value = url.into();
        e.fields[1].value = user.into();
        e.fields[3].value = pw.into();
        e
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
        otp.fields.push(crate::model::Field::with_value(
            "One-time code",
            FieldKind::Totp,
            "JBSWY3DPEHPK3PXP",
        ));
        otp.last_used = 9;
        let entries = vec![a, b, other, otp];

        let list: serde_json::Value =
            serde_json::from_slice(&logins_reply(&entries, "https://github.com/login")).unwrap();
        assert_eq!(list["host"], "github.com");
        let ids: Vec<&str> = list["logins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["4", "1", "2"], "most recently used first");
        assert!(
            !String::from_utf8_lossy(&logins_reply(&entries, "https://github.com")).contains("pw-")
        );

        let (r, used) = fill_reply(&entries, "https://github.com/login", "1", 0);
        let r: serde_json::Value = serde_json::from_slice(&r).unwrap();
        assert_eq!(
            (r["username"].as_str(), r["password"].as_str()),
            (Some("ann"), Some("pw-a"))
        );
        assert_eq!(used, Some(1));
        // An item of another site can't be asked for by id.
        let (r, used) = fill_reply(&entries, "https://github.com/login", "3", 0);
        assert_eq!(&*r, &*error("not_found"));
        assert_eq!(used, None);
        let (r, _) = fill_reply(&entries, "https://github.com", "4", 59);
        let r: serde_json::Value = serde_json::from_slice(&r).unwrap();
        assert_eq!(r["code"].as_str().unwrap().len(), 6);
    }

    #[test]
    fn pairing_codes_match_the_extension() {
        // The extension computes the same code from the same token (see
        // pairingCode in browser-extension/vaultrust.js).
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
        let req = |kind: &str| Request {
            kind: kind.into(),
            token: token.clone(),
            url: "https://example.com".into(),
            browser: "Edge".into(),
            ..Default::default()
        };
        let code = |r: Reply| {
            serde_json::from_slice::<serde_json::Value>(&r).unwrap()["error"]
                .as_str()
                .map(str::to_string)
        };
        assert_eq!(
            code(link.answer(&req("logins"))).as_deref(),
            Some("disabled")
        );
        link.enabled.store(true, Ordering::Relaxed);
        assert_eq!(
            code(link.answer(&req("logins"))).as_deref(),
            Some("unpaired")
        );

        // Asking to pair queues the question and brings the window forward.
        assert_eq!(code(link.answer(&req("pair"))).as_deref(), Some("unpaired"));
        assert!(shown.load(Ordering::Relaxed));
        let Ok(Job::Pair { browser, hash }) = jobs.try_recv() else {
            panic!("expected a pairing request");
        };
        assert_eq!(
            (browser.as_str(), hash.clone()),
            ("Edge", token_hash(&token))
        );
        link.paired.lock().unwrap().push(hash);

        assert_eq!(code(link.answer(&req("logins"))).as_deref(), Some("locked"));
        unlocked.store(true, Ordering::Relaxed);
        // The window thread answers.
        let answering = std::thread::spawn(move || {
            if let Ok(Job::Logins { url, reply }) = jobs.recv() {
                let _ = reply.send(logins_reply(
                    &[login(1, "https://example.com", "u", "p")],
                    &url,
                ));
            }
        });
        let r: serde_json::Value = serde_json::from_slice(&link.answer(&req("logins"))).unwrap();
        assert_eq!(r["logins"][0]["username"], "u");
        answering.join().unwrap();

        let stranger = Request {
            token: "cd".repeat(32),
            ..req("fill")
        };
        assert_eq!(code(link.answer(&stranger)).as_deref(), Some("unpaired"));
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
        assert!(!is_host_invocation(&[
            "vaultrust.exe".into(),
            "--startup".into()
        ]));
    }

    #[test]
    fn host_manifest_allows_only_the_extension() {
        let m: serde_json::Value = serde_json::from_str(&host_manifest(std::path::Path::new(
            r"C:\Apps\VaultRust.exe",
        )))
        .unwrap();
        assert_eq!(m["name"], HOST_NAME);
        assert_eq!(m["path"], r"C:\Apps\VaultRust.exe");
        assert_eq!(
            m["allowed_origins"][0],
            format!("chrome-extension://{EXTENSION_ID}/")
        );
        // The built-in copy of the extension has the key that gives it this ID.
        let manifest: serde_json::Value = serde_json::from_slice(EXTENSION_FILES[0].1).unwrap();
        let key = manifest["key"].as_str().unwrap();
        let der = crate::encoding::base64_decode(key).unwrap();
        let id: String = Sha256::digest(&der[..])[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 15])
            .map(|n| (b'a' + n) as char)
            .collect();
        assert_eq!(id, EXTENSION_ID);
    }
}
