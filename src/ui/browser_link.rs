//! The app's side of the browser extension (see `browser.rs`): answering
//! its requests on the window thread, asking the user to approve a browser,
//! and its settings, including adding the extension to a browser.

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use eframe::egui::{self, Frame, Id, RichText};

use super::entries::Category;
use super::main_view::{MainState, Page};
use super::theme::{accent, dim, faint, strong};
use super::{icons, widgets, Services};
use crate::browser::{self, error, ok, reply, Job, Link, Reply, Request, Saved, BROWSERS};
use crate::i18n::tr;
use crate::model::{EntryKind, FieldKind};
use crate::prefs::{AppPrefs, BrowserPairing};
use crate::trf;

#[derive(Default)]
pub struct BrowserLink {
    link: Option<Arc<Link>>,
    jobs: Option<Receiver<Job>>,
    /// The pipe server is running.
    serving: bool,
    /// A browser waiting for the user's answer: its name and token hash.
    pending: Option<(String, String)>,
    /// The browser being added (index into [`BROWSERS`]): its steps are
    /// shown in the settings until it connects.
    adding: Option<usize>,
}

impl BrowserLink {
    /// Ready to answer the extension (once turned on). `window` is shown
    /// when a browser asks to connect or to unlock, since a window hidden
    /// in the notification area gets no frames.
    pub fn new(ctx: &egui::Context, window: Arc<AtomicIsize>, unlocked: Arc<AtomicBool>) -> Self {
        let ctx = ctx.clone();
        let (link, jobs) = Link::new(unlocked, move |show| {
            if show {
                crate::os_protect::show_window(window.load(Ordering::Relaxed));
            }
            ctx.request_repaint();
        });
        BrowserLink {
            link: Some(link),
            jobs: Some(jobs),
            ..Default::default()
        }
    }

    /// Follow the preferences: whether to answer, and which browsers.
    /// When on, also (re)writes the extension and its registration, so a
    /// moved or updated program keeps working.
    pub fn apply(&mut self, prefs: &AppPrefs) -> Result<(), String> {
        let Some(link) = &self.link else {
            return Ok(());
        };
        let enabled = prefs.browser_enabled && !crate::portable::is_on();
        link.enabled.store(enabled, Ordering::Relaxed);
        self.apply_pairings(prefs);
        if !enabled || cfg!(test) {
            // Tests never touch the registry or the real pipe.
            return Ok(());
        }
        if !self.serving {
            self.serving = browser::serve(link.clone());
            if !self.serving {
                return Err(tr(
                    "Couldn't start the browser connection: another program is using it",
                )
                .to_string());
            }
        }
        browser::install().map(|_| ())
    }

    /// Turn browser filling on or off from the settings.
    fn set_enabled(&mut self, on: bool, prefs: &mut AppPrefs) -> Result<(), String> {
        prefs.browser_enabled = on;
        prefs.save();
        if !on {
            self.adding = None;
            if !cfg!(test) {
                self.apply(prefs)?;
                return browser::uninstall();
            }
        }
        self.apply(prefs)
    }

    fn apply_pairings(&self, prefs: &AppPrefs) {
        if let Some(mut paired) = self.link.as_ref().and_then(|l| l.paired.lock().ok()) {
            *paired = prefs
                .browser_pairings
                .iter()
                .map(|p| p.hash.clone())
                .collect();
        }
    }

    #[cfg(test)]
    pub fn show_steps_for(&mut self, browser: usize) {
        self.adding = Some(browser);
    }

    #[cfg(test)]
    pub fn link(&self) -> Arc<Link> {
        self.link.clone().expect("created with new()")
    }

    pub fn take_jobs(&mut self) -> Vec<Job> {
        self.jobs
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default()
    }

    /// A browser asked to connect (ignored while another one is waiting or
    /// if it is already allowed).
    pub fn ask_to_pair(&mut self, browser: String, hash: String, prefs: &AppPrefs) {
        if self.pending.is_none() && !prefs.browser_pairings.iter().any(|p| p.hash == hash) {
            self.pending = Some((browser, hash));
        }
    }

    /// The question "Connect this browser?". Returns a message for a toast
    /// once answered.
    pub fn pair_dialog(&mut self, ctx: &egui::Context, prefs: &mut AppPrefs) -> Option<String> {
        let (name, hash) = self.pending.as_ref()?;
        let name = if name.trim().is_empty() {
            tr("A browser").to_string()
        } else {
            name.clone()
        };
        let mut decision = None;
        let resp = egui::Modal::new(Id::new("browser_pair")).show(ctx, |ui| {
            ui.set_width(440.0);
            ui.label(strong(trf!("Connect {name}?", name), 16.0));
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(dim(tr(
                    "The VaultRust extension there wants to fill in logins from your vault. \
                     Allow it only if you just clicked “Connect to VaultRust” in the browser and \
                     it shows this code:",
                )))
                .wrap(),
            );
            ui.add_space(10.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new(browser::pairing_code(hash))
                        .monospace()
                        .size(28.0)
                        .strong(),
                );
            });
            ui.add_space(10.0);
            ui.label(faint(tr(
                "It can then fill in and save logins while the vault is unlocked. \
                 You can disconnect it in Settings.",
            )));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if widgets::primary_button(ui, tr("Allow")).clicked() {
                    decision = Some(true);
                }
                if widgets::secondary_button(ui, tr("Don't allow")).clicked() {
                    decision = Some(false);
                }
            });
        });
        if resp.should_close() && decision.is_none() {
            decision = Some(false);
        }
        let allow = decision?;
        let (name, hash) = self.pending.take()?;
        if !allow {
            return Some(trf!("{name} wasn't connected", name));
        }
        prefs.add_browser_pairing(BrowserPairing {
            hash,
            browser: name.clone(),
            added: crate::timeutil::now_unix(),
        });
        prefs.save();
        self.apply_pairings(prefs);
        if self.adding.is_some_and(|i| BROWSERS[i].is(&name)) {
            self.adding = None;
        }
        Some(trf!("{name} is connected", name))
    }
}

/// Answer a request that needs the unlocked vault.
pub fn answer(ms: &mut MainState, svc: &mut Services, req: &Request) -> Reply {
    let now = crate::timeutil::now_unix();
    match req.kind.as_str() {
        "logins" => browser::logins_reply(&ms.vault.data().entries, &req.url),
        "search" => browser::search_reply(&ms.vault.data().entries, &req.query),
        "fill" => {
            let (answer, used) =
                browser::fill_reply(&ms.vault.data().entries, &req.url, &req.id, now);
            if let Some(browser::Used { id, code }) = used {
                ms.vault.data_mut().mark_used(id, now);
                ms.schedule_settings_save();
                // The next page usually asks for it.
                if let Some(code) = code {
                    ms.copy_secret(svc, &code, tr("One-time code"));
                }
            }
            answer
        }
        "forms" => browser::forms_reply(&ms.vault.data().entries, &req.what),
        "fillForm" => {
            let (answer, used) =
                browser::form_fill_reply(&ms.vault.data().entries, &req.url, &req.id);
            if let Some(id) = used {
                ms.vault.data_mut().mark_used(id, now);
                ms.schedule_settings_save();
            }
            answer
        }
        "copy" => {
            let found = req
                .id
                .parse::<u64>()
                .ok()
                .and_then(|id| ms.vault.data().entry(id))
                .and_then(|e| Some((e.id, browser::value_to_copy(e, &req.what, now)?)));
            let Some((id, value)) = found else {
                return error("not_found");
            };
            let what = match req.what.as_str() {
                "username" => tr("Username"),
                "password" => tr("Password"),
                "number" => tr("Card number"),
                "cvv" => tr("Security code (CVV)"),
                _ => tr("One-time code"),
            };
            ms.copy_from(svc, id, &value, what);
            ok()
        }
        "generate" => {
            let url = Some(req.url.as_str()).filter(|u| !u.is_empty());
            let opts = ms.vault.data().settings.generator_for(url).clone();
            match crate::generator::generate_password(&opts) {
                Ok(pw) => reply(&serde_json::json!({ "password": pw.as_str() })),
                Err(_) => error("bad_request"),
            }
        }
        "check" => browser::check_reply(
            &ms.vault.data().entries,
            &req.url,
            &req.username,
            &req.password,
        ),
        "save" => {
            let saved = browser::save_login(
                ms.vault.data_mut(),
                &req.url,
                &req.username,
                &req.password,
                &req.id,
            );
            match saved {
                Ok(saved) => {
                    if !ms.commit(svc.toasts) {
                        return error("not_saved");
                    }
                    let id = match saved {
                        Saved::Created(id) | Saved::Updated(id) => id,
                    };
                    let title = ms
                        .vault
                        .data()
                        .entry(id)
                        .map(|e| e.display_title().to_string())
                        .unwrap_or_default();
                    svc.toasts.success(match saved {
                        Saved::Created(_) => trf!("Saved “{title}” from the browser", title),
                        Saved::Updated(_) => {
                            trf!("Updated the password of “{title}” from the browser", title)
                        }
                    });
                    reply(&serde_json::json!({ "ok": true, "id": id.to_string() }))
                }
                Err(e) => error(e),
            }
        }
        "new" => {
            // Never throw away an item being edited.
            if ms.items.editor.is_some() {
                svc.toasts.info(tr("Finish editing the open item first"));
                return error("busy");
            }
            let (category, kind) = match req.what.as_str() {
                "card" => (Category::Cards, EntryKind::CreditCard),
                "identity" => (Category::Identities, EntryKind::Identity),
                _ => (Category::Logins, EntryKind::Login),
            };
            ms.page = Page::Items(category);
            ms.items.new_entry(kind);
            if kind != EntryKind::Login {
                return ok();
            }
            if let Some(ed) = ms.items.editor.as_mut() {
                if let Some(f) = ed
                    .entry
                    .fields
                    .iter_mut()
                    .find(|f| f.kind == FieldKind::Url)
                {
                    f.value = browser::origin(&req.url);
                }
            }
            ok()
        }
        _ => error("bad_request"),
    }
}

/// Settings → Browser extension.
pub fn settings_section(ui: &mut egui::Ui, svc: &mut Services) {
    widgets::section(ui, tr("Browser extension"), |ui| {
        if crate::portable::is_on() {
            // Adding it would change the computer's browsers.
            widgets::setting_row(
                ui,
                tr("Fill in and save logins in your browser"),
                super::settings_page::portable_off(),
                0.0,
                |_| {},
            );
            return;
        }
        let mut on = svc.prefs.browser_enabled;
        widgets::switch_row(
            ui,
            &mut on,
            tr("Fill in and save logins in your browser"),
            tr("Chrome, Edge, Brave and Firefox, while the vault is unlocked"),
        );
        if on != svc.prefs.browser_enabled {
            match svc.browser.set_enabled(on, svc.prefs) {
                Ok(()) if on => svc
                    .toasts
                    .success(tr("Turned on. Now add the extension to your browser")),
                Ok(()) => svc.toasts.info(tr("Browser filling turned off")),
                Err(e) => svc.toasts.error(e),
            }
        }
        if !svc.prefs.browser_enabled {
            return;
        }
        let installed: Vec<usize> = (0..BROWSERS.len())
            .filter(|&i| cfg!(test) || BROWSERS[i].program().is_some())
            .collect();
        if installed.is_empty() {
            widgets::divider(ui, 16.0);
            widgets::warning_box(
                ui,
                tr("No Chrome, Edge, Brave or Firefox found on this computer."),
            );
        }
        let mut add = None;
        for &i in &installed {
            let b = &BROWSERS[i];
            let connected = svc.prefs.browser_pairings.iter().any(|p| b.is(&p.browser));
            widgets::divider(ui, 16.0);
            let desc = if connected {
                tr("Added and connected")
            } else {
                tr("Not added yet")
            };
            let name = b.name;
            let label = if connected {
                trf!("Add to {name} again", name)
            } else {
                trf!("Add to {name}", name)
            };
            widgets::setting_row(ui, b.name, desc, 200.0, |ui| {
                let text = icons::with(icons::PUZZLE_PIECE, &label);
                let clicked = if connected {
                    widgets::secondary_button(ui, &text).clicked()
                } else {
                    widgets::primary_button(ui, &text).clicked()
                };
                if clicked {
                    add = Some(i);
                }
                if connected {
                    ui.label(
                        RichText::new(icons::CHECK_CIRCLE)
                            .color(accent())
                            .size(18.0),
                    );
                }
            });
            if svc.browser.adding == Some(i) {
                steps(ui, svc, i);
            }
        }
        if let Some(i) = add {
            start_adding(ui.ctx(), svc, i);
        }

        widgets::divider(ui, 16.0);
        let folder = browser::extension_dir().unwrap_or_default();
        let (mut copy, mut open) = (false, false);
        widgets::setting_row(
            ui,
            tr("Extension folder"),
            &widgets::short_path(&folder),
            230.0,
            |ui| {
                open = widgets::secondary_button(
                    ui,
                    &icons::with(icons::FOLDER_OPEN, tr("Open folder")),
                )
                .clicked();
                copy = widgets::secondary_button(ui, &icons::with(icons::COPY, tr("Copy path")))
                    .clicked();
            },
        );
        if copy {
            ui.ctx().copy_text(folder.display().to_string());
            svc.toasts.info(tr("Folder path copied"));
        }
        if open && !cfg!(test) {
            browser::show_extension_folder();
        }

        let mut remove = None;
        for (i, p) in svc.prefs.browser_pairings.iter().enumerate() {
            widgets::divider(ui, 16.0);
            let desc = trf!("Connected {}", crate::timeutil::format_date(p.added));
            widgets::setting_row(ui, &p.browser, &desc, 120.0, |ui| {
                if widgets::secondary_button(ui, tr("Disconnect")).clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            let p = svc.prefs.browser_pairings.remove(i);
            svc.prefs.save();
            svc.browser.apply_pairings(svc.prefs);
            let name = p.browser;
            svc.toasts.info(trf!("{name} disconnected", name));
        }
    });
}

/// "Add to Edge": refresh the extension's files, show the folder in File
/// Explorer, put the extensions page's address on the clipboard and open
/// the browser on a page with the steps. Browsers don't let other programs
/// install extensions (or even open their extensions page), so the user
/// finishes with a paste and a drag and drop ([`steps`]).
///
/// "Add to Firefox": download the signed add-on and open it in Firefox,
/// which asks whether to add it; if that fails, open a page with the steps
/// for adding it by hand.
fn start_adding(ctx: &egui::Context, svc: &mut Services, i: usize) {
    let b = &BROWSERS[i];
    svc.browser.adding = Some(i);
    if cfg!(test) {
        return;
    }
    let dir = match browser::install() {
        Ok(dir) => dir,
        Err(e) => {
            svc.toasts.error(e);
            return;
        }
    };
    if b.firefox {
        let page = browser::setup_page_path()
            .filter(|p| std::fs::write(p, firefox_setup_page(&dir)).is_ok());
        let b = *b;
        std::thread::spawn(move || {
            if browser::add_to_firefox(&b).is_err() {
                if let Some(p) = page {
                    b.open(&p);
                }
            }
        });
        return;
    }
    ctx.copy_text(b.extensions_page.to_string());
    browser::show_extension_folder();
    let page =
        browser::setup_page_path().filter(|p| std::fs::write(p, setup_page(b, &dir)).is_ok());
    if !page.is_some_and(|p| b.open(&p)) {
        let name = b.name;
        svc.toasts.error(trf!("Couldn't open {name}", name));
    }
}

fn developer_mode_place(b: &browser::Browser) -> &'static str {
    if b.name == "Edge" {
        tr("on the left")
    } else {
        tr("at the top right")
    }
}

/// One numbered step of a setup page, with a value to copy.
fn page_step(n: u32, text: &str, value: Option<&str>) -> String {
    use browser::html_escape as esc;
    let copy = esc(tr("Copy"));
    let value = value.map_or(String::new(), |v| {
        format!(
            r#"<div class="value"><code>{v}</code><button data-copy="{v}">{copy}</button></div>"#,
            v = esc(v)
        )
    });
    format!(
        r#"<li><span class="n">{n}</span><div>{}{value}</div></li>"#,
        esc(text)
    )
}

/// The steps for adding the extension, as a page opened in the browser.
pub(super) fn setup_page(b: &browser::Browser, dir: &std::path::Path) -> String {
    let name = b.name;
    let page = b.extensions_page;
    let developer = developer_mode_place(b);
    let folder = dir.display().to_string();
    let step = |n: u32, text: String, value: Option<&str>| page_step(n, &text, value);
    let steps = [
        step(1, trf!("Copy this address into {name}'s address bar and press Enter (it's already on the clipboard):", name), Some(page)),
        step(2, trf!("On that page, turn on “Developer mode” {developer}.", developer), None),
        step(3, tr("Drag the “Browser extension” folder from the File Explorer window that VaultRust opened onto the extensions page. Or click “Load unpacked” and choose this folder:").to_string(), Some(&folder)),
        step(4, tr("Click the puzzle piece in the toolbar and pin VaultRust. Then click its button and choose “Connect to VaultRust”; VaultRust asks you to allow it.").to_string(), None),
    ]
    .join("");
    page_html(
        &trf!("Add VaultRust to {name}", name),
        tr("Browsers only let you add extensions from outside their store by hand. It takes a minute, once."),
        &steps,
    )
}

/// What Firefox shows when VaultRust couldn't download the add-on: get it
/// by hand, or (for a version not released yet) load it from the folder
/// until Firefox closes.
pub(super) fn firefox_setup_page(dir: &std::path::Path) -> String {
    let url = browser::firefox_addon_url();
    let manifest = dir.join("manifest.json").display().to_string();
    let steps = [
        page_step(1, tr("Download the VaultRust add-on from this address:"), Some(&url)),
        page_step(2, tr("Open this page, click the gear button and choose “Install Add-on From File…”. Pick the downloaded VaultRust-Firefox.xpi and click “Add”."), Some("about:addons")),
        page_step(3, tr("Click the puzzle piece in the toolbar and pin VaultRust. Then click its button and choose “Connect to VaultRust”; VaultRust asks you to allow it."), None),
        page_step(4, tr("Trying a version that isn't released yet? On about:debugging, under “This Firefox”, click “Load Temporary Add-on…” and choose this file. Firefox removes it again when it closes."), Some(&manifest)),
    ]
    .join("");
    page_html(
        tr("Add VaultRust to Firefox"),
        tr("VaultRust couldn't download the Firefox add-on. You can add it by hand:"),
        &steps,
    )
}

/// A setup page around its numbered steps.
fn page_html(title: &str, intro: &str, steps: &str) -> String {
    use browser::html_escape as esc;
    let copy = esc(tr("Copy"));
    let copied = esc(tr("Copied"));
    format!(
        r#"<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8"><title>{title}</title>
<style>
:root {{ --bg:#f6f4f0; --surface:#fff; --border:#ddd8d0; --text:#1f1d1a; --dim:#5b564f; --accent:#237f58; color-scheme:light dark; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#171615; --surface:#1e1d1b; --border:#2e2c29; --text:#ece8e2; --dim:#a59f96; --accent:#2f8560; }} }}
body {{ margin:0; background:var(--bg); color:var(--text); font:15px/1.5 "Segoe UI",system-ui,sans-serif; }}
main {{ max-width:640px; margin:48px auto; padding:0 20px; }}
h1 {{ font-size:22px; margin:0 0 6px; }}
p {{ color:var(--dim); margin:0 0 24px; }}
ol {{ list-style:none; padding:0; margin:0; display:grid; gap:14px; }}
li {{ display:flex; gap:14px; background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }}
.n {{ flex:none; width:26px; height:26px; border-radius:50%; background:var(--accent); color:#fff; display:grid; place-items:center; font-weight:600; }}
.value {{ display:flex; gap:8px; align-items:center; margin-top:8px; }}
code {{ flex:1; min-width:0; overflow-wrap:anywhere; background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:6px 8px; font:13px "Cascadia Mono",Consolas,monospace; }}
button {{ font:inherit; border:0; border-radius:6px; padding:6px 14px; background:var(--accent); color:#fff; cursor:pointer; }}
</style></head>
<body><main><h1>{title}</h1><p>{intro}</p><ol>{steps}</ol></main>
<script>
for (const b of document.querySelectorAll("button[data-copy]")) {{
  b.addEventListener("click", async () => {{
    try {{ await navigator.clipboard.writeText(b.dataset.copy); }}
    catch {{ const t = document.createElement("textarea"); t.value = b.dataset.copy; document.body.append(t); t.select(); document.execCommand("copy"); t.remove(); }}
    b.textContent = "{copied}";
    setTimeout(() => (b.textContent = "{copy}"), 1500);
  }});
}}
</script></body></html>
"#,
        lang = crate::i18n::language().key(),
        title = esc(title),
        intro = esc(intro),
    )
}

/// What to do in the browser, shown while adding the extension to it.
fn steps(ui: &mut egui::Ui, svc: &mut Services, i: usize) {
    let b = &BROWSERS[i];
    let name = b.name;
    let page = b.extensions_page;
    let developer = developer_mode_place(b);
    let firefox_items = [
        tr("Firefox asks whether to add VaultRust: click “Add”. (If it opened a page with steps instead, the download didn't work; follow the steps there.)")
            .to_string(),
        tr("Click the puzzle piece in the toolbar, pin VaultRust, then click its button and choose “Connect to VaultRust”. VaultRust asks you to allow it.")
            .to_string(),
    ];
    let chromium_items = [
        trf!(
            "{name} opened a page with these steps. Paste {page} into its address bar (it's on the clipboard) and turn on “Developer mode” {developer}.",
            name,
            page,
            developer
        ),
        tr("Drag the highlighted “Browser extension” folder from the File Explorer window onto the extensions page, or click “Load unpacked” and choose it.")
            .to_string(),
        tr("Click the puzzle piece in the toolbar, pin VaultRust, then click its button and choose “Connect to VaultRust”. VaultRust asks you to allow it.")
            .to_string(),
    ];
    let (items, note): (&[String], _) = if b.firefox {
        (
            &firefox_items,
            tr("Firefox only adds extensions signed by Mozilla, so VaultRust downloads the signed add-on from its releases on GitHub."),
        )
    } else {
        (
            &chromium_items,
            tr(
                "Browsers only let you add extensions from outside their store this way. \
                 Edge and Chrome may remind you that developer-mode extensions are on; \
                 choose to keep it.",
            ),
        )
    };
    ui.add_space(6.0);
    let mut done = false;
    let mut again = false;
    Frame::new()
        .fill(super::theme::palette().accent_bg)
        .stroke(egui::Stroke::new(1.0_f32, super::theme::palette().border))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(strong(
                trf!("Finish adding VaultRust to {name}", name),
                14.0,
            ));
            ui.add_space(6.0);
            for (n, text) in items.iter().enumerate() {
                ui.horizontal_top(|ui| {
                    ui.label(
                        RichText::new(format!("{}.", n + 1))
                            .color(accent())
                            .strong(),
                    );
                    ui.add(egui::Label::new(dim(text.as_str())).wrap());
                });
                ui.add_space(4.0);
            }
            ui.label(faint(note));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                again = widgets::secondary_button(
                    ui,
                    &icons::with(icons::ARROW_CLOCKWISE, tr("Open again")),
                )
                .clicked();
                done = widgets::secondary_button(ui, tr("Close")).clicked();
            });
        });
    ui.add_space(4.0);
    if again {
        start_adding(ui.ctx(), svc, i);
    }
    if done {
        svc.browser.adding = None;
    }
}
