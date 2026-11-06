//! The app's side of the browser extension (see `browser.rs`): answering
//! its requests on the window thread, asking the user to approve a browser,
//! and its settings.

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use eframe::egui::{self, Id};

use super::theme::{dim, faint, strong};
use super::{icons, widgets, Services};
use crate::browser::{self, Job, Link};
use crate::i18n::tr;
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
        link.enabled.store(prefs.browser_enabled, Ordering::Relaxed);
        if let Ok(mut paired) = link.paired.lock() {
            *paired = prefs
                .browser_pairings
                .iter()
                .map(|p| p.hash.clone())
                .collect();
        }
        if !prefs.browser_enabled || cfg!(test) {
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
    fn set_enabled(&mut self, on: bool, svc_prefs: &mut AppPrefs) -> Result<(), String> {
        svc_prefs.browser_enabled = on;
        svc_prefs.save();
        if !on && !cfg!(test) {
            self.apply(svc_prefs)?;
            return browser::uninstall();
        }
        self.apply(svc_prefs)
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
                     Allow it only if you just clicked “Connect to VaultRust” in the browser and it shows \
                     this code:",
                )))
                .wrap(),
            );
            ui.add_space(10.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new(browser::pairing_code(hash))
                        .monospace()
                        .size(28.0)
                        .strong(),
                );
            });
            ui.add_space(10.0);
            ui.label(faint(tr(
                "It can then fill in the login for the site you're on while the vault is unlocked. \
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
        let _ = self.apply_pairings(prefs);
        Some(trf!("{name} is connected", name))
    }

    fn apply_pairings(&self, prefs: &AppPrefs) -> Option<()> {
        let mut paired = self.link.as_ref()?.paired.lock().ok()?;
        *paired = prefs
            .browser_pairings
            .iter()
            .map(|p| p.hash.clone())
            .collect();
        Some(())
    }
}

/// Settings → Browser extension.
pub fn settings_section(ui: &mut egui::Ui, svc: &mut Services) {
    widgets::section(ui, tr("Browser extension"), |ui| {
        let mut on = svc.prefs.browser_enabled;
        widgets::switch_row(
            ui,
            &mut on,
            tr("Fill in logins in your browser"),
            tr("Chrome, Edge and Brave, while the vault is unlocked"),
        );
        if on != svc.prefs.browser_enabled {
            match svc.browser.set_enabled(on, svc.prefs) {
                Ok(()) if on => svc
                    .toasts
                    .success(tr("Turned on. Add the extension to your browser (below)")),
                Ok(()) => svc.toasts.info(tr("Browser filling turned off")),
                Err(e) => svc.toasts.error(e),
            }
        }
        if !svc.prefs.browser_enabled {
            return;
        }
        widgets::divider(ui, 16.0);
        let folder = browser::extension_dir().unwrap_or_default();
        let (mut copy, mut open) = (false, false);
        widgets::setting_row(
            ui,
            tr("Add the extension"),
            tr("Once per browser, from the folder below"),
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
        ui.add(
            egui::Label::new(dim(tr(
                "Open the browser's extensions page (chrome://extensions, edge://extensions or \
                 brave://extensions), turn on Developer mode, choose “Load unpacked” and pick this \
                 folder. Then click the VaultRust button in the toolbar to connect the browser.",
            )))
            .wrap(),
        );
        ui.add_space(4.0);
        ui.add(egui::Label::new(faint(folder.display().to_string())).wrap());
        if copy {
            ui.ctx().copy_text(folder.display().to_string());
            svc.toasts.info(tr("Folder path copied"));
        }
        if open && !cfg!(test) {
            let _ = std::process::Command::new("explorer.exe")
                .arg(&folder)
                .spawn();
        }
        widgets::divider(ui, 16.0);
        if svc.prefs.browser_pairings.is_empty() {
            widgets::setting_row(ui, tr("Connected browsers"), tr("None yet"), 0.0, |_| {});
            return;
        }
        let mut remove = None;
        for (i, p) in svc.prefs.browser_pairings.iter().enumerate() {
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
            let _ = svc.browser.apply_pairings(svc.prefs);
            let name = p.browser;
            svc.toasts.info(trf!("{name} disconnected", name));
        }
    });
}
