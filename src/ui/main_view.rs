//! The unlocked application: sidebar, page routing, auto-lock, saving.

use std::time::{Duration, Instant};

use eframe::egui::{self, Frame, Key, Margin};

use super::entries::{self, Category, ItemsState};
use super::generator_page::{self, GenState};
use super::icons;
use super::modals::{self, Modal};
use super::settings_page::{self, SettingsState};
use super::theme::*;
use super::widgets;
use super::{dashboard, security_page, Services, Toasts, Transition};
use crate::analysis::{analyze, HealthReport};
use crate::error::VaultError;
use crate::model::EntryKind;
use crate::session::AutoLock;
use crate::storage::with_vault_extension;
use crate::timeutil::{file_stamp, now_unix};
use crate::vault::UnlockedVault;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Dashboard,
    Items(Category),
    Generator,
    Security,
    Settings,
}

/// A navigation request. Routed through [`MainState::request`] so unsaved
/// edits are never discarded without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Page(Page),
    /// Show an entry in "All items".
    Open(u64),
    /// Select an entry on the current page.
    Select(u64),
    New(Category, EntryKind),
    CloseEditor,
}

pub struct MainState {
    pub vault: UnlockedVault,
    pub page: Page,
    pub autolock: AutoLock,
    pub items: ItemsState,
    pub gen: GenState,
    pub settings: SettingsState,
    pub modal: Option<Modal>,
    pub health: HealthReport,
    /// Search text on the home page.
    pub home_query: String,
    health_rev: u64,
    rev: u64,
    settings_save_at: Option<Instant>,
}

impl MainState {
    pub fn new(vault: UnlockedVault) -> Self {
        let minutes = vault.data().settings.auto_lock_minutes;
        MainState {
            vault,
            page: Page::Dashboard,
            autolock: AutoLock::new(Duration::from_secs(u64::from(minutes) * 60), Instant::now()),
            items: ItemsState::default(),
            gen: GenState::default(),
            settings: SettingsState::default(),
            modal: None,
            health: HealthReport::default(),
            home_query: String::new(),
            health_rev: u64::MAX,
            rev: 0,
            settings_save_at: None,
        }
    }

    /// Persist the vault after a change. Returns false on failure; a
    /// conflicting external change opens a dialog instead of overwriting.
    pub fn commit(&mut self, toasts: &mut Toasts) -> bool {
        self.rev = self.rev.wrapping_add(1);
        self.settings_save_at = None;
        match self.vault.save() {
            Ok(()) => true,
            Err(VaultError::ModifiedExternally) => {
                self.modal = Some(Modal::ExternalChange);
                false
            }
            Err(e) => {
                toasts.error(format!("Couldn't save the vault: {e}"));
                false
            }
        }
    }

    /// Save pending (debounced) changes before locking or exiting.
    pub fn flush(&mut self, toasts: &mut Toasts) {
        if !self.vault.is_dirty() {
            return;
        }
        match self.vault.save() {
            Ok(()) => {}
            Err(VaultError::ModifiedExternally) => toasts.error(
                "Your last settings change wasn't saved: the vault file was changed elsewhere.",
            ),
            Err(e) => toasts.error(format!("Couldn't save the vault: {e}")),
        }
    }

    /// Settings are saved after a short pause rather than on every slider
    /// movement.
    pub fn schedule_settings_save(&mut self) {
        self.settings_save_at = Some(Instant::now() + Duration::from_millis(1200));
    }

    pub fn refresh_health(&mut self) {
        if self.health_rev != self.rev {
            self.health = analyze(self.vault.data(), now_unix());
            self.health_rev = self.rev;
        }
    }

    pub fn copy_secret(&mut self, svc: &mut Services, value: &str, what: &str) {
        let secs = self.vault.data().settings.clipboard_clear_secs;
        match svc
            .clipboard
            .copy_secret(value, Duration::from_secs(u64::from(secs)))
        {
            Ok(()) => svc
                .toasts
                .success(format!("{what} copied — clears in {secs} s")),
            Err(e) => svc.toasts.error(format!("Clipboard unavailable: {e}")),
        }
    }

    /// Ask to navigate; if the editor has unsaved changes, confirm first.
    pub fn request(&mut self, nav: Nav) {
        let dirty = self.items.editor.as_ref().is_some_and(|e| e.is_dirty());
        if dirty && nav != Nav::Page(self.page) {
            self.modal = Some(Modal::DiscardEdits(nav));
        } else {
            self.perform(nav);
        }
    }

    pub fn perform(&mut self, nav: Nav) {
        match nav {
            Nav::Page(p) => {
                if p != self.page {
                    self.items.editor = None;
                }
                self.page = p;
            }
            Nav::Open(id) => {
                self.page = Page::Items(Category::All);
                self.items.select(id);
            }
            Nav::Select(id) => self.items.select(id),
            Nav::New(c, k) => {
                self.page = Page::Items(c);
                self.items.new_entry(k);
            }
            Nav::CloseEditor => self.items.editor = None,
        }
    }

    #[cfg(test)]
    pub fn open_entry(&mut self, id: u64) {
        self.perform(Nav::Open(id));
    }

    pub fn start_backup(&mut self, svc: &mut Services) {
        let stem = self
            .vault
            .path()
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault".into());
        let mut dlg = rfd::FileDialog::new()
            .set_title("Save encrypted backup")
            .add_filter("VaultRust vault", &["vault"])
            .set_file_name(format!("{stem}-backup-{}.vault", file_stamp(now_unix())));
        if let Some(dir) = self.vault.path().parent() {
            dlg = dlg.set_directory(dir);
        }
        if let Some(p) = dlg.save_file() {
            let p = with_vault_extension(p);
            if p.exists() {
                self.modal = Some(Modal::ConfirmBackupOverwrite(p));
            } else {
                self.do_backup(&p, false, svc);
            }
        }
    }

    pub fn do_backup(&mut self, path: &std::path::Path, overwrite: bool, svc: &mut Services) {
        match self.vault.backup_to(path, overwrite) {
            Ok(()) => {
                // Recorded after verification, so it only counts real backups.
                self.vault.data_mut().last_backup = now_unix();
                self.commit(svc.toasts);
                svc.toasts.success(format!(
                    "Backup saved and verified: {}",
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ));
            }
            Err(VaultError::ModifiedExternally) => self.modal = Some(Modal::ExternalChange),
            Err(e) => svc.toasts.error(format!("Backup failed: {e}")),
        }
    }

    pub fn show(&mut self, ctx: &egui::Context, svc: &mut Services) -> Option<Transition> {
        let now = Instant::now();

        // Automatic locking.
        let active = ctx.input(|i| {
            !i.events.is_empty() || i.pointer.is_moving() || i.raw_scroll_delta != egui::Vec2::ZERO
        });
        // Background key derivation (password change / restore) counts as
        // activity so the vault is not locked out from under it.
        if active || self.modal.as_ref().is_some_and(Modal::is_busy) || self.settings.is_busy() {
            self.autolock.touch(now);
        }
        let settings = self.vault.data().settings.clone();
        self.autolock.set_timeout(Duration::from_secs(
            u64::from(settings.auto_lock_minutes) * 60,
        ));
        if self.autolock.should_lock(now) {
            svc.toasts.info("Locked after inactivity");
            return Some(Transition::Lock);
        }
        if settings.lock_on_minimize && ctx.input(|i| i.viewport().minimized.unwrap_or(false)) {
            return Some(Transition::Lock);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, Key::L)) {
            return Some(Transition::Lock);
        }
        if self.settings_save_at.is_some_and(|t| now >= t) {
            self.commit(svc.toasts);
        }

        self.refresh_health();
        let mut transition = None;

        egui::SidePanel::left("nav")
            .exact_width(220.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(Frame::new().fill(SIDEBAR).inner_margin(Margin {
                left: 10,
                right: 10,
                top: 14,
                bottom: 12,
            }))
            .show(ctx, |ui| {
                if self.sidebar(ui, now) {
                    transition = Some(Transition::Lock);
                }
            });

        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(BG)
                    .inner_margin(Margin::symmetric(28, 22)),
            )
            .show(ctx, |ui| match self.page {
                Page::Dashboard => dashboard::show(ui, self, svc),
                Page::Items(c) => entries::show(ui, self, svc, c),
                Page::Generator => generator_page::show(ui, self, svc),
                Page::Security => security_page::show(ui, self, svc),
                Page::Settings => {
                    if let Some(t) = settings_page::show(ui, self, svc) {
                        transition = Some(t);
                    }
                }
            });

        if let Some(t) = modals::show(ctx, self, svc) {
            transition = Some(t);
        }
        transition
    }

    /// Returns true if the user asked to lock.
    fn sidebar(&mut self, ui: &mut egui::Ui, now: Instant) -> bool {
        let mut lock = false;
        let mut nav = None;
        egui::TopBottomPanel::bottom("nav_bottom")
            .frame(Frame::new())
            .show_separator_line(false)
            .show_inside(ui, |ui| {
                ui.add_space(6.0);
                if widgets::secondary_button_wide(ui, &icons::with(icons::LOCK, "Lock vault"))
                    .on_hover_text("Ctrl+L")
                    .clicked()
                {
                    lock = true;
                }
                let rem = self.autolock.remaining(now).as_secs();
                ui.vertical_centered(|ui| {
                    ui.label(faint(format!("Locks in {}:{:02}", rem / 60, rem % 60)));
                });
            });

        egui::CentralPanel::default()
            .frame(Frame::new())
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(4.0);
                    widgets::logo(ui, 26.0);
                    ui.add(egui::Label::new(strong(&self.vault.data().name, 15.0)).truncate());
                });
                ui.add_space(14.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        let mut item = |ui: &mut egui::Ui,
                                        icon: &str,
                                        label: &str,
                                        badge: Option<(String, egui::Color32)>,
                                        page: Page| {
                            if widgets::nav_item(ui, icon, label, badge, self.page == page)
                                .clicked()
                            {
                                nav = Some(Nav::Page(page));
                            }
                        };
                        item(ui, icons::HOUSE, "Overview", None, Page::Dashboard);
                        ui.add_space(10.0);
                        ui.label(section_label("    Vault"));
                        ui.add_space(2.0);
                        for c in Category::ALL {
                            let n = self
                                .vault
                                .data()
                                .entries
                                .iter()
                                .filter(|e| c.includes(e))
                                .count();
                            let badge = (n > 0).then(|| (n.to_string(), TEXT_FAINT));
                            item(ui, c.icon(), c.label(), badge, Page::Items(c));
                        }
                        ui.add_space(10.0);
                        ui.label(section_label("    Tools"));
                        ui.add_space(2.0);
                        item(ui, icons::DICE_FIVE, "Generator", None, Page::Generator);
                        let issues = self.health.weak.len() + self.health.reused_count();
                        let badge = (issues > 0).then(|| (issues.to_string(), WARN));
                        item(ui, icons::SHIELD_CHECK, "Security", badge, Page::Security);
                        item(ui, icons::GEAR_SIX, "Settings", None, Page::Settings);
                    });
            });
        if let Some(n) = nav {
            self.request(n);
        }
        lock
    }
}
