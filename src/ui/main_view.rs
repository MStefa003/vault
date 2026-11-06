//! The unlocked application: sidebar, page routing, auto-lock, saving.

use std::time::{Duration, Instant};

use eframe::egui::{self, Frame, Key, Margin};
use zeroize::Zeroizing;

use super::entries::{self, Category, ItemsState};
use super::generator_page::{self, GenState};
use super::icons;
use super::jobs::{Job, Poll};
use super::modals::{self, AutoTypeState, Modal, QuickOpenState};
use super::settings_page::{self, SettingsState};
use super::theme::*;
use super::widgets;
use super::{dashboard, security_page, trash_page, Services, Toasts, Transition};
use crate::analysis::{analyze, HealthReport, PasswordRef};
use crate::error::VaultError;
use crate::model::{EntryKind, FieldKind};
use crate::session::AutoLock;
use crate::storage::with_vault_extension;
use crate::timeutil::{file_stamp, now_unix};
use crate::vault::UnlockedVault;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    Dashboard,
    Items(Category),
    /// All items carrying a tag.
    Tag(String),
    Trash,
    Generator,
    Security,
    Settings,
}

/// A navigation request. Routed through [`MainState::request`] so unsaved
/// edits are never discarded without asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nav {
    Page(Page),
    /// Show an entry in "All items".
    Open(u64),
    /// Select an entry on the current page.
    Select(u64),
    New(Category, EntryKind),
    CloseEditor,
}

/// Result of the offline breached-password check.
#[derive(Default)]
pub struct BreachReport {
    /// Password locations found in the list, with how often they appear.
    pub hits: Vec<(PasswordRef, u64)>,
    pub checked: usize,
    pub error: Option<String>,
}

impl BreachReport {
    pub fn is_breached(&self, entry_id: u64) -> bool {
        self.hits.iter().any(|(r, _)| r.entry_id == entry_id)
    }
}

#[derive(Default)]
pub struct BreachState {
    pub report: Option<BreachReport>,
    job: Option<(u64, Job<BreachReport>)>,
    /// Vault revision (and list path) the current report belongs to.
    checked: Option<(u64, String)>,
}

impl BreachState {
    pub fn is_running(&self) -> bool {
        self.job.is_some()
    }
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
    pub breach: BreachState,
    /// Search text on the home page.
    pub home_query: String,
    health_rev: u64,
    rev: u64,
    settings_save_at: Option<Instant>,
    /// When the session-lock state was last polled.
    session_checked: Option<Instant>,
    /// Turning on Windows Hello (shows the Hello prompt).
    pub hello_job: Option<Job<Result<(), crate::hello::HelloError>>>,
    /// The welcome tour, while it is showing.
    pub tour: Option<super::tutorial::Tour>,
    /// Looking for a two-step verification QR code on screen.
    pub qr_job: Option<Job<Result<Zeroizing<String>, crate::qr::ScanError>>>,
    /// A screen asked for a QR scan this frame (started where a context is
    /// at hand).
    pub qr_requested: bool,
    /// Whether Hello is on for this vault (`None` = not checked yet).
    pub hello_enabled: Option<bool>,
    /// Keystrokes being typed into another window.
    pub auto_type_job: Option<Job<Result<(), crate::os_protect::AutoTypeError>>>,
    /// What the last auto-type would have typed (tests never send keys).
    #[cfg(test)]
    pub auto_typed: Option<Vec<String>>,
}

impl MainState {
    pub fn new(mut vault: UnlockedVault) -> Self {
        let minutes = vault.data().settings.auto_lock_minutes;
        // Trash older than the retention period goes on unlock. Saved with
        // the next change rather than now, so merely opening a vault never
        // writes to it.
        if vault
            .data()
            .trash
            .iter()
            .any(|t| t.deleted <= now_unix() - crate::model::TRASH_RETENTION_DAYS * 86_400)
        {
            vault.data_mut().purge_expired_trash(now_unix());
        }
        MainState {
            vault,
            page: Page::Dashboard,
            autolock: AutoLock::new(Duration::from_secs(u64::from(minutes) * 60), Instant::now()),
            items: ItemsState::default(),
            gen: GenState::default(),
            settings: SettingsState::default(),
            modal: None,
            health: HealthReport::default(),
            breach: BreachState::default(),
            home_query: String::new(),
            health_rev: u64::MAX,
            rev: 0,
            settings_save_at: None,
            session_checked: None,
            auto_type_job: None,
            hello_job: None,
            qr_job: None,
            tour: None,
            qr_requested: false,
            hello_enabled: None,
            #[cfg(test)]
            auto_typed: None,
        }
    }

    /// Whether Windows Hello unlock is on for this vault.
    pub fn hello_enabled(&mut self) -> bool {
        let id = self.vault.vault_id();
        *self
            .hello_enabled
            .get_or_insert_with(|| crate::hello::is_enabled(&id))
    }

    /// Turn Hello on in the background (it shows its own prompts).
    pub fn start_hello_enable(&mut self, ctx: &egui::Context) {
        let id = self.vault.vault_id();
        let secret = self.vault.hello_secret();
        self.hello_job = Some(Job::spawn(ctx, move || crate::hello::enable(id, &secret)));
    }

    pub fn disable_hello(&mut self, svc: &mut Services) {
        crate::hello::remove(&self.vault.vault_id());
        self.hello_enabled = Some(false);
        self.vault
            .data_mut()
            .log(crate::model::AuditKind::HelloDisabled, "");
        self.commit(svc.toasts);
        svc.toasts.info("Windows Hello unlock is off");
    }

    fn poll_hello(&mut self, svc: &mut Services) {
        let Some(job) = &self.hello_job else { return };
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(Ok(())) => {
                self.hello_job = None;
                self.hello_enabled = Some(true);
                self.vault
                    .data_mut()
                    .log(crate::model::AuditKind::HelloEnabled, "");
                self.commit(svc.toasts);
                svc.toasts
                    .success("Windows Hello can now unlock this vault");
            }
            Poll::Done(Err(crate::hello::HelloError::Cancelled)) => {
                self.hello_job = None;
                svc.toasts.info("Windows Hello was cancelled");
            }
            Poll::Done(Err(e)) => {
                self.hello_job = None;
                svc.toasts.error(e.to_string());
            }
            Poll::Failed => {
                self.hello_job = None;
                svc.toasts.error("Windows Hello stopped unexpectedly");
            }
        }
    }

    /// Show the auto-type picker for a window of another application.
    pub fn open_auto_type(&mut self, target: crate::os_protect::ForeignWindow) {
        if !self.modal.as_ref().is_some_and(Modal::is_busy) {
            self.modal = Some(Modal::AutoType(AutoTypeState::new(target)));
        }
    }

    /// Type `steps` into `target` on a background thread.
    pub fn start_auto_type(
        &mut self,
        ctx: &egui::Context,
        target: crate::os_protect::ForeignWindow,
        steps: Vec<crate::os_protect::TypeStep>,
    ) {
        #[cfg(test)]
        {
            let _ = (ctx, target);
            use crate::os_protect::TypeStep;
            self.auto_typed = Some(
                steps
                    .iter()
                    .map(|s| match s {
                        TypeStep::Text(t) => t.to_string(),
                        TypeStep::Tab => "{TAB}".into(),
                        TypeStep::Enter => "{ENTER}".into(),
                        TypeStep::Delay(ms) => format!("{{DELAY {ms}}}"),
                    })
                    .collect(),
            );
        }
        #[cfg(not(test))]
        {
            self.auto_type_job = Some(Job::spawn(ctx, move || {
                crate::os_protect::auto_type(&target, &steps)
            }));
        }
    }

    fn poll_auto_type(&mut self, svc: &mut Services) {
        let Some(job) = &self.auto_type_job else {
            return;
        };
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(Ok(())) => self.auto_type_job = None,
            Poll::Done(Err(e)) => {
                self.auto_type_job = None;
                svc.toasts.error(format!("Auto-type: {e}"));
            }
            Poll::Failed => {
                self.auto_type_job = None;
                svc.toasts.error("Auto-type stopped unexpectedly");
            }
        }
    }

    /// Persist the vault after a change. Returns false on failure; a
    /// conflicting external change opens a dialog instead of overwriting.
    pub fn commit(&mut self, toasts: &mut Toasts) -> bool {
        self.rev = self.rev.wrapping_add(1);
        self.settings_save_at = None;
        let ok = match self.vault.save() {
            Ok(()) => true,
            Err(VaultError::ModifiedExternally) => {
                self.modal = Some(Modal::ExternalChange);
                false
            }
            Err(e) => {
                toasts.error(format!("Couldn't save the vault: {e}"));
                false
            }
        };
        self.report_auto_backup(toasts);
        ok
    }

    fn report_auto_backup(&mut self, toasts: &mut Toasts) {
        if let Some(e) = self.vault.take_auto_backup_warning() {
            toasts.error(format!("Saved, but the automatic backup failed: {e}"));
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
        self.report_auto_backup(toasts);
    }

    /// Settings are saved after a short pause rather than on every slider
    /// movement.
    pub fn schedule_settings_save(&mut self) {
        self.settings_save_at = Some(Instant::now() + Duration::from_millis(1200));
    }

    pub fn refresh_health(&mut self, ctx: &egui::Context) {
        if self.health_rev != self.rev {
            self.health = analyze(self.vault.data(), now_unix());
            self.health_rev = self.rev;
        }
        self.poll_breach(ctx);
    }

    /// Run the offline breach check in the background whenever the vault's
    /// passwords or the configured list change.
    fn poll_breach(&mut self, ctx: &egui::Context) {
        if let Some((rev, job)) = &self.breach.job {
            match job.poll() {
                Poll::Pending => return,
                Poll::Done(r) => {
                    let list = self.vault.data().settings.breach_list.clone();
                    self.breach.checked = Some((*rev, list));
                    self.breach.report = Some(r);
                }
                Poll::Failed => {
                    self.breach.report = Some(BreachReport {
                        error: Some("The breach check stopped unexpectedly.".into()),
                        ..Default::default()
                    });
                }
            }
            self.breach.job = None;
        }
        let list = self.vault.data().settings.breach_list.clone();
        if list.is_empty() {
            self.breach.report = None;
            self.breach.checked = None;
            return;
        }
        if self.breach.checked.as_ref() == Some(&(self.rev, list.clone())) {
            return;
        }
        let mut refs = Vec::new();
        let mut passwords = Vec::new();
        for e in &self.vault.data().entries {
            for (i, f) in e.fields.iter().enumerate() {
                if f.kind == FieldKind::Password && !f.value.is_empty() {
                    refs.push(PasswordRef {
                        entry_id: e.id,
                        field_index: i,
                    });
                    passwords.push(Zeroizing::new(f.value.clone()));
                }
            }
        }
        let path = std::path::PathBuf::from(list);
        let rev = self.rev;
        self.breach.job = Some((
            rev,
            Job::spawn(ctx, move || {
                match crate::breach::check_passwords(&path, &passwords) {
                    Ok(counts) => BreachReport {
                        checked: counts.len(),
                        hits: refs
                            .into_iter()
                            .zip(counts)
                            .filter_map(|(r, c)| c.map(|c| (r, c)))
                            .collect(),
                        error: None,
                    },
                    Err(e) => BreachReport {
                        error: Some(format!("Couldn't read the breached-password list: {e}")),
                        ..Default::default()
                    },
                }
            }),
        ));
    }

    /// Copy a value from an entry and remember that the entry was used.
    pub fn copy_from(&mut self, svc: &mut Services, id: u64, value: &str, what: &str) {
        self.copy_secret(svc, value, what);
        self.vault.data_mut().mark_used(id, now_unix());
        self.schedule_settings_save();
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

    /// Move an entry to the trash (undoable from the Trash page).
    pub fn trash(&mut self, svc: &mut Services, id: u64) {
        if self.vault.data_mut().trash_entry(id) {
            if self.items.selected == Some(id) {
                self.items.selected = None;
            }
            self.items.editor = None;
            if self.commit(svc.toasts) {
                svc.toasts.with_action(
                    "Moved to Trash",
                    "Undo",
                    super::toast::ToastAction::RestoreEntry(id),
                );
            }
        }
    }

    fn poll_qr(&mut self, svc: &mut Services) {
        let Some(job) = &self.qr_job else { return };
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(Ok(uri)) => {
                self.qr_job = None;
                self.use_otpauth(&uri, svc);
            }
            Poll::Done(Err(e)) => {
                self.qr_job = None;
                svc.toasts.error(e.to_string());
            }
            Poll::Failed => {
                self.qr_job = None;
                svc.toasts.error("The QR scanner stopped unexpectedly");
            }
        }
    }

    /// Put a scanned `otpauth://` link where it belongs. With an item open
    /// in the editor it goes into that item. Otherwise it is added to the one
    /// login that matches the code's site and account, or to a new login
    /// named after the site. Nothing is saved until the user presses Save.
    pub fn use_otpauth(&mut self, uri: &str, svc: &mut Services) {
        use crate::model::{Entry, Field};
        let (issuer, account) = crate::totp::otpauth_labels(uri);
        let set_code = |e: &mut Entry| {
            match e.fields.iter_mut().find(|f| f.kind == FieldKind::Totp) {
                Some(f) => f.value = uri.to_string(),
                None => e
                    .fields
                    .push(Field::with_value("One-time code", FieldKind::Totp, uri)),
            }
            if e.title.trim().is_empty() {
                e.title = issuer.clone();
            }
            if !account.is_empty()
                && e.first_of(FieldKind::Username).is_none()
                && e.first_of(FieldKind::Email).is_none()
            {
                let kind = if account.contains('@')
                    && e.fields.iter().any(|f| f.kind == FieldKind::Email)
                {
                    FieldKind::Email
                } else {
                    FieldKind::Username
                };
                if let Some(f) = e.fields.iter_mut().find(|f| f.kind == kind) {
                    f.value = account.clone();
                }
            }
        };
        let site = if issuer.is_empty() {
            "this account".to_string()
        } else {
            issuer.clone()
        };

        if let Some(ed) = self.items.editor.as_mut() {
            set_code(&mut ed.entry);
            svc.toasts.success(format!(
                "Two-step code for {site} added — press Save to keep it"
            ));
            return;
        }
        self.page = Page::Items(Category::Logins);
        match self.find_login_for(&issuer, &account) {
            Some(id) => {
                let Some(original) = self.vault.data().entry(id).cloned() else {
                    return;
                };
                let mut entry = original.clone();
                set_code(&mut entry);
                self.items.select(id);
                self.items.editor = Some(entries::Editor::prefilled(original, entry, false));
                svc.toasts.success(format!(
                    "Two-step code added to “{}” — press Save to keep it",
                    self.vault
                        .data()
                        .entry(id)
                        .map(|e| e.display_title())
                        .unwrap_or("")
                ));
            }
            None => {
                let blank = Entry::new(EntryKind::Login);
                let mut entry = blank.clone();
                set_code(&mut entry);
                self.items.selected = None;
                self.items.editor = Some(entries::Editor::prefilled(blank, entry, true));
                svc.toasts.success(format!(
                    "New login for {site} with its two-step code — add the password and Save"
                ));
            }
        }
    }

    /// The only login without a one-time code whose title or website matches
    /// `issuer` and whose username (if any) matches `account`.
    fn find_login_for(&self, issuer: &str, account: &str) -> Option<u64> {
        let iss = issuer.trim().to_lowercase();
        if iss.is_empty() {
            return None;
        }
        let iss_compact: String = iss.chars().filter(|c| c.is_alphanumeric()).collect();
        let acc = account.trim().to_lowercase();
        let mut found = self.vault.data().entries.iter().filter(|e| {
            if e.totp_secret().is_some() {
                return false;
            }
            let title = e.title.trim().to_lowercase();
            let host = e
                .first_of(FieldKind::Url)
                .map(crate::autotype::url_host)
                .unwrap_or_default();
            let site = crate::autotype::site_name(&host).to_lowercase();
            let site_match = (!title.is_empty() && (title.contains(&iss) || iss.contains(&title)))
                || (!site.is_empty()
                    && !iss_compact.is_empty()
                    && (site == iss_compact || iss_compact.contains(&site)));
            let user = e
                .first_of(FieldKind::Username)
                .or_else(|| e.first_of(FieldKind::Email))
                .unwrap_or("")
                .trim()
                .to_lowercase();
            site_match && (acc.is_empty() || user.is_empty() || user == acc)
        });
        let first = found.next()?;
        found.next().is_none().then_some(first.id)
    }

    /// Run a clicked toast button, or Ctrl+Z for the latest one (when no
    /// text field has focus, so text undo keeps working).
    fn poll_toast_action(&mut self, ctx: &egui::Context, svc: &mut Services) {
        let typing = ctx.memory(|m| m.focused().is_some());
        if !typing && self.modal.is_none() {
            if let Some(a) = svc.toasts.latest_action() {
                if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Z)) {
                    svc.toasts.trigger(a);
                }
            }
        }
        if let Some(super::toast::ToastAction::RestoreEntry(id)) = svc.toasts.take_clicked() {
            if self.vault.data_mut().restore_entry(id) && self.commit(svc.toasts) {
                svc.toasts.info("Restored");
                // Restoring may give the item a new id if the old one is
                // taken; the restored item is the last one added.
                if let Some(e) = self.vault.data().entries.last() {
                    let id = e.id;
                    self.items.select(id);
                }
            }
        }
    }

    /// Open the quick-open palette. `from_hotkey` minimises the window again
    /// after copying, so the user lands back in the app they came from.
    pub fn open_quick_open(&mut self, from_hotkey: bool) {
        if !matches!(self.modal, Some(Modal::QuickOpen(_)))
            && !self.modal.as_ref().is_some_and(Modal::is_busy)
        {
            self.modal = Some(Modal::QuickOpen(QuickOpenState::new(from_hotkey)));
        }
    }

    /// Ask to navigate; if the editor has unsaved changes, confirm first.
    pub fn request(&mut self, nav: Nav) {
        let dirty = self.items.editor.as_ref().is_some_and(|e| e.is_dirty());
        if dirty && nav != Nav::Page(self.page.clone()) {
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
                if !matches!(self.page, Page::Tag(_)) {
                    self.page = Page::Items(c);
                }
                self.items.new_entry(k);
                if let Page::Tag(t) = &self.page {
                    if let Some(ed) = &mut self.items.editor {
                        ed.entry.add_tag(t);
                    }
                }
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
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                self.vault
                    .data_mut()
                    .log(crate::model::AuditKind::BackupCreated, &name);
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

    /// Whether Windows has locked the session. Polled at most once a second.
    fn session_locked(&mut self, now: Instant) -> bool {
        if self
            .session_checked
            .is_some_and(|t| now.duration_since(t) < Duration::from_secs(1))
        {
            return false;
        }
        self.session_checked = Some(now);
        // Headless test runners have no interactive desktop, which would look
        // exactly like a locked session.
        !cfg!(test) && crate::os_protect::is_session_locked()
    }

    pub fn show(&mut self, ctx: &egui::Context, svc: &mut Services) -> Option<Transition> {
        let now = Instant::now();

        // Automatic locking.
        let active = ctx.input(|i| {
            !i.events.is_empty() || i.pointer.is_moving() || i.raw_scroll_delta != egui::Vec2::ZERO
        });
        // Background key derivation (password change / restore) counts as
        // activity so the vault is not locked out from under it.
        if active
            || self.modal.as_ref().is_some_and(Modal::is_busy)
            || self.settings.is_busy()
            || self.hello_job.is_some()
        {
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
        if settings.lock_on_session_lock && self.session_locked(now) {
            svc.toasts.info("Locked because Windows was locked");
            return Some(Transition::Lock);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, Key::L)) {
            return Some(Transition::Lock);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, Key::K)) {
            self.open_quick_open(false);
        }
        if self.settings_save_at.is_some_and(|t| now >= t) {
            self.commit(svc.toasts);
        }

        self.refresh_health(ctx);
        self.poll_auto_type(svc);
        self.poll_hello(svc);
        self.poll_toast_action(ctx, svc);
        if std::mem::take(&mut self.qr_requested) && self.qr_job.is_none() {
            self.qr_job = Some(Job::spawn(ctx, crate::qr::scan_screen));
        }
        self.poll_qr(svc);
        let mut transition = None;

        egui::SidePanel::left("nav")
            .exact_width(220.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(Frame::new().fill(sidebar()).inner_margin(Margin {
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

        let page = self.page.clone();
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(bg())
                    .inner_margin(Margin::symmetric(28, 22)),
            )
            .show(ctx, |ui| match page {
                Page::Dashboard => dashboard::show(ui, self, svc),
                Page::Items(c) => entries::show(ui, self, svc, c, None),
                Page::Tag(t) => entries::show(ui, self, svc, Category::All, Some(&t)),
                Page::Trash => trash_page::show(ui, self, svc),
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
        // The welcome tour, once, the first time a vault is open.
        if self.tour.is_none() && !svc.prefs.tour_seen && self.modal.is_none() {
            self.tour = Some(super::tutorial::Tour::default());
        }
        if let Some(tour) = &mut self.tour {
            if super::tutorial::show(ctx, tour) {
                self.tour = None;
                if !svc.prefs.tour_seen {
                    svc.prefs.tour_seen = true;
                    svc.prefs.save();
                }
            }
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
                        let current = self.page.clone();
                        let mut item = |ui: &mut egui::Ui,
                                        icon: &str,
                                        label: &str,
                                        badge: Option<(String, egui::Color32)>,
                                        page: Page| {
                            if widgets::nav_item(ui, icon, label, badge, current == page).clicked()
                            {
                                nav = Some(Nav::Page(page));
                            }
                        };
                        item(ui, icons::HOUSE, "Overview", None, Page::Dashboard);
                        ui.add_space(10.0);
                        ui.label(section_label("    Vault"));
                        ui.add_space(2.0);
                        let data = self.vault.data();
                        for c in Category::ALL {
                            let n = data.entries.iter().filter(|e| c.includes(e)).count();
                            // Empty type categories stay out of the way.
                            if n == 0
                                && !matches!(c, Category::All | Category::Favorites)
                                && current != Page::Items(c)
                            {
                                continue;
                            }
                            let badge = (n > 0).then(|| (n.to_string(), text_faint()));
                            item(ui, c.icon(), c.label(), badge, Page::Items(c));
                        }
                        let tags = data.tags();
                        if !tags.is_empty() {
                            ui.add_space(10.0);
                            ui.label(section_label("    Tags"));
                            ui.add_space(2.0);
                            for (tag, n) in tags {
                                item(
                                    ui,
                                    icons::TAG_SIMPLE,
                                    &tag,
                                    Some((n.to_string(), text_faint())),
                                    Page::Tag(tag.clone()),
                                );
                            }
                        }
                        ui.add_space(10.0);
                        ui.label(section_label("    Tools"));
                        ui.add_space(2.0);
                        item(ui, icons::DICE_FIVE, "Generator", None, Page::Generator);
                        let breached = self.breach.report.as_ref().map_or(0, |r| r.hits.len());
                        let expired = self.health.expired.len();
                        let issues = self.health.weak.len()
                            + self.health.reused_count()
                            + breached
                            + expired
                            + self.health.expiring.len();
                        let badge = (issues > 0).then(|| {
                            let urgent = breached > 0 || expired > 0;
                            (issues.to_string(), if urgent { danger() } else { warn() })
                        });
                        item(ui, icons::SHIELD_CHECK, "Security", badge, Page::Security);
                        let trashed = self.vault.data().trash.len();
                        let badge = (trashed > 0).then(|| (trashed.to_string(), text_faint()));
                        item(ui, icons::TRASH, "Trash", badge, Page::Trash);
                        item(ui, icons::GEAR_SIX, "Settings", None, Page::Settings);
                    });
            });
        if let Some(n) = nav {
            self.request(n);
        }
        lock
    }
}
