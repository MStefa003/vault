//! Dialogs for destructive or sensitive operations.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Align2, FontId, Id, Key, Modifiers, RichText, Sense, Vec2};
use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

use super::create::{key_file_picker, secret_buffer, KeyFileChoice};
use super::icons::{self, kind_icon};
use super::jobs::{Job, Poll};
use super::main_view::{MainState, Nav};
use super::theme::*;
use super::widgets;
use super::{Services, Transition};
use crate::error::VaultError;
use crate::format::VaultFile;
use crate::i18n::tr;
use crate::import_export::{export_csv, ImportResult};
use crate::kdbx::{import_kdbx, KdbxError};
use crate::model::{AuditKind, Entry, FieldKind};
use crate::storage::{self, with_vault_extension, WriteMode};
use crate::timeutil::now_unix;
use crate::totp::Totp;
use crate::trf;
use crate::vault::{restore_backup_with, Credentials, UnlockedVault};

pub struct RestoreState {
    backup: PathBuf,
    password: Zeroizing<String>,
    reveal: bool,
    replace_current: bool,
    understood: bool,
    /// The backup's header says it needs a key file.
    needs_key_file: bool,
    key_file: KeyFileChoice,
    error: Option<String>,
    job: Option<Job<Result<UnlockedVault, VaultError>>>,
}

impl RestoreState {
    pub fn new(backup: PathBuf) -> Self {
        let needs_key_file = storage::read_vault_bytes(&backup)
            .ok()
            .and_then(|b| VaultFile::from_bytes(&b).ok())
            .is_some_and(|f| f.header.key_file);
        RestoreState {
            backup,
            password: secret_buffer(),
            reveal: false,
            replace_current: false,
            understood: false,
            needs_key_file,
            key_file: KeyFileChoice::default(),
            error: None,
            job: None,
        }
    }
}

/// What a successful re-authentication unlocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReauthAction {
    /// Show the plaintext export dialog.
    Export,
    /// Turn off "hide from screenshots and screen sharing".
    DisableCaptureProtection,
    /// Turn on Windows Hello unlock for this vault.
    EnableHello,
}

impl ReauthAction {
    fn describe(self) -> &'static str {
        match self {
            ReauthAction::Export => tr("Exporting writes every secret to an unencrypted file."),
            ReauthAction::DisableCaptureProtection => {
                tr("Screenshots and screen sharing will be able to show this window.")
            }
            ReauthAction::EnableHello => {
                tr("Windows Hello will be able to unlock this vault on this computer.")
            }
        }
    }
}

pub struct ReauthState {
    pub action: ReauthAction,
    password: Zeroizing<String>,
    reveal: bool,
    error: Option<String>,
    focus_pending: bool,
    job: Option<Job<bool>>,
}

impl ReauthState {
    pub fn new(action: ReauthAction) -> Self {
        ReauthState {
            action,
            password: secret_buffer(),
            reveal: false,
            error: None,
            focus_pending: true,
            job: None,
        }
    }
}

pub struct KdbxImportState {
    source: PathBuf,
    bytes: Zeroizing<Vec<u8>>,
    password: Zeroizing<String>,
    reveal: bool,
    error: Option<String>,
    job: Option<Job<Result<ImportResult, KdbxError>>>,
}

impl KdbxImportState {
    pub fn new(source: PathBuf, bytes: Zeroizing<Vec<u8>>) -> Self {
        KdbxImportState {
            source,
            bytes,
            password: secret_buffer(),
            reveal: false,
            error: None,
            job: None,
        }
    }
}

pub struct QuickOpenState {
    query: String,
    selected: usize,
    /// Opened by the global hotkey: minimise again after copying.
    from_hotkey: bool,
    focus: bool,
}

impl QuickOpenState {
    pub fn new(from_hotkey: bool) -> Self {
        QuickOpenState {
            query: String::new(),
            selected: 0,
            from_hotkey,
            focus: true,
        }
    }
}

pub struct AutoTypeState {
    target: crate::os_protect::ForeignWindow,
    query: String,
    selected: usize,
    focus: bool,
}

impl AutoTypeState {
    pub fn new(target: crate::os_protect::ForeignWindow) -> Self {
        AutoTypeState {
            target,
            query: String::new(),
            selected: 0,
            focus: true,
        }
    }
}

pub enum Modal {
    /// Delete one trashed item for good.
    PurgeEntry(u64),
    EmptyTrash,
    ConfirmBackupOverwrite(PathBuf),
    ImportPreview {
        source: PathBuf,
        result: ImportResult,
        /// Update the password of items that already exist with a different
        /// one (instead of adding them as separate items).
        update_changed: bool,
    },
    ExportWarning {
        understood: bool,
        typed: String,
    },
    Restore(Box<RestoreState>),
    /// The vault file changed on disk since this session read or wrote it.
    ExternalChange,
    /// Leaving the editor with unsaved changes.
    DiscardEdits(Nav),
    /// Confirm the master password before a sensitive action.
    Reauth(Box<ReauthState>),
    /// Password prompt for a KeePass database being imported.
    KdbxImport(Box<KdbxImportState>),
    /// Ctrl+K / global hotkey palette.
    QuickOpen(QuickOpenState),
    /// Pick the item to type into another application's window.
    AutoType(AutoTypeState),
    /// Password rules for one website.
    SiteRule(SiteRuleState),
}

pub struct SiteRuleState {
    host: String,
    options: crate::generator::GeneratorOptions,
    /// A rule for exactly this host is already saved.
    existing: bool,
    /// An example password for the current options.
    sample: Zeroizing<String>,
    sample_for: Option<crate::generator::GeneratorOptions>,
}

impl SiteRuleState {
    pub fn new(host: String, options: crate::generator::GeneratorOptions, existing: bool) -> Self {
        SiteRuleState {
            host,
            options,
            existing,
            sample: Zeroizing::new(String::new()),
            sample_for: None,
        }
    }
}

impl Modal {
    pub fn is_busy(&self) -> bool {
        match self {
            Modal::Restore(r) => r.job.is_some(),
            Modal::Reauth(r) => r.job.is_some(),
            Modal::KdbxImport(k) => k.job.is_some(),
            _ => false,
        }
    }
}

enum Outcome {
    Keep,
    Close,
}

pub fn show(ctx: &egui::Context, ms: &mut MainState, svc: &mut Services) -> Option<Transition> {
    let mut modal = ms.modal.take()?;
    let mut transition = None;
    let outcome = match &mut modal {
        Modal::PurgeEntry(id) => purge_entry(ctx, ms, svc, *id),
        Modal::EmptyTrash => empty_trash(ctx, ms, svc),
        Modal::Reauth(r) => reauth(ctx, ms, svc, r),
        Modal::KdbxImport(k) => kdbx_import(ctx, ms, k),
        Modal::QuickOpen(q) => quick_open(ctx, ms, svc, q),
        Modal::AutoType(a) => auto_type(ctx, ms, svc, a),
        Modal::ConfirmBackupOverwrite(path) => confirm_backup_overwrite(ctx, ms, svc, path),
        Modal::ImportPreview {
            source,
            result,
            update_changed,
        } => import_preview(ctx, ms, svc, source, result, update_changed),
        Modal::ExportWarning { understood, typed } => {
            export_warning(ctx, ms, svc, understood, typed)
        }
        Modal::Restore(r) => restore(ctx, ms, svc, r, &mut transition),
        Modal::ExternalChange => external_change(ctx, ms, svc, &mut transition),
        Modal::DiscardEdits(nav) => discard_edits(ctx, ms, nav.clone()),
        Modal::SiteRule(r) => site_rule(ctx, ms, svc, r),
    };
    // A handler may have opened a different dialog (e.g. a save conflict);
    // that one takes precedence.
    if matches!(outcome, Outcome::Keep) && ms.modal.is_none() {
        ms.modal = Some(modal);
    }
    transition
}

/// Standard two-button confirmation dialog. Returns Some(true) on confirm.
fn confirm(
    ctx: &egui::Context,
    id: &str,
    title: &str,
    body: impl FnOnce(&mut egui::Ui),
    confirm_label: &str,
    danger: bool,
) -> Option<bool> {
    let mut decision = None;
    let resp = egui::Modal::new(Id::new(id)).show(ctx, |ui| {
        ui.set_width(420.0);
        ui.label(strong(title, 16.0));
        ui.add_space(6.0);
        body(ui);
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let yes = if danger {
                widgets::danger_button(ui, confirm_label)
            } else {
                widgets::primary_button(ui, confirm_label)
            };
            if yes.clicked() {
                decision = Some(true);
            }
            if widgets::secondary_button(ui, tr("Cancel")).clicked() {
                decision = Some(false);
            }
        });
    });
    decision.or_else(|| resp.should_close().then_some(false))
}

fn purge_entry(ctx: &egui::Context, ms: &mut MainState, svc: &mut Services, id: u64) -> Outcome {
    let title = ms
        .vault
        .data()
        .trash
        .iter()
        .find(|t| t.entry.id == id)
        .map(|t| t.entry.display_title().to_string())
        .unwrap_or_default();
    match confirm(
        ctx,
        "modal_purge",
        tr("Delete forever?"),
        |ui| {
            ui.label(dim(trf!(
                "“{title}” will be removed from the vault. This can't be undone (older backups still contain it).", title
            )));
        },
        tr("Delete forever"),
        true,
    ) {
        Some(true) => {
            ms.vault.data_mut().purge_entry(id);
            ms.vault.data_mut().log(AuditKind::DeletedForever, &title);
            if ms.commit(svc.toasts) {
                svc.toasts.success(tr("Deleted"));
            }
            Outcome::Close
        }
        Some(false) => Outcome::Close,
        None => Outcome::Keep,
    }
}

fn empty_trash(ctx: &egui::Context, ms: &mut MainState, svc: &mut Services) -> Outcome {
    let n = ms.vault.data().trash.len();
    match confirm(
        ctx,
        "modal_empty_trash",
        tr("Empty the Trash?"),
        |ui| {
            ui.label(dim(crate::i18n::plural(
                n,
                tr("{n} item will be removed from the vault. This can't be undone."),
                tr("{n} items will be removed from the vault. This can't be undone."),
            )));
        },
        tr("Empty Trash"),
        true,
    ) {
        Some(true) => {
            ms.vault.data_mut().empty_trash();
            ms.vault
                .data_mut()
                .log(AuditKind::TrashEmptied, &format!("{n} items"));
            if ms.commit(svc.toasts) {
                svc.toasts.success(tr("Trash emptied"));
            }
            Outcome::Close
        }
        Some(false) => Outcome::Close,
        None => Outcome::Keep,
    }
}

/// Re-enter the master password before a sensitive action. The check is a
/// full Argon2 derivation, run off the UI thread.
fn reauth(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    r: &mut ReauthState,
) -> Outcome {
    if let Some(job) = &r.job {
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(true) => {
                r.job = None;
                match r.action {
                    ReauthAction::Export => {
                        ms.modal = Some(Modal::ExportWarning {
                            understood: false,
                            typed: String::new(),
                        });
                    }
                    ReauthAction::EnableHello => ms.start_hello_enable(ctx),
                    ReauthAction::DisableCaptureProtection => {
                        ms.vault.data_mut().settings.hide_from_capture = false;
                        ms.vault.data_mut().log(AuditKind::CaptureProtectionOff, "");
                        ms.commit(svc.toasts);
                        svc.toasts.info(tr("Screen-capture protection is off"));
                    }
                }
                return Outcome::Close;
            }
            Poll::Done(false) => {
                r.job = None;
                r.focus_pending = true;
                r.error = Some(tr("That's not the master password.").into());
            }
            Poll::Failed => {
                r.job = None;
                r.error = Some(tr("The check failed unexpectedly.").into());
            }
        }
    }
    let busy = r.job.is_some();
    let mut decision = None;
    let resp = egui::Modal::new(Id::new("modal_reauth")).show(ctx, |ui| {
        ui.set_width(420.0);
        ui.label(strong(tr("Confirm it's you"), 16.0));
        ui.add_space(4.0);
        ui.label(dim(r.action.describe()));
        ui.add_space(8.0);
        ui.label(small(tr("Master password")));
        let input = ui
            .add_enabled_ui(!busy, |ui| {
                widgets::password_input(ui, &mut r.password, &mut r.reveal, "")
            })
            .inner;
        if !busy && r.focus_pending {
            input.request_focus();
            r.focus_pending = false;
        }
        let enter = input.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        if let Some(e) = &r.error {
            widgets::error_text(ui, e);
        }
        ui.add_space(12.0);
        if busy {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(dim(tr("Checking…")));
            });
        } else {
            ui.horizontal(|ui| {
                if widgets::primary_button_enabled(ui, tr("Continue"), !r.password.is_empty())
                    .clicked()
                    || (enter && !r.password.is_empty())
                {
                    decision = Some(true);
                }
                if widgets::secondary_button(ui, tr("Cancel")).clicked() {
                    decision = Some(false);
                }
            });
        }
    });
    match decision {
        Some(true) => {
            let pw = SecretString::from(r.password.as_str().to_owned());
            r.password.zeroize();
            r.error = None;
            r.job = Some(Job::spawn(ctx, ms.vault.verify_task(pw)));
            Outcome::Keep
        }
        Some(false) => Outcome::Close,
        None if !busy && resp.should_close() => Outcome::Close,
        None => Outcome::Keep,
    }
}

fn kdbx_import(ctx: &egui::Context, ms: &mut MainState, k: &mut KdbxImportState) -> Outcome {
    if let Some(job) = &k.job {
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(Ok(result)) => {
                k.job = None;
                if result.entries.is_empty() {
                    k.error = Some(tr("No items found in that database.").into());
                } else {
                    ms.modal = Some(Modal::ImportPreview {
                        source: k.source.clone(),
                        result,
                        update_changed: true,
                    });
                    return Outcome::Close;
                }
            }
            Poll::Done(Err(e)) => {
                k.job = None;
                k.error = Some(e.to_string());
            }
            Poll::Failed => {
                k.job = None;
                k.error = Some(tr("Reading the database failed unexpectedly.").into());
            }
        }
    }
    let busy = k.job.is_some();
    let file = k
        .source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut decision = None;
    let resp = egui::Modal::new(Id::new("modal_kdbx")).show(ctx, |ui| {
        ui.set_width(440.0);
        ui.label(strong(tr("Import KeePass database"), 16.0));
        ui.add_space(4.0);
        ui.add(egui::Label::new(faint(&file)).truncate());
        ui.add_space(8.0);
        ui.label(small(tr("Database password")));
        let input = ui
            .add_enabled_ui(!busy, |ui| {
                widgets::password_input(ui, &mut k.password, &mut k.reveal, "")
            })
            .inner;
        let enter = input.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        ui.label(faint(tr(
            "Decrypted on this computer only. Attachments are not imported.",
        )));
        if let Some(e) = &k.error {
            ui.add_space(4.0);
            widgets::error_text(ui, e);
        }
        ui.add_space(12.0);
        if busy {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(dim(tr("Decrypting…")));
            });
        } else {
            ui.horizontal(|ui| {
                if widgets::primary_button(ui, tr("Open")).clicked() || enter {
                    decision = Some(true);
                }
                if widgets::secondary_button(ui, tr("Cancel")).clicked() {
                    decision = Some(false);
                }
            });
        }
    });
    match decision {
        Some(true) => {
            let pw = SecretString::from(k.password.as_str().to_owned());
            k.password.zeroize();
            k.error = None;
            let bytes = k.bytes.clone();
            k.job = Some(Job::spawn(ctx, move || import_kdbx(&bytes, &pw)));
            Outcome::Keep
        }
        Some(false) => Outcome::Close,
        None if !busy && resp.should_close() => Outcome::Close,
        None => Outcome::Keep,
    }
}

const QUICK_RESULTS: usize = 8;

/// Auto-type picker. Items matching the target window come first; typing
/// filters the whole vault. Enter types username, Tab, password, Enter;
/// Shift+Enter the password only; Ctrl+Enter the one-time code. The window
/// title is shown so the user can see where the keystrokes will go.
fn auto_type(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    a: &mut AutoTypeState,
) -> Outcome {
    use crate::autotype::{build, match_score, Sequence};

    let query = a.query.trim().to_lowercase();
    let (ids, matched): (Vec<u64>, usize) = {
        let data = ms.vault.data();
        let mut rows: Vec<(i32, i32, &Entry)> = data
            .entries
            .iter()
            .filter_map(|e| {
                let m = match_score(e, &a.target.title).unwrap_or(0);
                if query.is_empty() {
                    (m > 0).then_some((m, 0, e))
                } else {
                    e.search_score(&query).map(|s| (m, s, e))
                }
            })
            .collect();
        rows.sort_by(|(ma, sa, a), (mb, sb, b)| {
            mb.cmp(ma)
                .then_with(|| sb.cmp(sa))
                .then_with(|| b.last_used.cmp(&a.last_used))
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        let matched = rows.iter().filter(|(m, _, _)| *m > 0).count();
        if rows.is_empty() && query.is_empty() {
            // Nothing matches the window: offer recently used items.
            let mut recent: Vec<&Entry> = data.entries.iter().collect();
            recent.sort_by_key(|e| std::cmp::Reverse(e.last_used));
            rows = recent.into_iter().map(|e| (0, 0, e)).collect();
        }
        (
            rows.into_iter()
                .take(QUICK_RESULTS)
                .map(|(_, _, e)| e.id)
                .collect(),
            matched,
        )
    };
    if a.selected >= ids.len() {
        a.selected = ids.len().saturating_sub(1);
    }

    let (up, down, seq, escape) = ctx.input_mut(|i| {
        let seq = if i.consume_key(Modifiers::COMMAND, Key::Enter) {
            Some(Sequence::Code)
        } else if i.consume_key(Modifiers::SHIFT, Key::Enter) {
            Some(Sequence::Password)
        } else if i.consume_key(Modifiers::NONE, Key::Enter) {
            Some(Sequence::Login)
        } else {
            None
        };
        (
            i.consume_key(Modifiers::NONE, Key::ArrowUp),
            i.consume_key(Modifiers::NONE, Key::ArrowDown),
            seq,
            i.consume_key(Modifiers::NONE, Key::Escape),
        )
    });
    if up {
        a.selected = a.selected.saturating_sub(1);
    }
    if down && a.selected + 1 < ids.len() {
        a.selected += 1;
    }
    let mut clicked = None;

    egui::Modal::new(Id::new("modal_auto_type")).show(ctx, |ui| {
        ui.set_width(560.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            ui.label(RichText::new(icons::KEYBOARD).size(16.0).color(text_dim()));
            ui.label(faint(tr("Type into")));
        });
        let title = if a.target.title.trim().is_empty() {
            tr("(untitled window)").to_string()
        } else {
            a.target.title.clone()
        };
        ui.add(egui::Label::new(strong(title, 15.0)).truncate());
        ui.add_space(8.0);
        let resp = ui.add(
            egui::TextEdit::singleline(&mut a.query)
                .hint_text(hint(trf!(
                    "{}  Search for another item",
                    icons::MAGNIFYING_GLASS
                )))
                .desired_width(f32::INFINITY)
                .margin(Vec2::new(12.0, 8.0)),
        );
        if a.focus || !resp.has_focus() {
            resp.request_focus();
            a.focus = false;
        }
        if resp.changed() {
            a.selected = 0;
        }
        ui.add_space(6.0);
        if query.is_empty() {
            ui.label(faint(if matched > 0 {
                tr("Matching this window")
            } else {
                tr("No item matches this window — recently used")
            }));
            ui.add_space(2.0);
        }
        let data = ms.vault.data();
        if ids.is_empty() {
            ui.add_space(8.0);
            ui.label(dim(tr("No matches.")));
            ui.add_space(8.0);
        }
        for (i, id) in ids.iter().enumerate() {
            let Some(e) = data.entry(*id) else { continue };
            let (rect, row) =
                ui.allocate_exact_size(Vec2::new(ui.available_width(), 38.0), Sense::click());
            let p = ui.painter();
            if i == a.selected {
                p.rect_filled(rect, RADIUS_SM, surface_2());
            } else if row.hovered() {
                p.rect_filled(rect, RADIUS_SM, row_hover());
            }
            p.text(
                rect.left_center() + Vec2::new(14.0, 0.0),
                Align2::CENTER_CENTER,
                kind_icon(e.kind),
                FontId::proportional(15.0),
                text_faint(),
            );
            let t = p.text(
                rect.left_center() + Vec2::new(34.0, 0.0),
                Align2::LEFT_CENTER,
                e.display_title(),
                FontId::proportional(14.0),
                text(),
            );
            ui.painter_at(rect.shrink2(Vec2::new(8.0, 0.0))).text(
                egui::pos2(t.right() + 10.0, rect.center().y),
                Align2::LEFT_CENTER,
                e.subtitle(),
                FontId::proportional(12.5),
                text_faint(),
            );
            if row.clicked() {
                a.selected = i;
                clicked = Some(Sequence::Login);
            }
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 14.0;
            for hint in [
                tr("Enter  username + password"),
                tr("Shift+Enter  password"),
                tr("Ctrl+Enter  one-time code"),
                tr("Esc  cancel"),
            ] {
                ui.label(faint(hint));
            }
        });
    });

    if escape {
        return Outcome::Close;
    }
    let Some(seq) = seq.or(clicked) else {
        return Outcome::Keep;
    };
    let Some(&id) = ids.get(a.selected) else {
        return Outcome::Keep;
    };
    let built = match ms.vault.data().entry(id) {
        Some(e) => build(e, seq, now_unix()),
        None => return Outcome::Close,
    };
    match built {
        Ok(steps) => {
            ms.vault.data_mut().mark_used(id, now_unix());
            ms.schedule_settings_save();
            ms.start_auto_type(ctx, a.target.clone(), steps);
            Outcome::Close
        }
        Err(reason) => {
            svc.toasts.info(reason);
            Outcome::Keep
        }
    }
}

/// Keyboard-first palette: type to filter, arrows to choose, then
/// Enter = copy password, Shift+Enter = copy username,
/// Ctrl+Enter = copy one-time code, Ctrl+O = open the item.
fn quick_open(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    q: &mut QuickOpenState,
) -> Outcome {
    let query = q.query.trim().to_lowercase();
    let ids: Vec<u64> = {
        let data = ms.vault.data();
        let mut hits: Vec<(i32, &Entry)> = data
            .entries
            .iter()
            .filter_map(|e| e.search_score(&query).map(|s| (s, e)))
            .collect();
        hits.sort_by(|(sa, a), (sb, b)| {
            if query.is_empty() {
                b.last_used
                    .cmp(&a.last_used)
                    .then_with(|| b.favorite.cmp(&a.favorite))
                    .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
            } else {
                sb.cmp(sa).then_with(|| b.last_used.cmp(&a.last_used))
            }
        });
        hits.into_iter()
            .take(QUICK_RESULTS)
            .map(|(_, e)| e.id)
            .collect()
    };
    if q.selected >= ids.len() {
        q.selected = ids.len().saturating_sub(1);
    }

    #[derive(Clone, Copy)]
    enum Want {
        Password,
        Username,
        Code,
        Open,
    }
    let (up, down, want, escape) = ctx.input_mut(|i| {
        let want = if i.consume_key(Modifiers::COMMAND, Key::Enter) {
            Some(Want::Code)
        } else if i.consume_key(Modifiers::SHIFT, Key::Enter) {
            Some(Want::Username)
        } else if i.consume_key(Modifiers::NONE, Key::Enter) {
            Some(Want::Password)
        } else if i.consume_key(Modifiers::COMMAND, Key::O) {
            Some(Want::Open)
        } else {
            None
        };
        (
            i.consume_key(Modifiers::NONE, Key::ArrowUp),
            i.consume_key(Modifiers::NONE, Key::ArrowDown),
            want,
            i.consume_key(Modifiers::NONE, Key::Escape),
        )
    });
    if up {
        q.selected = q.selected.saturating_sub(1);
    }
    if down && q.selected + 1 < ids.len() {
        q.selected += 1;
    }
    let mut clicked = None;

    egui::Modal::new(Id::new("modal_quick_open")).show(ctx, |ui| {
        ui.set_width(560.0);
        let resp = ui.add(
            egui::TextEdit::singleline(&mut q.query)
                .hint_text(hint(trf!("{}  Search the vault", icons::MAGNIFYING_GLASS)))
                .font(FontId::proportional(16.0))
                .desired_width(f32::INFINITY)
                .margin(Vec2::new(12.0, 10.0)),
        );
        if q.focus || !resp.has_focus() {
            resp.request_focus();
            q.focus = false;
        }
        if resp.changed() {
            q.selected = 0;
        }
        ui.add_space(6.0);
        let data = ms.vault.data();
        if ids.is_empty() {
            ui.add_space(8.0);
            ui.label(dim(tr("No matches.")));
            ui.add_space(8.0);
        }
        for (i, id) in ids.iter().enumerate() {
            let Some(e) = data.entry(*id) else { continue };
            let (rect, row) =
                ui.allocate_exact_size(Vec2::new(ui.available_width(), 36.0), Sense::click());
            let p = ui.painter();
            if i == q.selected {
                p.rect_filled(rect, RADIUS_SM, surface_2());
            } else if row.hovered() {
                p.rect_filled(rect, RADIUS_SM, row_hover());
            }
            p.text(
                rect.left_center() + Vec2::new(14.0, 0.0),
                Align2::CENTER_CENTER,
                kind_icon(e.kind),
                FontId::proportional(15.0),
                text_faint(),
            );
            let title = p.text(
                rect.left_center() + Vec2::new(34.0, 0.0),
                Align2::LEFT_CENTER,
                e.display_title(),
                FontId::proportional(14.0),
                text(),
            );
            ui.painter_at(rect.shrink2(Vec2::new(8.0, 0.0))).text(
                egui::pos2(title.right() + 10.0, rect.center().y),
                Align2::LEFT_CENTER,
                e.subtitle(),
                FontId::proportional(12.5),
                text_faint(),
            );
            if row.clicked() {
                q.selected = i;
                clicked = Some(Want::Password);
            }
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 14.0;
            for hint in [
                tr("Enter  copy password"),
                tr("Shift+Enter  username"),
                tr("Ctrl+Enter  one-time code"),
                tr("Ctrl+O  open"),
                tr("Esc  close"),
            ] {
                ui.label(faint(hint));
            }
        });
    });

    if escape {
        return Outcome::Close;
    }
    let Some(want) = want.or(clicked) else {
        return Outcome::Keep;
    };
    let Some(&id) = ids.get(q.selected) else {
        return Outcome::Keep;
    };
    let (value, what): (Option<Zeroizing<String>>, &str) = {
        let Some(e) = ms.vault.data().entry(id) else {
            return Outcome::Close;
        };
        match want {
            Want::Password => (
                e.first_of(FieldKind::Password)
                    .map(|v| Zeroizing::new(v.to_string())),
                tr("Password"),
            ),
            Want::Username => (
                e.first_of(FieldKind::Username)
                    .or_else(|| e.first_of(FieldKind::Email))
                    .map(|v| Zeroizing::new(v.to_string())),
                tr("Username"),
            ),
            Want::Code => (
                e.totp_secret()
                    .and_then(|s| Totp::parse(s).ok())
                    .map(|t| Zeroizing::new(t.code_at(now_unix()))),
                tr("One-time code"),
            ),
            Want::Open => (None, ""),
        }
    };
    if matches!(want, Want::Open) {
        ms.request(Nav::Open(id));
        return Outcome::Close;
    }
    match value {
        Some(v) => {
            ms.copy_from(svc, id, &v, what);
            let lock_on_minimize = ms.vault.data().settings.lock_on_minimize;
            // Minimising would lock (and clear the clipboard) with
            // lock-on-minimise on, so only hide the window otherwise.
            if q.from_hotkey && !lock_on_minimize {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
            Outcome::Close
        }
        None => {
            svc.toasts
                .info(trf!("This item has no {}", what.to_lowercase()));
            Outcome::Keep
        }
    }
}

/// Length and character sets the generator uses for one website, for sites
/// that refuse long passwords or certain symbols.
fn site_rule(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    r: &mut SiteRuleState,
) -> Outcome {
    use crate::generator::{generate_password, MAX_LENGTH, MIN_LENGTH};
    let mut outcome = Outcome::Keep;
    let g = &mut r.options;
    let resp = egui::Modal::new(Id::new("modal_site_rule")).show(ctx, |ui| {
        ui.set_width(440.0);
        ui.label(strong(trf!("Password rules for {}", r.host), 16.0));
        ui.add_space(4.0);
        ui.label(dim(tr(
            "Used whenever VaultRust generates a password for this site or its subdomains. \
             Match what the site's sign-up page allows.",
        )));
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(small(tr("Length")));
            ui.add_sized(
                [56.0, 26.0],
                egui::DragValue::new(&mut g.length).range(MIN_LENGTH..=MAX_LENGTH),
            );
            ui.spacing_mut().slider_width = 240.0;
            widgets::slider(
                ui,
                egui::Slider::new(&mut g.length, MIN_LENGTH..=64)
                    .clamping(egui::SliderClamping::Never),
            );
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.label(small(tr("Characters")));
            super::generator_page::chip(ui, &mut g.uppercase, "A–Z");
            super::generator_page::chip(ui, &mut g.lowercase, "a–z");
            super::generator_page::chip(ui, &mut g.digits, "0–9");
            super::generator_page::chip(ui, &mut g.symbols, "!#$%&*");
        });
        ui.add_space(6.0);
        widgets::switch_row(
            ui,
            &mut g.exclude_ambiguous,
            tr("Avoid look-alike characters"),
            crate::generator::AMBIGUOUS,
        );
        widgets::switch_row(
            ui,
            &mut g.require_each_class,
            tr("Use every selected set at least once"),
            "",
        );
        widgets::setting_row(
            ui,
            tr("Extra characters"),
            tr("Symbols the site accepts, e.g. !@#"),
            170.0,
            |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut g.custom_chars)
                        .desired_width(160.0)
                        .font(egui::TextStyle::Monospace)
                        .margin(Vec2::new(8.0, 5.0)),
                );
            },
        );
        widgets::switch_row(
            ui,
            &mut g.custom_only,
            tr("Use only the extra characters"),
            "",
        );
        g.sanitize();
        if r.sample_for.as_ref() != Some(g) {
            r.sample = generate_password(g).unwrap_or_else(|e| Zeroizing::new(format!("({e})")));
            r.sample_for = Some(g.clone());
        }
        ui.add_space(8.0);
        ui.label(faint(tr("Example")));
        ui.add(
            egui::Label::new(
                RichText::new(r.sample.as_str())
                    .family(egui::FontFamily::Monospace)
                    .color(text()),
            )
            .wrap(),
        );
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let ok = generate_password(g).is_ok();
            if widgets::primary_button_enabled(ui, tr("Save rules"), ok).clicked() {
                let host = r.host.clone();
                let saved = ms.vault.data_mut().settings.set_site_rule(&host, g.clone());
                match saved {
                    Some(host) => {
                        if ms.commit(svc.toasts) {
                            svc.toasts
                                .success(trf!("Password rules saved for {host}", host));
                        }
                    }
                    None => svc.toasts.error(trf!(
                        "Couldn't save the rules: a vault holds at most {} site rules",
                        crate::model::MAX_SITE_RULES
                    )),
                }
                outcome = Outcome::Close;
            }
            if widgets::secondary_button(ui, tr("Cancel")).clicked() {
                outcome = Outcome::Close;
            }
            if r.existing {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if widgets::link_button(ui, tr("Remove rules")).clicked() {
                        if ms.vault.data_mut().settings.remove_site_rule(&r.host)
                            && ms.commit(svc.toasts)
                        {
                            svc.toasts
                                .info(trf!("{} uses the default generator settings again", r.host));
                        }
                        outcome = Outcome::Close;
                    }
                });
            }
        });
    });
    if resp.should_close() {
        outcome = Outcome::Close;
    }
    outcome
}

fn discard_edits(ctx: &egui::Context, ms: &mut MainState, nav: Nav) -> Outcome {
    match confirm(
        ctx,
        "modal_discard",
        tr("Discard changes?"),
        |ui| {
            ui.label(dim(tr("Your edits to this item haven't been saved.")));
        },
        tr("Discard"),
        true,
    ) {
        Some(true) => {
            ms.items.editor = None;
            ms.perform(nav);
            Outcome::Close
        }
        Some(false) => Outcome::Close,
        None => Outcome::Keep,
    }
}

fn external_change(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    transition: &mut Option<Transition>,
) -> Outcome {
    let mut choice = None;
    egui::Modal::new(Id::new("modal_external")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.label(strong(tr("The vault file changed on disk"), 16.0));
        ui.add_space(6.0);
        ui.label(dim(
            tr("Another VaultRust window, a sync tool or a restore modified the file after you opened \
             it. Your latest change has not been saved yet."),
        ));
        ui.add_space(8.0);
        ui.label(small(
            tr("Reload: lock and reopen the file from disk. Your unsaved change is lost."),
        ));
        ui.label(small(
            tr("Keep mine: overwrite the file with this window's version. The other changes are lost."),
        ));
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if widgets::primary_button(ui, tr("Reload")).clicked() {
                choice = Some(0);
            }
            if widgets::danger_button(ui, tr("Keep mine")).clicked() {
                choice = Some(1);
            }
        });
    });
    match choice {
        Some(0) => {
            *transition = Some(Transition::Reload);
            Outcome::Close
        }
        Some(_) => {
            match ms.vault.save_overwriting_external_changes() {
                Ok(()) => svc.toasts.success(tr("Saved your version")),
                Err(e) => svc.toasts.error(trf!("Couldn't save: {e}", e)),
            }
            Outcome::Close
        }
        None => Outcome::Keep,
    }
}

fn confirm_backup_overwrite(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    path: &Path,
) -> Outcome {
    match confirm(
        ctx,
        "modal_backup_overwrite",
        tr("Replace existing file?"),
        |ui| {
            ui.add(egui::Label::new(dim(path.display().to_string())).wrap());
            ui.label(dim(tr(
                "Its current contents will be replaced by this backup.",
            )));
        },
        tr("Replace"),
        true,
    ) {
        Some(true) => {
            ms.do_backup(path, true, svc);
            Outcome::Close
        }
        Some(false) => Outcome::Close,
        None => Outcome::Keep,
    }
}

/// How an imported item relates to what is already in the vault.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportFate {
    New,
    /// Same account with the same password: skipped.
    Identical,
    /// Same account, different password.
    Changed(u64),
}

fn import_preview(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    source: &Path,
    result: &mut ImportResult,
    update_changed: &mut bool,
) -> Outcome {
    let fates: Vec<ImportFate> = {
        let data = ms.vault.data();
        result
            .entries
            .iter()
            .map(|e| match data.find_duplicate(e) {
                None => ImportFate::New,
                Some((_, true)) => ImportFate::Identical,
                Some((id, false)) => ImportFate::Changed(id),
            })
            .collect()
    };
    let count = |f: fn(&ImportFate) -> bool| fates.iter().filter(|x| f(x)).count();
    let new = count(|f| *f == ImportFate::New);
    let identical = count(|f| *f == ImportFate::Identical);
    let changed = count(|f| matches!(f, ImportFate::Changed(_)));
    let skipped_rows = result.skipped;
    let format = result.format;
    let file = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let to_add = new + if *update_changed { 0 } else { changed };
    let to_update = if *update_changed { changed } else { 0 };
    let title = match (to_add, to_update) {
        (0, 0) => tr("Nothing new to import").to_string(),
        (a, 0) => crate::i18n::plural(a, tr("Import {n} item"), tr("Import {n} items")),
        (0, u) => crate::i18n::plural(u, tr("Update {n} item"), tr("Update {n} items")),
        (a, u) => trf!("Import {a}, update {u}", a, u),
    };
    let entries = &result.entries;
    let mut decision = None;
    let resp = egui::Modal::new(Id::new("modal_import")).show(ctx, |ui| {
        ui.set_width(480.0);
        ui.label(strong(&title, 16.0));
        ui.add_space(4.0);
        let mut line = trf!("From {file} ({format})", file, format);
        if skipped_rows > 0 {
            line.push_str(&trf!(
                " · {skipped_rows} empty or unreadable rows skipped",
                skipped_rows
            ));
        }
        ui.label(dim(line));
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            widgets::pill(ui, &trf!("{new} new", new), accent());
            if identical > 0 {
                widgets::pill(
                    ui,
                    &trf!("{identical} already in the vault", identical),
                    text_dim(),
                );
            }
            if changed > 0 {
                widgets::pill(
                    ui,
                    &trf!("{changed} with a different password", changed),
                    warn(),
                );
            }
        });
        if identical > 0 {
            ui.label(faint(tr(
                "Items already in the vault with the same password are skipped.",
            )));
        }
        if changed > 0 {
            ui.add_space(4.0);
            ui.checkbox(
                update_changed,
                tr("Update their passwords (the current ones are kept in password history)"),
            );
            if !*update_changed {
                ui.label(faint(tr("They will be added as separate items instead.")));
            }
        }
        ui.add_space(6.0);
        egui::Frame::new()
            .fill(input())
            .corner_radius(RADIUS_SM)
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical()
                    .max_height(170.0)
                    .show(ui, |ui| {
                        for (e, fate) in entries.iter().zip(&fates).take(200) {
                            widgets::trailing_row_h(
                                ui,
                                22.0,
                                egui::Align::Center,
                                |ui| {
                                    let (text, color) = match fate {
                                        ImportFate::New => ("new", accent()),
                                        ImportFate::Identical => ("skip", text_faint()),
                                        ImportFate::Changed(_) if *update_changed => {
                                            ("update", warn())
                                        }
                                        ImportFate::Changed(_) => (tr("new copy"), text_dim()),
                                    };
                                    ui.label(RichText::new(text).size(12.0).color(color));
                                },
                                |ui| {
                                    let color = if *fate == ImportFate::Identical {
                                        text_faint()
                                    } else {
                                        text()
                                    };
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(icons::with(
                                                kind_icon(e.kind),
                                                e.display_title(),
                                            ))
                                            .color(color),
                                        )
                                        .truncate(),
                                    );
                                },
                            );
                        }
                        if entries.len() > 200 {
                            ui.label(faint(trf!("and {} more", entries.len() - 200)));
                        }
                    });
            });
        ui.add_space(8.0);
        widgets::warning_box(
            ui,
            &trf!(
                "{file} is not encrypted. Delete it after importing and empty the Recycle Bin. \
                 On SSDs, deleted data may still be recoverable.",
                file
            ),
        );
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            let any = to_add + to_update > 0;
            if widgets::primary_button_enabled(
                ui,
                if any { tr("Import") } else { tr("Close") },
                true,
            )
            .clicked()
            {
                decision = Some(any);
            }
            if any && widgets::secondary_button(ui, tr("Cancel")).clicked() {
                decision = Some(false);
            }
        });
    });
    match decision.or_else(|| resp.should_close().then_some(false)) {
        Some(true) => {
            let update = *update_changed;
            let d = ms.vault.data_mut();
            for (e, fate) in result.entries.drain(..).zip(fates) {
                match fate {
                    ImportFate::New => d.upsert(e),
                    ImportFate::Identical => {}
                    ImportFate::Changed(id) if update => {
                        if let Some(mut existing) = d.entry(id).cloned() {
                            let pw = e.primary_password().unwrap_or("").to_string();
                            if let Some(f) = existing
                                .fields
                                .iter_mut()
                                .find(|f| f.kind == FieldKind::Password && !f.value.is_empty())
                            {
                                f.value = pw;
                            }
                            for t in &e.tags {
                                existing.add_tag(t);
                            }
                            d.upsert(existing);
                        }
                    }
                    ImportFate::Changed(_) => d.upsert(e),
                }
            }
            d.log(
                AuditKind::Imported,
                &trf!(
                    "{to_add} added, {to_update} updated from {file}",
                    to_add,
                    to_update,
                    file
                ),
            );
            if ms.commit(svc.toasts) {
                svc.toasts.success(match (to_add, to_update) {
                    (a, 0) => {
                        crate::i18n::plural(a, tr("Imported {n} item"), tr("Imported {n} items"))
                    }
                    (a, u) => trf!("Imported {a}, updated {u}", a, u),
                });
            }
            Outcome::Close
        }
        Some(false) => Outcome::Close,
        None => Outcome::Keep,
    }
}

fn export_warning(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    understood: &mut bool,
    typed: &mut String,
) -> Outcome {
    let mut decision = None;
    let resp = egui::Modal::new(Id::new("modal_export")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.label(strong(tr("Export as plain CSV"), 16.0));
        ui.add_space(6.0);
        widgets::danger_box(
            ui,
            tr("This writes every password, card number, key and note in the vault to an unencrypted \
             file. Any program or person that can read the file gets all of them."),
        );
        ui.add_space(6.0);
        ui.label(dim(
            tr("For safekeeping use an encrypted backup instead. Only export to move to another \
             password manager, and delete the file straight after."),
        ));
        ui.add_space(8.0);
        ui.checkbox(understood, tr("I understand the risk"));
        ui.label(small(tr("Type EXPORT to continue")));
        widgets::text_input(ui, typed, "");
        ui.add_space(12.0);
        let ok = *understood && typed.trim() == "EXPORT";
        ui.horizontal(|ui| {
            if widgets::danger_button_enabled(ui, tr("Choose file…"), ok).clicked() {
                decision = Some(true);
            }
            if widgets::secondary_button(ui, tr("Cancel")).clicked() {
                decision = Some(false);
            }
        });
    });
    match decision.or_else(|| resp.should_close().then_some(false)) {
        Some(true) => {
            let dlg = rfd::FileDialog::new()
                .set_title(tr("Save plain CSV export"))
                .add_filter("CSV", &["csv"])
                .set_file_name("vaultrust-export-UNENCRYPTED.csv");
            if let Some(path) = dlg.save_file() {
                // The OS save dialog has already confirmed replacing a file.
                let bytes = export_csv(ms.vault.data());
                match storage::atomic_write(&path, &bytes, WriteMode::Replace) {
                    Ok(()) => {
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        ms.vault.data_mut().log(AuditKind::Exported, &name);
                        ms.commit(svc.toasts);
                        svc.toasts.info(trf!(
                            "Exported to {} — delete it when you're done",
                            path.display()
                        ))
                    }
                    Err(e) => svc.toasts.error(trf!("Export failed: {e}", e)),
                }
            }
            Outcome::Close
        }
        Some(false) => Outcome::Close,
        None => Outcome::Keep,
    }
}

fn restore(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    r: &mut RestoreState,
    transition: &mut Option<Transition>,
) -> Outcome {
    if let Some(job) = &r.job {
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(Ok(mut v)) => {
                r.job = None;
                let name = r
                    .backup
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                v.data_mut().log(AuditKind::Restored, &name);
                svc.toasts.success(tr("Backup restored"));
                *transition = Some(Transition::Open(Box::new(v)));
                return Outcome::Close;
            }
            Poll::Done(Err(e)) => {
                r.job = None;
                r.error = Some(match e {
                    VaultError::WrongPasswordOrTampered if r.needs_key_file => {
                        tr("Wrong password or key file for this backup.").into()
                    }
                    VaultError::WrongPasswordOrTampered => {
                        tr("Wrong password for this backup.").into()
                    }
                    other => other.to_string(),
                });
            }
            Poll::Failed => {
                r.job = None;
                r.error = Some(tr("Restore failed unexpectedly.").into());
            }
        }
    }
    let busy = r.job.is_some();
    let mut decision = None;
    let resp = egui::Modal::new(Id::new("modal_restore")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.label(strong(tr("Restore backup"), 16.0));
        ui.add_space(4.0);
        ui.add(egui::Label::new(faint(r.backup.display().to_string())).truncate());
        ui.add_space(8.0);
        ui.add_enabled_ui(!busy, |ui| {
            ui.label(small(tr("Master password of the backup")));
            widgets::password_input(ui, &mut r.password, &mut r.reveal, "");
            if r.needs_key_file {
                ui.add_space(4.0);
                ui.label(small(tr("Key file of the backup")));
                key_file_picker(ui, &mut r.key_file, false);
            }
            ui.add_space(6.0);
            ui.radio_value(&mut r.replace_current, false, tr("Restore to a new file"));
            ui.radio_value(&mut r.replace_current, true, tr("Replace the open vault"));
            if r.replace_current {
                widgets::danger_box(
                    ui,
                    tr("Anything added since the backup was made will be lost."),
                );
                ui.checkbox(&mut r.understood, tr("Replace the open vault"));
            }
        });
        if let Some(e) = &r.error {
            ui.add_space(4.0);
            widgets::error_text(ui, e);
        }
        ui.add_space(12.0);
        if busy {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(dim(tr("Checking and restoring…")));
            });
        } else {
            ui.horizontal(|ui| {
                let ok = !r.password.is_empty()
                    && (!r.replace_current || r.understood)
                    && (!r.needs_key_file || r.key_file.is_chosen());
                if widgets::primary_button_enabled(ui, tr("Restore"), ok).clicked() {
                    decision = Some(true);
                }
                if widgets::secondary_button(ui, tr("Cancel")).clicked() {
                    decision = Some(false);
                }
            });
        }
    });
    match decision {
        Some(true) => {
            let dest = if r.replace_current {
                Some(ms.vault.path().to_path_buf())
            } else {
                let stem = r
                    .backup
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "restored".into());
                rfd::FileDialog::new()
                    .set_title(tr("Save restored vault as"))
                    .add_filter(tr("VaultRust vault"), &["vault"])
                    .set_file_name(format!("{stem}-restored.vault"))
                    .save_file()
                    .map(with_vault_extension)
            };
            let Some(dest) = dest else {
                return Outcome::Keep;
            };
            if !r.replace_current && dest.exists() {
                r.error = Some(tr("That file already exists. Choose a new name.").into());
                return Outcome::Keep;
            }
            // Make sure nothing pending is written over the restored file.
            ms.flush(svc.toasts);
            let key_file = match r.key_file.load() {
                Ok(k) => k,
                Err(e) => {
                    r.error = Some(e);
                    return Outcome::Keep;
                }
            };
            let creds = Credentials::with_key_file(
                SecretString::from(r.password.as_str().to_owned()),
                key_file,
            );
            r.password.zeroize();
            let backup = r.backup.clone();
            let overwrite = r.replace_current;
            r.error = None;
            r.job = Some(Job::spawn(ctx, move || {
                restore_backup_with(&backup, &creds, &dest, overwrite)
            }));
            Outcome::Keep
        }
        Some(false) => Outcome::Close,
        None if !busy && resp.should_close() => Outcome::Close,
        None => Outcome::Keep,
    }
}
