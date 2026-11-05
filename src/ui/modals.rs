//! Dialogs for destructive or sensitive operations.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Id, RichText};
use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

use super::create::secret_buffer;
use super::icons::{self, kind_icon};
use super::jobs::{Job, Poll};
use super::main_view::{MainState, Nav};
use super::theme::*;
use super::widgets;
use super::{Services, Transition};
use crate::error::VaultError;
use crate::import_export::{export_csv, ImportResult};
use crate::storage::{self, with_vault_extension, WriteMode};
use crate::vault::{restore_backup, UnlockedVault};

pub struct RestoreState {
    backup: PathBuf,
    password: Zeroizing<String>,
    reveal: bool,
    replace_current: bool,
    understood: bool,
    error: Option<String>,
    job: Option<Job<Result<UnlockedVault, VaultError>>>,
}

impl RestoreState {
    pub fn new(backup: PathBuf) -> Self {
        RestoreState {
            backup,
            password: secret_buffer(),
            reveal: false,
            replace_current: false,
            understood: false,
            error: None,
            job: None,
        }
    }
}

pub enum Modal {
    DeleteEntry(u64),
    ConfirmBackupOverwrite(PathBuf),
    ImportPreview {
        source: PathBuf,
        result: ImportResult,
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
}

impl Modal {
    pub fn is_busy(&self) -> bool {
        matches!(self, Modal::Restore(r) if r.job.is_some())
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
        Modal::DeleteEntry(id) => delete_entry(ctx, ms, svc, *id),
        Modal::ConfirmBackupOverwrite(path) => confirm_backup_overwrite(ctx, ms, svc, path),
        Modal::ImportPreview { source, result } => import_preview(ctx, ms, svc, source, result),
        Modal::ExportWarning { understood, typed } => {
            export_warning(ctx, ms, svc, understood, typed)
        }
        Modal::Restore(r) => restore(ctx, ms, svc, r, &mut transition),
        Modal::ExternalChange => external_change(ctx, ms, svc, &mut transition),
        Modal::DiscardEdits(nav) => discard_edits(ctx, ms, *nav),
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
            if widgets::secondary_button(ui, "Cancel").clicked() {
                decision = Some(false);
            }
        });
    });
    decision.or_else(|| resp.should_close().then_some(false))
}

fn delete_entry(ctx: &egui::Context, ms: &mut MainState, svc: &mut Services, id: u64) -> Outcome {
    let title = ms
        .vault
        .data()
        .entry(id)
        .map(|e| e.display_title().to_string())
        .unwrap_or_default();
    match confirm(
        ctx,
        "modal_delete",
        "Delete item?",
        |ui| {
            ui.label(dim(format!("“{title}” will be removed permanently.")));
        },
        "Delete",
        true,
    ) {
        Some(true) => {
            ms.vault.data_mut().remove(id);
            ms.items.selected = None;
            ms.items.editor = None;
            if ms.commit(svc.toasts) {
                svc.toasts.success("Deleted");
            }
            Outcome::Close
        }
        Some(false) => Outcome::Close,
        None => Outcome::Keep,
    }
}

fn discard_edits(ctx: &egui::Context, ms: &mut MainState, nav: Nav) -> Outcome {
    match confirm(
        ctx,
        "modal_discard",
        "Discard changes?",
        |ui| {
            ui.label(dim("Your edits to this item haven't been saved."));
        },
        "Discard",
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
        ui.label(strong("The vault file changed on disk", 16.0));
        ui.add_space(6.0);
        ui.label(dim(
            "Another VaultRust window, a sync tool or a restore modified the file after you opened \
             it. Your latest change has not been saved yet.",
        ));
        ui.add_space(8.0);
        ui.label(small(
            "Reload: lock and reopen the file from disk. Your unsaved change is lost.",
        ));
        ui.label(small(
            "Keep mine: overwrite the file with this window's version. The other changes are lost.",
        ));
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if widgets::primary_button(ui, "Reload").clicked() {
                choice = Some(0);
            }
            if widgets::danger_button(ui, "Keep mine").clicked() {
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
                Ok(()) => svc.toasts.success("Saved your version"),
                Err(e) => svc.toasts.error(format!("Couldn't save: {e}")),
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
        "Replace existing file?",
        |ui| {
            ui.add(egui::Label::new(dim(path.display().to_string())).wrap());
            ui.label(dim("Its current contents will be replaced by this backup."));
        },
        "Replace",
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

fn import_preview(
    ctx: &egui::Context,
    ms: &mut MainState,
    svc: &mut Services,
    source: &Path,
    result: &mut ImportResult,
) -> Outcome {
    let n = result.entries.len();
    let skipped = result.skipped;
    let format = result.format;
    let file = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let entries = &result.entries;
    let decision = confirm(
        ctx,
        "modal_import",
        &format!("Import {n} item{}", if n == 1 { "" } else { "s" }),
        |ui| {
            let mut line = format!("From {file} ({format})");
            if skipped > 0 {
                line.push_str(&format!(" · {skipped} empty or unreadable rows skipped"));
            }
            ui.label(dim(line));
            ui.add_space(6.0);
            egui::Frame::new()
                .fill(INPUT)
                .corner_radius(6.0)
                .inner_margin(8.0)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::ScrollArea::vertical()
                        .max_height(170.0)
                        .show(ui, |ui| {
                            for e in entries.iter().take(200) {
                                ui.label(
                                    RichText::new(icons::with(
                                        kind_icon(e.kind),
                                        e.display_title(),
                                    ))
                                    .color(TEXT),
                                );
                            }
                            if entries.len() > 200 {
                                ui.label(faint(format!("and {} more", entries.len() - 200)));
                            }
                        });
                });
            ui.add_space(8.0);
            widgets::warning_box(
                ui,
                &format!(
                    "{file} is not encrypted. Delete it after importing and empty the Recycle Bin. \
                     On SSDs, deleted data may still be recoverable."
                ),
            );
        },
        "Import",
        false,
    );
    match decision {
        Some(true) => {
            let d = ms.vault.data_mut();
            for e in result.entries.drain(..) {
                d.upsert(e);
            }
            if ms.commit(svc.toasts) {
                svc.toasts.success(format!(
                    "Imported {n} item{}",
                    if n == 1 { "" } else { "s" }
                ));
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
        ui.label(strong("Export as plain CSV", 16.0));
        ui.add_space(6.0);
        widgets::danger_box(
            ui,
            "This writes every password, card number, key and note in the vault to an unencrypted \
             file. Any program or person that can read the file gets all of them.",
        );
        ui.add_space(6.0);
        ui.label(dim(
            "For safekeeping use an encrypted backup instead. Only export to move to another \
             password manager, and delete the file straight after.",
        ));
        ui.add_space(8.0);
        ui.checkbox(understood, "I understand the risk");
        ui.label(small("Type EXPORT to continue"));
        widgets::text_input(ui, typed, "");
        ui.add_space(12.0);
        let ok = *understood && typed.trim() == "EXPORT";
        ui.horizontal(|ui| {
            if widgets::danger_button_enabled(ui, "Choose file…", ok).clicked() {
                decision = Some(true);
            }
            if widgets::secondary_button(ui, "Cancel").clicked() {
                decision = Some(false);
            }
        });
    });
    match decision.or_else(|| resp.should_close().then_some(false)) {
        Some(true) => {
            let dlg = rfd::FileDialog::new()
                .set_title("Save plain CSV export")
                .add_filter("CSV", &["csv"])
                .set_file_name("vaultrust-export-UNENCRYPTED.csv");
            if let Some(path) = dlg.save_file() {
                // The OS save dialog has already confirmed replacing a file.
                let bytes = export_csv(ms.vault.data());
                match storage::atomic_write(&path, &bytes, WriteMode::Replace) {
                    Ok(()) => svc.toasts.info(format!(
                        "Exported to {} — delete it when you're done",
                        path.display()
                    )),
                    Err(e) => svc.toasts.error(format!("Export failed: {e}")),
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
            Poll::Done(Ok(v)) => {
                r.job = None;
                svc.toasts.success("Backup restored");
                *transition = Some(Transition::Open(Box::new(v)));
                return Outcome::Close;
            }
            Poll::Done(Err(e)) => {
                r.job = None;
                r.error = Some(match e {
                    VaultError::WrongPasswordOrTampered => "Wrong password for this backup.".into(),
                    other => other.to_string(),
                });
            }
            Poll::Failed => {
                r.job = None;
                r.error = Some("Restore failed unexpectedly.".into());
            }
        }
    }
    let busy = r.job.is_some();
    let mut decision = None;
    let resp = egui::Modal::new(Id::new("modal_restore")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.label(strong("Restore backup", 16.0));
        ui.add_space(4.0);
        ui.add(egui::Label::new(faint(r.backup.display().to_string())).truncate());
        ui.add_space(8.0);
        ui.add_enabled_ui(!busy, |ui| {
            ui.label(small("Master password of the backup"));
            widgets::password_input(ui, &mut r.password, &mut r.reveal, "");
            ui.add_space(6.0);
            ui.radio_value(&mut r.replace_current, false, "Restore to a new file");
            ui.radio_value(&mut r.replace_current, true, "Replace the open vault");
            if r.replace_current {
                widgets::danger_box(ui, "Anything added since the backup was made will be lost.");
                ui.checkbox(&mut r.understood, "Replace the open vault");
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
                ui.label(dim("Checking and restoring…"));
            });
        } else {
            ui.horizontal(|ui| {
                let ok = !r.password.is_empty() && (!r.replace_current || r.understood);
                if widgets::primary_button_enabled(ui, "Restore", ok).clicked() {
                    decision = Some(true);
                }
                if widgets::secondary_button(ui, "Cancel").clicked() {
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
                    .set_title("Save restored vault as")
                    .add_filter("VaultRust vault", &["vault"])
                    .set_file_name(format!("{stem}-restored.vault"))
                    .save_file()
                    .map(with_vault_extension)
            };
            let Some(dest) = dest else {
                return Outcome::Keep;
            };
            if !r.replace_current && dest.exists() {
                r.error = Some("That file already exists. Choose a new name.".into());
                return Outcome::Keep;
            }
            // Make sure nothing pending is written over the restored file.
            ms.flush(svc.toasts);
            let pw = SecretString::from(r.password.as_str().to_owned());
            r.password.zeroize();
            let backup = r.backup.clone();
            let overwrite = r.replace_current;
            r.error = None;
            r.job = Some(Job::spawn(ctx, move || {
                restore_backup(&backup, &pw, &dest, overwrite)
            }));
            Outcome::Keep
        }
        Some(false) => Outcome::Close,
        None if !busy && resp.should_close() => Outcome::Close,
        None => Outcome::Keep,
    }
}
