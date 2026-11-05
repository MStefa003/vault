//! Settings: vault file, privacy, master password, backups, import/export.

use eframe::egui::{self, RichText};
use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

use super::create::{secret_buffer, KdfPreset};
use super::icons;
use super::jobs::{Job, Poll};
use super::main_view::MainState;
use super::modals::{Modal, RestoreState};
use super::theme::*;
use super::welcome::pick_vault_file;
use super::widgets::{self, section};
use super::{Services, Transition};
use crate::analysis::estimate_strength;
use crate::error::VaultError;
use crate::format::FORMAT_VERSION;
use crate::import_export::{import_auto, read_import_file};
use crate::model::VaultSettings;
use crate::storage::with_vault_extension;
use crate::timeutil::{age_description, now_unix};
use crate::vault::{RewrappedHeader, MIN_MASTER_PASSWORD_CHARS};

pub struct SettingsState {
    name_buf: Option<String>,
    current: Zeroizing<String>,
    new: Zeroizing<String>,
    confirm: Zeroizing<String>,
    reveal: bool,
    /// `None` keeps the current Argon2 parameters.
    preset: Option<KdfPreset>,
    pw_error: Option<String>,
    job: Option<Job<Result<RewrappedHeader, VaultError>>>,
}

impl Default for SettingsState {
    fn default() -> Self {
        SettingsState {
            name_buf: None,
            current: secret_buffer(),
            new: secret_buffer(),
            confirm: secret_buffer(),
            reveal: false,
            preset: None,
            pw_error: None,
            job: None,
        }
    }
}

impl SettingsState {
    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    fn clear_passwords(&mut self) {
        self.current.zeroize();
        self.new.zeroize();
        self.confirm.zeroize();
    }
}

/// Report a vault operation error, routing external-change conflicts to the
/// conflict dialog.
fn report(ms: &mut MainState, svc: &mut Services, what: &str, e: VaultError) {
    match e {
        VaultError::ModifiedExternally => ms.modal = Some(Modal::ExternalChange),
        e => svc.toasts.error(format!("{what}: {e}")),
    }
}

pub fn show(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) -> Option<Transition> {
    poll_password_job(ms, svc);
    egui::ScrollArea::vertical()
        .id_salt("settings")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            widgets::page_header(ui, "Settings", "Stored inside the encrypted vault.");
            vault_section(ui, ms, svc);
            ui.add_space(12.0);
            privacy_section(ui, ms);
            ui.add_space(12.0);
            password_section(ui, ms);
            ui.add_space(12.0);
            backup_section(ui, ms, svc);
            ui.add_space(12.0);
            import_export_section(ui, ms, svc);
            ui.add_space(12.0);
            app_section(ui, svc);
        });
    None
}

fn vault_section(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
    section(ui, "Vault", |ui| {
        let name = ms
            .settings
            .name_buf
            .get_or_insert_with(|| ms.vault.data().name.clone());
        let changed = *name != ms.vault.data().name;
        let mut rename = false;
        widgets::setting_row(ui, "Name", "Shown in the sidebar", 380.0, |ui| {
            if changed {
                rename = widgets::primary_button(ui, "Rename").clicked();
            }
            ui.add(
                egui::TextEdit::singleline(name)
                    .desired_width(ui.available_width().min(280.0))
                    .margin(egui::vec2(10.0, 6.0)),
            );
        });
        if rename {
            let n = name.clone();
            match ms.vault.rename(&n) {
                Ok(()) => {
                    svc.toasts.success("Renamed");
                    ms.settings.name_buf = None;
                }
                Err(e) => report(ms, svc, "Couldn't rename", e),
            }
        }
        widgets::divider(ui, 16.0);
        let mut move_file = false;
        let path = ms.vault.path().display().to_string();
        widgets::setting_row(ui, "File", &path, 120.0, |ui| {
            move_file = widgets::secondary_button(ui, "Move…").clicked();
        });
        if move_file {
            let mut dlg = rfd::FileDialog::new()
                .set_title("Move vault file")
                .add_filter("VaultRust vault", &["vault"]);
            if let Some(n) = ms.vault.path().file_name() {
                dlg = dlg.set_file_name(n.to_string_lossy());
            }
            if let Some(dir) = ms.vault.path().parent() {
                dlg = dlg.set_directory(dir);
            }
            if let Some(dest) = dlg.save_file() {
                let dest = with_vault_extension(dest);
                match ms.vault.move_to(&dest) {
                    Ok(()) => {
                        svc.recent.push(&dest);
                        svc.toasts.success("Vault file moved");
                    }
                    Err(VaultError::AlreadyExists) => svc
                        .toasts
                        .error("A file with that name already exists there. Moving never overwrites files."),
                    Err(e) => report(ms, svc, "Couldn't move the vault", e),
                }
            }
        }
        widgets::divider(ui, 16.0);
        ui.add_space(2.0);
        egui::Grid::new("vault_info")
            .num_columns(2)
            .spacing([24.0, 4.0])
            .show(ui, |ui| {
                ui.label(faint("Encryption"));
                ui.label(small("XChaCha20-Poly1305, 256-bit key"));
                ui.end_row();
                ui.label(faint("Key derivation"));
                ui.label(small(ms.vault.kdf_params().describe()));
                ui.end_row();
                ui.label(faint("File format"));
                ui.label(small(format!("Version {FORMAT_VERSION}")));
                ui.end_row();
                ui.label(faint("Vault ID"));
                ui.label(
                    RichText::new(ms.vault.vault_id_hex())
                        .family(egui::FontFamily::Monospace)
                        .size(11.5)
                        .color(TEXT_DIM),
                );
                ui.end_row();
            });
    });
}

fn privacy_section(ui: &mut egui::Ui, ms: &mut MainState) {
    section(ui, "Locking & privacy", |ui| {
        let mut s = ms.vault.data().settings.clone();
        timed_row(
            ui,
            "Lock after inactivity",
            "Ctrl+L locks at any time",
            &mut s.auto_lock_minutes,
            VaultSettings::MIN_AUTO_LOCK_MINUTES..=VaultSettings::MAX_AUTO_LOCK_MINUTES,
            " min",
        );
        widgets::divider(ui, 16.0);
        timed_row(
            ui,
            "Clear clipboard after",
            "Only if it still holds what VaultRust copied",
            &mut s.clipboard_clear_secs,
            VaultSettings::MIN_CLIPBOARD_SECS..=VaultSettings::MAX_CLIPBOARD_SECS,
            " s",
        );
        widgets::divider(ui, 16.0);
        timed_row(
            ui,
            "Hide revealed secrets after",
            "Masks passwords you clicked to show",
            &mut s.reveal_timeout_secs,
            VaultSettings::MIN_REVEAL_SECS..=VaultSettings::MAX_REVEAL_SECS,
            " s",
        );
        widgets::divider(ui, 16.0);
        widgets::switch_row(ui, &mut s.lock_on_minimize, "Lock when minimized", "");
        widgets::divider(ui, 16.0);
        widgets::switch_row(
            ui,
            &mut s.hide_from_capture,
            "Hide from screenshots and screen sharing",
            "Uses Windows display affinity; not a defence against malware",
        );
        s.sanitize();
        if s != ms.vault.data().settings {
            ms.vault.data_mut().settings = s;
            ms.schedule_settings_save();
        }
    });
}

/// Setting row with a logarithmic slider and an editable value.
fn timed_row<T: egui::emath::Numeric>(
    ui: &mut egui::Ui,
    title: &str,
    desc: &str,
    value: &mut T,
    range: std::ops::RangeInclusive<T>,
    suffix: &str,
) {
    widgets::setting_row(ui, title, desc, 300.0, |ui| {
        ui.add_sized(
            [72.0, 28.0],
            egui::DragValue::new(value)
                .range(range.clone())
                .suffix(suffix),
        );
        ui.add_space(4.0);
        ui.spacing_mut().slider_width = 200.0;
        widgets::slider(ui, egui::Slider::new(value, range).logarithmic(true));
    });
}

fn password_section(ui: &mut egui::Ui, ms: &mut MainState) {
    section(ui, "Master password", |ui| {
        let busy = ms.settings.job.is_some();
        let current_kdf = ms.vault.kdf_params();
        let st = &mut ms.settings;
        ui.add_enabled_ui(!busy, |ui| {
            ui.label(small("Current"));
            widgets::password_input(ui, &mut st.current, &mut st.reveal, "");
            ui.label(small("New"));
            widgets::password_input(ui, &mut st.new, &mut st.reveal, "At least 10 characters");
            if !st.new.is_empty() {
                widgets::strength_meter(ui, &estimate_strength(&st.new));
            }
            ui.label(small("Confirm new"));
            widgets::password_input(ui, &mut st.confirm, &mut st.reveal, "");
            ui.label(small("Key derivation"));
            let selected = st
                .preset
                .map(|p| p.label().to_string())
                .unwrap_or_else(|| format!("Keep current ({})", current_kdf.describe()));
            egui::ComboBox::from_id_salt("change_kdf")
                .width(ui.available_width())
                .icon(widgets::combo_caret)
                .selected_text(selected)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut st.preset, None, "Keep current");
                    for p in KdfPreset::ALL {
                        ui.selectable_value(&mut st.preset, Some(p), p.label());
                    }
                });
        });
        if let Some(e) = &st.pw_error {
            widgets::error_text(ui, e);
        }
        ui.add_space(4.0);
        if busy {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(dim("Changing password…"));
            });
        } else if widgets::primary_button(ui, "Change password").clicked() {
            st.pw_error = None;
            if st.current.is_empty() {
                st.pw_error = Some("Enter your current master password.".into());
            } else if st.new.chars().count() < MIN_MASTER_PASSWORD_CHARS {
                st.pw_error = Some("The new password must be at least 10 characters.".into());
            } else if *st.new != *st.confirm {
                st.pw_error = Some("The new passwords don't match.".into());
            } else {
                let kdf = st.preset.map(KdfPreset::params).unwrap_or(current_kdf);
                let task = ms.vault.password_change_task(
                    SecretString::from(st.current.as_str().to_owned()),
                    SecretString::from(st.new.as_str().to_owned()),
                    kdf,
                );
                st.clear_passwords();
                st.job = Some(Job::spawn(ui.ctx(), move || task.run()));
            }
        }
        ui.label(faint(
            "Existing backups keep the password they were made with.",
        ));
    });
}

fn poll_password_job(ms: &mut MainState, svc: &mut Services) {
    let Some(job) = &ms.settings.job else { return };
    match job.poll() {
        Poll::Pending => {}
        Poll::Done(Ok(header)) => {
            ms.settings.job = None;
            match ms.vault.apply_password_change(header) {
                Ok(()) => {
                    ms.settings.preset = None;
                    svc.toasts.success("Master password changed");
                }
                Err(VaultError::ModifiedExternally) => ms.modal = Some(Modal::ExternalChange),
                Err(e) => ms.settings.pw_error = Some(e.to_string()),
            }
        }
        Poll::Done(Err(e)) => {
            ms.settings.job = None;
            ms.settings.pw_error = Some(match e {
                VaultError::WrongPasswordOrTampered => "The current password is wrong.".into(),
                other => other.to_string(),
            });
        }
        Poll::Failed => {
            ms.settings.job = None;
            ms.settings.pw_error = Some("Password change failed unexpectedly.".into());
        }
    }
}

fn backup_section(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
    section(ui, "Backups", |ui| {
        let last = ms.vault.data().last_backup;
        let status = if last == 0 {
            "Never backed up".to_string()
        } else {
            format!("Last verified backup {}", age_description(last, now_unix()))
        };
        let mut backup = false;
        widgets::setting_row(ui, "Back up", &status, 160.0, |ui| {
            backup = widgets::secondary_button(ui, &icons::with(icons::FLOPPY_DISK, "Back up…"))
                .clicked();
        });
        if backup {
            ms.start_backup(svc);
        }
        widgets::divider(ui, 16.0);
        let mut restore = false;
        widgets::setting_row(
            ui,
            "Restore",
            "Replaces this vault with a backup after checking its password",
            160.0,
            |ui| {
                restore = widgets::secondary_button(
                    ui,
                    &icons::with(icons::ARROW_COUNTER_CLOCKWISE, "Restore…"),
                )
                .clicked();
            },
        );
        if restore {
            if let Some(p) = pick_vault_file() {
                ms.modal = Some(Modal::Restore(Box::new(RestoreState::new(p))));
            }
        }
        ui.add_space(4.0);
        ui.label(faint(
            "Backups are encrypted copies of the vault file. Nothing is uploaded; keep one on another drive.",
        ));
    });
}

/// Pick a CSV/JSON export from another app and show the import preview.
pub fn start_import(ms: &mut MainState, svc: &mut Services) {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Import")
        .add_filter("CSV or JSON", &["csv", "json"])
        .add_filter("All files", &["*"])
        .pick_file()
    else {
        return;
    };
    match read_import_file(&path).and_then(|bytes| import_auto(&path, &bytes)) {
        Ok(r) if r.entries.is_empty() => svc.toasts.error("No items found in that file."),
        Ok(r) => {
            ms.modal = Some(Modal::ImportPreview {
                source: path,
                result: r,
            })
        }
        Err(e) => svc.toasts.error(format!("Import failed: {e}")),
    }
}

fn import_export_section(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
    section(ui, "Import & export", |ui| {
        let mut import = false;
        widgets::setting_row(
            ui,
            "Import",
            "CSV or JSON from Chrome, Edge, Firefox, Bitwarden, 1Password, LastPass, KeePass",
            160.0,
            |ui| {
                import =
                    widgets::secondary_button(ui, &icons::with(icons::DOWNLOAD_SIMPLE, "Import…"))
                        .clicked();
            },
        );
        if import {
            start_import(ms, svc);
        }
        widgets::divider(ui, 16.0);
        let mut export = false;
        widgets::setting_row(
            ui,
            "Export",
            "Writes every secret to an unencrypted CSV file",
            160.0,
            |ui| {
                export = ui
                    .add(
                        egui::Button::new(
                            RichText::new(icons::with(icons::UPLOAD_SIMPLE, "Export…"))
                                .color(DANGER),
                        )
                        .fill(SURFACE_2)
                        .stroke(egui::Stroke::new(1.0, BORDER))
                        .corner_radius(6.0)
                        .min_size(egui::vec2(0.0, 32.0)),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked();
            },
        );
        if export {
            ms.modal = Some(Modal::ExportWarning {
                understood: false,
                typed: String::new(),
            });
        }
    });
}

fn app_section(ui: &mut egui::Ui, svc: &mut Services) {
    section(ui, "App", |ui| {
        let count = svc.recent.paths.len();
        let mut clear = false;
        let desc = match count {
            0 => "The start screen lists no vaults".to_string(),
            1 => "1 vault listed on the start screen".to_string(),
            n => format!("{n} vaults listed on the start screen"),
        };
        widgets::setting_row(ui, "Recent vaults", &desc, 160.0, |ui| {
            clear = ui
                .add_enabled_ui(count > 0, |ui| widgets::secondary_button(ui, "Clear"))
                .inner
                .clicked();
        });
        if clear {
            svc.recent.clear();
            svc.toasts.info("Recent list cleared");
        }
        ui.add_space(4.0);
        ui.label(faint(format!(
            "VaultRust {} · works fully offline · no telemetry",
            env!("CARGO_PKG_VERSION")
        )));
    });
}
