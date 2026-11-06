//! Settings: vault file, privacy, master password, backups, import/export.

use eframe::egui::{self, RichText};
use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

use super::create::{key_file_picker, secret_buffer, KdfPreset, KeyFileChoice};
use super::icons;
use super::jobs::{Job, Poll};
use super::main_view::MainState;
use super::modals::{KdbxImportState, Modal, ReauthAction, ReauthState, RestoreState};
use super::theme::*;
use super::welcome::pick_vault_file;
use super::widgets::{self, section};
use super::{Services, Transition};
use crate::analysis::estimate_strength;
use crate::error::VaultError;
use crate::format::FORMAT_VERSION;
use crate::import_export::{import_auto, read_import_file, ImportError};
use crate::model::VaultSettings;
use crate::storage::{self, with_vault_extension};
use crate::timeutil::{age_description, now_unix};
use crate::vault::{Credentials, RewrappedHeader, MIN_MASTER_PASSWORD_CHARS};

/// What a credentials change does with the key file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyFileMode {
    /// Keep the current setting (and file, if any).
    Keep,
    /// Use a newly chosen or created key file.
    Use,
    /// Stop requiring a key file.
    Remove,
}

pub struct SettingsState {
    name_buf: Option<String>,
    current: Zeroizing<String>,
    new: Zeroizing<String>,
    confirm: Zeroizing<String>,
    reveal: bool,
    /// `None` keeps the current Argon2 parameters.
    preset: Option<KdfPreset>,
    key_mode: KeyFileMode,
    key_file: KeyFileChoice,
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
            key_mode: KeyFileMode::Keep,
            key_file: KeyFileChoice::default(),
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
            privacy_section(ui, ms, svc);
            ui.add_space(12.0);
            password_section(ui, ms);
            ui.add_space(12.0);
            backup_section(ui, ms, svc);
            ui.add_space(12.0);
            breach_section(ui, ms, svc);
            ui.add_space(12.0);
            import_export_section(ui, ms, svc);
            ui.add_space(12.0);
            app_section(ui, ms, svc);
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
        let path = widgets::short_path(ms.vault.path());
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
                ui.label(faint("Unlocks with"));
                ui.label(small(if ms.vault.uses_key_file() {
                    "Master password + key file"
                } else {
                    "Master password"
                }));
                ui.end_row();
                ui.label(faint("File format"));
                ui.label(small(format!("Version {FORMAT_VERSION}")));
                ui.end_row();
                ui.label(faint("Vault ID"));
                ui.label(
                    RichText::new(ms.vault.vault_id_hex())
                        .family(egui::FontFamily::Monospace)
                        .size(11.5)
                        .color(text_dim()),
                );
                ui.end_row();
            });
    });
}

/// Windows Hello quick unlock for this vault.
fn hello_row(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
    if !crate::hello::is_available() {
        widgets::setting_row(
            ui,
            "Unlock with Windows Hello",
            "Set up a fingerprint, face or PIN in Windows Settings › Accounts › Sign-in options",
            100.0,
            |ui| {
                ui.label(faint("Unavailable"));
            },
        );
        return;
    }
    let on = ms.hello_enabled();
    let busy = ms.hello_job.is_some();
    let desc = if on {
        "On · the master password is still needed the first time after VaultRust starts"
    } else {
        "Fingerprint, face or PIN instead of typing the master password every time"
    };
    let (mut turn_on, mut turn_off) = (false, false);
    widgets::setting_row(ui, "Unlock with Windows Hello", desc, 160.0, |ui| {
        if busy {
            ui.add(egui::Spinner::new());
        } else if on {
            turn_off = widgets::secondary_button(ui, "Turn off").clicked();
        } else {
            turn_on = widgets::secondary_button(ui, &icons::with(icons::FINGERPRINT, "Turn on…"))
                .clicked();
        }
    });
    if turn_on {
        ms.modal = Some(Modal::Reauth(Box::new(ReauthState::new(
            ReauthAction::EnableHello,
        ))));
    }
    if turn_off {
        ms.disable_hello(svc);
    }
}

/// "Start with Windows". Testing builds never touch the real registry.
fn startup_row(ui: &mut egui::Ui, svc: &mut Services) {
    use crate::os_protect::Autostart;
    let status = if cfg!(test) {
        Autostart::Off
    } else {
        crate::os_protect::autostart_status()
    };
    let mut on = status != Autostart::Off;
    let desc = match &status {
        Autostart::OtherCopy(cmd) => format!(
            "Starts a different copy of VaultRust: {}. Turn off and on again to use this one.",
            cmd
        ),
        _ if svc.tray && svc.prefs.close_to_tray => {
            "Waits in the notification area after you sign in, locked".to_string()
        }
        _ => "Opens VaultRust minimized after you sign in, locked".to_string(),
    };
    widgets::switch_row(ui, &mut on, "Start with Windows", &desc);
    if on != (status != Autostart::Off) && !cfg!(test) {
        match crate::os_protect::set_autostart(on) {
            Ok(()) if on => svc.toasts.success("VaultRust will start when you sign in"),
            Ok(()) => svc.toasts.info("VaultRust won't start with Windows"),
            Err(e) => svc.toasts.error(format!("Couldn't change start-up: {e}")),
        }
    }
}

fn privacy_section(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
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
        widgets::switch_row(
            ui,
            &mut s.lock_on_session_lock,
            "Lock when Windows locks",
            "Win+L, sleep with sign-in on wake, switching user",
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
        widgets::divider(ui, 16.0);
        hello_row(ui, ms, svc);
        if !s.hide_from_capture && ms.vault.data().settings.hide_from_capture {
            // Turning protection off needs the master password.
            s.hide_from_capture = true;
            ms.modal = Some(Modal::Reauth(Box::new(ReauthState::new(
                ReauthAction::DisableCaptureProtection,
            ))));
        }
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
    section(ui, "Master password & key file", |ui| {
        let busy = ms.settings.job.is_some();
        let current_kdf = ms.vault.kdf_params();
        let has_key_file = ms.vault.uses_key_file();
        let st = &mut ms.settings;
        ui.add_enabled_ui(!busy, |ui| {
            ui.label(small("Current"));
            widgets::password_input(ui, &mut st.current, &mut st.reveal, "");
            ui.label(small("New"));
            widgets::password_input(
                ui,
                &mut st.new,
                &mut st.reveal,
                "At least 10 characters (leave empty to keep the current one)",
            );
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
            ui.label(small("Key file"));
            let label = |m: KeyFileMode| match (m, has_key_file) {
                (KeyFileMode::Keep, true) => "Keep the current key file",
                (KeyFileMode::Keep, false) => "No key file",
                (KeyFileMode::Use, true) => "Switch to a different key file",
                (KeyFileMode::Use, false) => "Require a key file",
                (KeyFileMode::Remove, _) => "Stop using a key file",
            };
            egui::ComboBox::from_id_salt("change_key_file")
                .width(ui.available_width())
                .icon(widgets::combo_caret)
                .selected_text(label(st.key_mode))
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut st.key_mode,
                        KeyFileMode::Keep,
                        label(KeyFileMode::Keep),
                    );
                    ui.selectable_value(
                        &mut st.key_mode,
                        KeyFileMode::Use,
                        label(KeyFileMode::Use),
                    );
                    if has_key_file {
                        ui.selectable_value(
                            &mut st.key_mode,
                            KeyFileMode::Remove,
                            label(KeyFileMode::Remove),
                        );
                    }
                });
            if st.key_mode == KeyFileMode::Use {
                key_file_picker(ui, &mut st.key_file, true);
            }
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
        } else if widgets::primary_button(ui, "Apply").clicked() {
            st.pw_error = None;
            let keep_password = st.new.is_empty() && st.confirm.is_empty();
            let new_key = match st.key_mode {
                KeyFileMode::Keep => Ok(ms.vault.session_key_file()),
                KeyFileMode::Remove => Ok(None),
                KeyFileMode::Use => match st.key_file.load() {
                    Ok(Some(k)) => Ok(Some(k)),
                    Ok(None) => Err("Choose or create the new key file.".to_string()),
                    Err(e) => Err(e),
                },
            };
            let unchanged =
                keep_password && st.key_mode == KeyFileMode::Keep && st.preset.is_none();
            if st.current.is_empty() {
                st.pw_error = Some("Enter your current master password.".into());
            } else if unchanged {
                st.pw_error = Some(
                    "Nothing to change: enter a new password or pick a key file option.".into(),
                );
            } else if !keep_password && st.new.chars().count() < MIN_MASTER_PASSWORD_CHARS {
                st.pw_error = Some("The new password must be at least 10 characters.".into());
            } else if !keep_password && *st.new != *st.confirm {
                st.pw_error = Some("The new passwords don't match.".into());
            } else {
                match new_key {
                    Err(e) => st.pw_error = Some(e),
                    Ok(new_key) => {
                        let kdf = st.preset.map(KdfPreset::params).unwrap_or(current_kdf);
                        let current = SecretString::from(st.current.as_str().to_owned());
                        let new_pw = if keep_password {
                            current.clone()
                        } else {
                            SecretString::from(st.new.as_str().to_owned())
                        };
                        let task = ms.vault.credentials_change_task(
                            Credentials::with_key_file(current, ms.vault.session_key_file()),
                            Credentials::with_key_file(new_pw, new_key),
                            kdf,
                        );
                        st.clear_passwords();
                        st.job = Some(Job::spawn(ui.ctx(), move || task.run()));
                    }
                }
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
                    ms.vault
                        .data_mut()
                        .log(crate::model::AuditKind::CredentialsChanged, "");
                    ms.commit(svc.toasts);
                    ms.settings.preset = None;
                    ms.settings.key_mode = KeyFileMode::Keep;
                    ms.settings.key_file.clear();
                    svc.toasts.success("Unlock settings changed");
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
        widgets::divider(ui, 16.0);
        let mut s = ms.vault.data().settings.clone();
        let auto_dir = ms.vault.auto_backup_dir();
        let existing = storage::list_auto_backups(ms.vault.path());
        let desc = match (s.auto_backup_count, existing.first()) {
            (0, _) => "Off".to_string(),
            (_, None) => "None yet — the first is taken on the next change".to_string(),
            (_, Some(newest)) => format!(
                "{} kept · newest {}",
                existing.len(),
                newest
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
        };
        let mut restore_auto = false;
        widgets::setting_row(ui, "Automatic backups", &desc, 260.0, |ui| {
            if !existing.is_empty() {
                restore_auto = widgets::secondary_button(ui, "Restore…").clicked();
            }
            ui.add_sized(
                [96.0, 28.0],
                egui::DragValue::new(&mut s.auto_backup_count)
                    .range(0..=VaultSettings::MAX_AUTO_BACKUPS)
                    .custom_formatter(|n, _| {
                        if n == 0.0 {
                            "off".into()
                        } else {
                            format!("keep {n}")
                        }
                    }),
            );
        });
        if restore_auto {
            let pick = rfd::FileDialog::new()
                .set_title("Restore an automatic backup")
                .add_filter("VaultRust vault", &["vault"])
                .set_directory(&auto_dir)
                .pick_file();
            if let Some(p) = pick {
                ms.modal = Some(Modal::Restore(Box::new(RestoreState::new(p))));
            }
        }
        s.sanitize();
        if s != ms.vault.data().settings {
            ms.vault.data_mut().settings = s;
            ms.schedule_settings_save();
        }
        ui.add_space(4.0);
        ui.label(faint(format!(
            "Automatic backups are encrypted copies taken at most hourly before changes, in {}. \
             They protect against mistakes, not against losing the drive: keep a manual backup elsewhere.",
            auto_dir.display()
        )));
    });
}

fn breach_section(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
    section(ui, "Breached-password check", |ui| {
        let list = ms.vault.data().settings.breach_list.clone();
        let status = if list.is_empty() {
            "Not set up".to_string()
        } else if ms.breach.is_running() {
            "Checking…".to_string()
        } else {
            match &ms.breach.report {
                Some(r) if r.error.is_some() => r.error.clone().unwrap_or_default(),
                Some(r) => format!(
                    "{} of {} passwords found in breaches",
                    r.hits.len(),
                    r.checked
                ),
                None => "Waiting to check".to_string(),
            }
        };
        let (mut choose, mut clear) = (false, false);
        widgets::setting_row(ui, "Pwned Passwords list", &status, 220.0, |ui| {
            if !list.is_empty() {
                clear = widgets::icon_button(ui, icons::X, "Stop checking").clicked();
            }
            choose = widgets::secondary_button(
                ui,
                if list.is_empty() {
                    "Choose file…"
                } else {
                    "Change…"
                },
            )
            .clicked();
        });
        if !list.is_empty() {
            ui.add(egui::Label::new(faint(&list)).truncate());
        }
        if choose {
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Choose a Pwned Passwords SHA-1 list")
                .add_filter("Text", &["txt"])
                .add_filter("All files", &["*"])
                .pick_file()
            {
                match crate::breach::BreachList::open(&p) {
                    Ok(_) => {
                        ms.vault.data_mut().settings.breach_list = p.display().to_string();
                        ms.commit(svc.toasts);
                    }
                    Err(e) => svc.toasts.error(format!("That file can't be used: {e}")),
                }
            }
        }
        if clear {
            ms.vault.data_mut().settings.breach_list.clear();
            ms.commit(svc.toasts);
        }
        ui.add_space(4.0);
        ui.label(faint(
            "Checks your passwords against a copy of the Have I Been Pwned list on this computer — \
             VaultRust never goes online. Download the SHA-1 list (ordered by hash) with the official \
             PwnedPasswordsDownloader, then choose the file here.",
        ));
    });
}

/// Pick a CSV/JSON export from another app and show the import preview.
pub fn start_import(ms: &mut MainState, svc: &mut Services) {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Import")
        .add_filter("CSV, JSON or KeePass", &["csv", "json", "kdbx"])
        .add_filter("All files", &["*"])
        .pick_file()
    else {
        return;
    };
    let bytes = match read_import_file(&path) {
        Ok(b) => b,
        Err(e) => return svc.toasts.error(format!("Import failed: {e}")),
    };
    match import_auto(&path, &bytes) {
        Ok(r) if r.entries.is_empty() => svc.toasts.error("No items found in that file."),
        Ok(r) => {
            ms.modal = Some(Modal::ImportPreview {
                source: path,
                result: r,
                update_changed: true,
            })
        }
        Err(ImportError::KdbxNeedsPassword) => {
            ms.modal = Some(Modal::KdbxImport(Box::new(KdbxImportState::new(
                path, bytes,
            ))));
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
            "KeePass .kdbx, or CSV / JSON from Chrome, Edge, Firefox, Bitwarden, 1Password, LastPass",
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
                                .color(danger()),
                        )
                        .fill(surface_2())
                        .stroke(egui::Stroke::new(1.0_f32, border()))
                        .corner_radius(6.0)
                        .min_size(egui::vec2(0.0, 32.0)),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked();
            },
        );
        if export {
            ms.modal = Some(Modal::Reauth(Box::new(ReauthState::new(
                ReauthAction::Export,
            ))));
        }
    });
}

fn app_section(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
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
        widgets::divider(ui, 16.0);
        let mut theme = svc.prefs.theme;
        widgets::setting_row(
            ui,
            "Appearance",
            "System follows the Windows light / dark setting",
            260.0,
            |ui| {
                for t in crate::prefs::ThemePref::ALL.into_iter().rev() {
                    if ui.selectable_label(theme == t, t.label()).clicked() {
                        theme = t;
                    }
                }
            },
        );
        if theme != svc.prefs.theme {
            svc.prefs.theme = theme;
            svc.prefs.save();
        }
        if svc.tray {
            widgets::divider(ui, 16.0);
            let mut keep = svc.prefs.close_to_tray;
            widgets::switch_row(
                ui,
                &mut keep,
                "Keep running in the notification area",
                "Closing the window locks the vault and keeps quick open and auto-type ready",
            );
            if keep != svc.prefs.close_to_tray {
                svc.prefs.close_to_tray = keep;
                svc.prefs.save();
            }
        }
        widgets::divider(ui, 16.0);
        let mut tour = false;
        widgets::setting_row(
            ui,
            "Welcome tour",
            "A quick look at saving, copying, auto-type and two-step codes",
            160.0,
            |ui| tour = widgets::secondary_button(ui, "Show the tour again").clicked(),
        );
        if tour {
            ms.tour = Some(super::tutorial::Tour::default());
        }
        widgets::divider(ui, 16.0);
        startup_row(ui, svc);
        widgets::divider(ui, 16.0);
        super::updates::settings_row(ui, svc.updates, svc.prefs);
        widgets::divider(ui, 16.0);
        let status = |ui: &mut egui::Ui, on: bool| {
            ui.label(if on {
                RichText::new("On").color(accent())
            } else {
                RichText::new("Unavailable").color(text_faint())
            });
        };
        let hotkey = crate::os_protect::QUICK_OPEN_HOTKEY;
        let desc = if svc.hotkeys.quick_open {
            format!("{hotkey} brings VaultRust forward with quick open; Ctrl+K inside the app")
        } else {
            format!("{hotkey} is used by another app; Ctrl+K still works inside VaultRust")
        };
        widgets::setting_row(ui, "Quick open", &desc, 80.0, |ui| {
            status(ui, svc.hotkeys.quick_open)
        });
        widgets::divider(ui, 16.0);
        let hotkey = crate::os_protect::AUTO_TYPE_HOTKEY;
        let desc = if svc.hotkeys.auto_type {
            format!("Click into a login form in any app and press {hotkey}; you pick what is typed")
        } else {
            format!("{hotkey} is used by another app, so auto-type is unavailable")
        };
        widgets::setting_row(ui, "Auto-type", &desc, 80.0, |ui| {
            status(ui, svc.hotkeys.auto_type)
        });
        ui.add_space(4.0);
        ui.label(faint(format!(
            "VaultRust {} · your vault never leaves this computer · no telemetry",
            env!("CARGO_PKG_VERSION")
        )));
    });
}
