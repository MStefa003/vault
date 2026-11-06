//! Unlock screen.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui::{self, Frame, Key};
use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

use super::create::{key_file_picker, secret_buffer, KeyFileChoice};
use super::icons;
use super::jobs::{Job, Poll};
use super::theme::*;
use super::welcome::pick_vault_file;
use super::widgets::{self, centered_column};
use super::{Services, Transition};
use crate::error::VaultError;
use crate::format::VaultFile;
use crate::i18n::tr;
use crate::storage;
use crate::trf;
use crate::vault::{Credentials, UnlockedVault};

/// Failed attempts allowed before a growing delay kicks in.
const FREE_ATTEMPTS: u32 = 3;
const MAX_DELAY_SECS: u64 = 30;

pub struct UnlockState {
    path: PathBuf,
    password: Zeroizing<String>,
    reveal: bool,
    error: Option<String>,
    /// Public header information, or why the file cannot be used.
    info: Result<String, String>,
    needs_key_file: bool,
    key_file: KeyFileChoice,
    failures: u32,
    retry_at: Option<Instant>,
    focus_pending: bool,
    job: Option<Job<Result<UnlockedVault, VaultError>>>,
    /// The vault id from the header (for Windows Hello).
    vault_id: Option<[u8; crate::format::VAULT_ID_LEN]>,
    /// Windows Hello can unlock this vault right now.
    hello: bool,
    hello_job: Option<Job<Result<UnlockedVault, String>>>,
}

/// Delay before the next attempt after `failures` wrong passwords. This
/// slows down guessing at an unattended, locked VaultRust window; it does not
/// (and cannot) slow down an attacker who has a copy of the file — Argon2id
/// does that.
pub fn retry_delay(failures: u32) -> Option<Duration> {
    if failures < FREE_ATTEMPTS {
        return None;
    }
    let secs = 1u64 << (failures - FREE_ATTEMPTS).min(5);
    Some(Duration::from_secs(secs.min(MAX_DELAY_SECS)))
}

impl UnlockState {
    pub fn new(path: PathBuf) -> Self {
        let mut needs_key_file = false;
        let mut vault_id = None;
        let info = match storage::read_vault_bytes(&path) {
            Ok(bytes) => match VaultFile::from_bytes(&bytes) {
                Ok(f) => {
                    needs_key_file = f.header.key_file;
                    vault_id = Some(f.header.vault_id);
                    let mut d = f.header.kdf.describe();
                    if needs_key_file {
                        d.push_str(tr(" · key file"));
                    }
                    Ok(d)
                }
                Err(e) => Err(e.to_string()),
            },
            Err(e) => Err(e.to_string()),
        };
        UnlockState {
            path,
            password: secret_buffer(),
            reveal: false,
            error: None,
            info,
            needs_key_file,
            key_file: KeyFileChoice::default(),
            failures: 0,
            retry_at: None,
            focus_pending: true,
            job: None,
            vault_id,
            hello: false,
            hello_job: None,
        }
    }

    /// Offer Windows Hello if `allowed` (the master password was already
    /// used for this vault since the app started) and Hello is turned on for
    /// this vault and available.
    pub fn allow_hello(mut self, allowed: bool) -> Self {
        self.hello = allowed
            && self
                .vault_id
                .is_some_and(|id| crate::hello::is_enabled(&id))
            && crate::hello::is_available();
        self
    }

    fn start_hello(&mut self, ctx: &egui::Context) {
        let Some(id) = self.vault_id else { return };
        let path = self.path.clone();
        self.error = None;
        self.hello_job = Some(Job::spawn(ctx, move || {
            let secret = crate::hello::unlock(&id).map_err(|e| e.to_string())?;
            UnlockedVault::open_with_hello(&path, secret).map_err(|e| e.to_string())
        }));
    }

    #[cfg(test)]
    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    /// Put the cursor back in the password field (after the global hotkey
    /// brought the window forward).
    pub fn focus(&mut self) {
        self.focus_pending = true;
    }

    fn start(&mut self, ctx: &egui::Context) {
        if self.password.is_empty() {
            self.focus_pending = true;
            return;
        }
        let key_file = match self.key_file.load() {
            Ok(k) => k,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        if self.needs_key_file && key_file.is_none() {
            self.error = Some(tr("Choose this vault's key file.").into());
            return;
        }
        let creds = Credentials::with_key_file(
            SecretString::from(self.password.as_str().to_owned()),
            key_file,
        );
        self.password.zeroize();
        let path = self.path.clone();
        self.error = None;
        self.job = Some(Job::spawn(ctx, move || {
            UnlockedVault::open_with(&path, &creds)
        }));
    }
}

pub fn show(ctx: &egui::Context, s: &mut UnlockState, _svc: &mut Services) -> Option<Transition> {
    let mut t = None;
    if let Some(job) = &s.hello_job {
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(Ok(mut v)) => {
                s.hello_job = None;
                v.data_mut()
                    .log(crate::model::AuditKind::UnlockedWithHello, "");
                return Some(Transition::Open(Box::new(v)));
            }
            Poll::Done(Err(e)) => {
                s.hello_job = None;
                s.focus_pending = true;
                s.error = Some(e);
            }
            Poll::Failed => {
                s.hello_job = None;
                s.error = Some(tr("Windows Hello failed unexpectedly.").into());
            }
        }
    }
    if let Some(job) = &s.job {
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(Ok(mut v)) => {
                s.job = None;
                // Saved with the next change or when the vault locks.
                v.data_mut().log(crate::model::AuditKind::Unlocked, "");
                return Some(Transition::Open(Box::new(v)));
            }
            Poll::Done(Err(e)) => {
                s.job = None;
                s.focus_pending = true;
                s.error = Some(match e {
                    VaultError::WrongPasswordOrTampered => {
                        s.failures += 1;
                        s.retry_at = retry_delay(s.failures).map(|d| Instant::now() + d);
                        if s.needs_key_file {
                            tr("Wrong master password or key file.").into()
                        } else {
                            tr("Wrong master password.").into()
                        }
                    }
                    other => other.to_string(),
                });
            }
            Poll::Failed => {
                s.job = None;
                s.error = Some(tr("Unlocking failed unexpectedly.").into());
            }
        }
    }
    let busy = s.job.is_some() || s.hello_job.is_some();
    let wait = s
        .retry_at
        .map(|at| at.saturating_duration_since(Instant::now()))
        .filter(|d| !d.is_zero());
    if wait.is_some() {
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    let name = s
        .path
        .file_stem()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| tr("Vault").into());

    egui::CentralPanel::default()
        .frame(Frame::new().fill(bg()).inner_margin(24.0))
        .show(ctx, |ui| {
            widgets::offline_footer(ui);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_space(((ui.available_height() - 330.0) / 2.0 - 24.0).max(24.0));
                    centered_column(ui, 360.0, |ui| {
                        ui.vertical_centered(|ui| {
                            widgets::logo(ui, 52.0);
                            ui.add_space(12.0);
                            ui.add(egui::Label::new(strong(&name, 22.0)).truncate());
                            let details = match &s.info {
                                Ok(kdf) => format!(
                                    "{}
{kdf}",
                                    s.path.display()
                                ),
                                Err(_) => s.path.display().to_string(),
                            };
                            ui.add(
                                egui::Label::new(faint(widgets::short_path(&s.path))).truncate(),
                            )
                            .on_hover_text(details);
                        });
                        ui.add_space(22.0);

                        let info = s.info.clone();

                        match &info {
                            Err(e) => {
                                widgets::danger_box(ui, &trf!("This file can't be opened: {e}", e))
                            }
                            Ok(_) => {
                                let resp = ui
                                    .add_enabled_ui(!busy, |ui| {
                                        widgets::password_input(
                                            ui,
                                            &mut s.password,
                                            &mut s.reveal,
                                            tr("Master password"),
                                        )
                                    })
                                    .inner;
                                if s.focus_pending && !busy {
                                    resp.request_focus();
                                    s.focus_pending = false;
                                }
                                if s.needs_key_file {
                                    ui.add_enabled_ui(!busy, |ui| {
                                        key_file_picker(ui, &mut s.key_file, false);
                                    });
                                }
                                let enter =
                                    resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                                if let Some(e) = &s.error {
                                    widgets::error_text(ui, e);
                                    if s.failures >= FREE_ATTEMPTS {
                                        ui.label(small(tr(
                                            "Check Caps Lock and the keyboard layout.",
                                        )));
                                    }
                                }
                                ui.add_space(4.0);
                                if busy {
                                    ui.horizontal(|ui| {
                                        ui.add(egui::Spinner::new());
                                        ui.label(dim(if s.hello_job.is_some() {
                                            tr("Waiting for Windows Hello…")
                                        } else {
                                            tr("Unlocking…")
                                        }));
                                    });
                                } else if let Some(w) = wait {
                                    widgets::primary_button_wide(
                                        ui,
                                        &trf!("Try again in {} s", w.as_secs() + 1),
                                        false,
                                    );
                                } else if widgets::primary_button_wide(
                                    ui,
                                    &icons::with(icons::LOCK_OPEN, tr("Unlock")),
                                    true,
                                )
                                .clicked()
                                    || (enter && !s.password.is_empty())
                                {
                                    s.start(ctx);
                                }
                                if s.hello && !busy {
                                    ui.add_space(2.0);
                                    if widgets::secondary_button_wide(
                                        ui,
                                        &icons::with(
                                            icons::FINGERPRINT,
                                            tr("Unlock with Windows Hello"),
                                        ),
                                    )
                                    .clicked()
                                    {
                                        s.start_hello(ctx);
                                    }
                                }
                            }
                        }
                        ui.add_space(22.0);
                        ui.add_enabled_ui(!busy, |ui| {
                            match widgets::centered_links(
                                ui,
                                &[
                                    tr("Open another vault…"),
                                    tr("Create a vault"),
                                    tr("Start screen"),
                                ],
                            ) {
                                Some(0) => {
                                    if let Some(p) = pick_vault_file() {
                                        t = Some(Transition::Unlock(p));
                                    }
                                }
                                Some(1) => t = Some(Transition::Create),
                                Some(_) => t = Some(Transition::Welcome),
                                None => {}
                            }
                        });
                    });
                });
        });
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_grows_and_is_capped() {
        assert_eq!(retry_delay(0), None);
        assert_eq!(retry_delay(2), None);
        assert_eq!(retry_delay(3), Some(Duration::from_secs(1)));
        assert_eq!(retry_delay(4), Some(Duration::from_secs(2)));
        assert_eq!(retry_delay(6), Some(Duration::from_secs(8)));
        assert_eq!(retry_delay(8), Some(Duration::from_secs(30)));
        assert_eq!(retry_delay(100), Some(Duration::from_secs(30)));
    }
}
