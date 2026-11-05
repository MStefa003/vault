//! Unlock screen.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui::{self, Frame, Key};
use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

use super::create::secret_buffer;
use super::icons;
use super::jobs::{Job, Poll};
use super::theme::*;
use super::welcome::pick_vault_file;
use super::widgets::{self, centered_column};
use super::{Services, Transition};
use crate::error::VaultError;
use crate::format::VaultFile;
use crate::storage;
use crate::vault::UnlockedVault;

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
    failures: u32,
    retry_at: Option<Instant>,
    focus_pending: bool,
    job: Option<Job<Result<UnlockedVault, VaultError>>>,
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
        let info = match storage::read_vault_bytes(&path) {
            Ok(bytes) => match VaultFile::from_bytes(&bytes) {
                Ok(f) => Ok(f.header.kdf.describe()),
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
            failures: 0,
            retry_at: None,
            focus_pending: true,
            job: None,
        }
    }

    #[cfg(test)]
    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    fn start(&mut self, ctx: &egui::Context) {
        if self.password.is_empty() {
            self.focus_pending = true;
            return;
        }
        let pw = SecretString::from(self.password.as_str().to_owned());
        self.password.zeroize();
        let path = self.path.clone();
        self.error = None;
        self.job = Some(Job::spawn(ctx, move || UnlockedVault::open(&path, &pw)));
    }
}

pub fn show(ctx: &egui::Context, s: &mut UnlockState, _svc: &mut Services) -> Option<Transition> {
    let mut t = None;
    if let Some(job) = &s.job {
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(Ok(v)) => {
                s.job = None;
                return Some(Transition::Open(Box::new(v)));
            }
            Poll::Done(Err(e)) => {
                s.job = None;
                s.focus_pending = true;
                s.error = Some(match e {
                    VaultError::WrongPasswordOrTampered => {
                        s.failures += 1;
                        s.retry_at = retry_delay(s.failures).map(|d| Instant::now() + d);
                        "Wrong master password.".into()
                    }
                    other => other.to_string(),
                });
            }
            Poll::Failed => {
                s.job = None;
                s.error = Some("Unlocking failed unexpectedly.".into());
            }
        }
    }
    let busy = s.job.is_some();
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
        .unwrap_or_else(|| "Vault".into());

    egui::CentralPanel::default()
        .frame(Frame::new().fill(BG).inner_margin(24.0))
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
                            ui.add(
                                egui::Label::new(faint(s.path.display().to_string())).truncate(),
                            )
                            .on_hover_text(s.path.display().to_string());
                        });
                        ui.add_space(22.0);

                        let info = s.info.clone();
                        match &info {
                            Err(e) => {
                                widgets::danger_box(ui, &format!("This file can't be opened: {e}"))
                            }
                            Ok(info) => {
                                let resp = ui
                                    .add_enabled_ui(!busy, |ui| {
                                        widgets::password_input(
                                            ui,
                                            &mut s.password,
                                            &mut s.reveal,
                                            "Master password",
                                        )
                                    })
                                    .inner;
                                if s.focus_pending && !busy {
                                    resp.request_focus();
                                    s.focus_pending = false;
                                }
                                let enter =
                                    resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                                if let Some(e) = &s.error {
                                    widgets::error_text(ui, e);
                                    if s.failures >= FREE_ATTEMPTS {
                                        ui.label(small("Check Caps Lock and the keyboard layout."));
                                    }
                                }
                                ui.add_space(4.0);
                                if busy {
                                    ui.horizontal(|ui| {
                                        ui.add(egui::Spinner::new());
                                        ui.label(dim("Unlocking…"));
                                    });
                                } else if let Some(w) = wait {
                                    widgets::primary_button_wide(
                                        ui,
                                        &format!("Try again in {} s", w.as_secs() + 1),
                                        false,
                                    );
                                } else if widgets::primary_button_wide(
                                    ui,
                                    &icons::with(icons::LOCK_OPEN, "Unlock"),
                                    true,
                                )
                                .clicked()
                                    || (enter && !s.password.is_empty())
                                {
                                    s.start(ctx);
                                }
                                ui.add_space(2.0);
                                ui.vertical_centered(|ui| ui.label(faint(info.as_str())));
                            }
                        }
                        ui.add_space(18.0);
                        ui.add_enabled_ui(!busy, |ui| {
                            // Three links centred as one row.
                            let row_w = 290.0;
                            ui.horizontal(|ui| {
                                ui.add_space(((ui.available_width() - row_w) / 2.0).max(0.0));
                                ui.spacing_mut().item_spacing.x = 4.0;
                                if widgets::link_button(ui, "Open another…").clicked() {
                                    if let Some(p) = pick_vault_file() {
                                        t = Some(Transition::Unlock(p));
                                    }
                                }
                                ui.label(faint("·"));
                                if widgets::link_button(ui, "Create new").clicked() {
                                    t = Some(Transition::Create);
                                }
                                ui.label(faint("·"));
                                if widgets::link_button(ui, "Start screen").clicked() {
                                    t = Some(Transition::Welcome);
                                }
                            });
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
