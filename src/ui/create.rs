//! Create-vault screen.

use std::path::PathBuf;

use eframe::egui::{self, Frame, RichText};
use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

use super::icons;
use super::jobs::{Job, Poll};
use super::theme::*;
use super::widgets::{self, card, centered_column};
use super::{Services, Transition};
use crate::analysis::estimate_strength;
use crate::crypto::KdfParams;
use crate::error::VaultError;
use crate::storage::with_vault_extension;
use crate::vault::{UnlockedVault, MIN_MASTER_PASSWORD_CHARS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfPreset {
    Standard,
    Strong,
    Paranoid,
}

impl KdfPreset {
    pub const ALL: [KdfPreset; 3] = [KdfPreset::Standard, KdfPreset::Strong, KdfPreset::Paranoid];

    pub fn params(self) -> KdfParams {
        match self {
            KdfPreset::Standard => KdfParams::STANDARD,
            KdfPreset::Strong => KdfParams::STRONG,
            KdfPreset::Paranoid => KdfParams::PARANOID,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            KdfPreset::Standard => "Standard (64 MiB, recommended)",
            KdfPreset::Strong => "Strong (256 MiB, slower unlock)",
            KdfPreset::Paranoid => "Maximum (1 GiB, needs free RAM)",
        }
    }
}

/// Password buffers are pre-allocated so typing rarely reallocates (each
/// reallocation can leave an un-wiped fragment behind).
pub fn secret_buffer() -> Zeroizing<String> {
    Zeroizing::new(String::with_capacity(256))
}

pub struct CreateState {
    name: String,
    path: Option<PathBuf>,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    reveal: bool,
    preset: KdfPreset,
    acknowledged: bool,
    error: Option<String>,
    confirm_overwrite: bool,
    job: Option<Job<Result<UnlockedVault, VaultError>>>,
}

impl Default for CreateState {
    fn default() -> Self {
        CreateState {
            name: "Personal".into(),
            path: None,
            password: secret_buffer(),
            confirm: secret_buffer(),
            reveal: false,
            preset: KdfPreset::Standard,
            acknowledged: false,
            error: None,
            confirm_overwrite: false,
            job: None,
        }
    }
}

pub fn documents_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .map(|h| PathBuf::from(h).join("Documents"))
        .filter(|p| p.is_dir())
}

fn safe_file_stem(name: &str) -> String {
    let s: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || " -_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.trim().is_empty() {
        "Vault".into()
    } else {
        s
    }
}

impl CreateState {
    fn start(&mut self, ctx: &egui::Context, overwrite: bool) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let pw = SecretString::from(self.password.as_str().to_owned());
        let params = self.preset.params();
        let name = self.name.trim().to_string();
        self.error = None;
        self.job = Some(Job::spawn(ctx, move || {
            UnlockedVault::create(&path, &pw, params, &name, overwrite)
        }));
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.name.trim().is_empty() {
            return Err("Enter a name for the vault.");
        }
        if self.path.is_none() {
            return Err("Choose where to save the vault file.");
        }
        if self.password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
            return Err("The master password must be at least 10 characters.");
        }
        if *self.password != *self.confirm {
            return Err("The passwords don't match.");
        }
        if !self.acknowledged {
            return Err("Confirm that you understand there is no password recovery.");
        }
        Ok(())
    }
}

pub fn show(ctx: &egui::Context, s: &mut CreateState, _svc: &mut Services) -> Option<Transition> {
    let mut t = None;

    if let Some(job) = &s.job {
        match job.poll() {
            Poll::Pending => {}
            Poll::Done(Ok(v)) => {
                s.job = None;
                s.password.zeroize();
                s.confirm.zeroize();
                return Some(Transition::Open(Box::new(v)));
            }
            Poll::Done(Err(e)) => {
                s.job = None;
                s.error = Some(e.to_string());
            }
            Poll::Failed => {
                s.job = None;
                s.error = Some("Vault creation failed unexpectedly.".into());
            }
        }
    }
    let busy = s.job.is_some();

    egui::CentralPanel::default()
        .frame(Frame::new().fill(BG).inner_margin(24.0))
        .show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(((ui.available_height() - 640.0) / 2.0).max(16.0));
                centered_column(ui, 480.0, |ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        if widgets::link_button(ui, &icons::with(icons::ARROW_LEFT, "Back")).clicked() {
                            t = Some(Transition::Welcome);
                        }
                    });
                    ui.add_space(6.0);
                    ui.label(strong("New vault", 22.0));
                    ui.add_space(12.0);

                    card(ui, |ui| {
                        ui.add_enabled_ui(!busy, |ui| {
                            ui.label(small("Name"));
                            widgets::text_input(ui, &mut s.name, "Personal");
                            ui.add_space(6.0);

                            ui.label(small("File"));
                            let shown = s
                                .path
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "Not chosen yet".into());
                            let mut choose = false;
                            widgets::truncated_path_row(ui, &shown, |ui| {
                                choose = widgets::secondary_button(ui, "Choose…").clicked();
                            });
                            if choose {
                                let mut dlg = rfd::FileDialog::new()
                                    .set_title("Save new vault as")
                                    .add_filter("VaultRust vault", &["vault"])
                                    .set_file_name(format!("{}.vault", safe_file_stem(&s.name)));
                                if let Some(d) = documents_dir() {
                                    dlg = dlg.set_directory(d);
                                }
                                if let Some(p) = dlg.save_file() {
                                    s.path = Some(with_vault_extension(p));
                                }
                            }
                            ui.add_space(6.0);

                            ui.label(small("Master password"));
                            widgets::password_input(ui, &mut s.password, &mut s.reveal, "At least 10 characters");
                            if !s.password.is_empty() {
                                widgets::strength_meter(ui, &estimate_strength(&s.password));
                            }
                            ui.add_space(4.0);
                            ui.label(small("Confirm master password"));
                            let mut reveal2 = s.reveal;
                            widgets::password_input(ui, &mut s.confirm, &mut reveal2, "");
                            s.reveal = reveal2;
                            if !s.confirm.is_empty() && *s.confirm != *s.password {
                                ui.label(RichText::new("Doesn't match").color(DANGER).size(12.5));
                            }
                            ui.add_space(6.0);

                            egui::CollapsingHeader::new(small("Advanced"))
                                .id_salt("create_advanced")
                                .show(ui, |ui| {
                                    ui.label(small("Key derivation (Argon2id)"));
                                    egui::ComboBox::from_id_salt("kdf_preset")
                                        .width(ui.available_width())
                                        .icon(widgets::combo_caret)
                                        .selected_text(s.preset.label())
                                        .show_ui(ui, |ui| {
                                            for p in KdfPreset::ALL {
                                                ui.selectable_value(&mut s.preset, p, p.label());
                                            }
                                        });
                                });
                            ui.add_space(8.0);

                            widgets::warning_box(
                                ui,
                                "A forgotten master password cannot be recovered or reset — not even by you.",
                            );
                            ui.checkbox(&mut s.acknowledged, "I understand");
                        });
                        ui.add_space(8.0);

                        if let Some(e) = &s.error {
                            widgets::error_text(ui, e);
                        }
                        if busy {
                            ui.horizontal(|ui| {
                                ui.add(egui::Spinner::new());
                                ui.label(dim("Creating vault…"));
                            });
                        } else if widgets::primary_button_wide(ui, "Create vault", true).clicked() {
                            match s.validate() {
                                Err(e) => s.error = Some(e.into()),
                                Ok(()) => {
                                    if s.path.as_ref().is_some_and(|p| p.exists()) {
                                        s.confirm_overwrite = true;
                                    } else {
                                        s.start(ctx, false);
                                    }
                                }
                            }
                        }
                    });
                });
            });
        });

    if s.confirm_overwrite {
        let shown = s
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let mut decision = None;
        let resp = egui::Modal::new(egui::Id::new("create_overwrite")).show(ctx, |ui| {
            ui.set_width(420.0);
            ui.label(strong("Replace existing file?", 16.0));
            ui.add_space(4.0);
            ui.add(egui::Label::new(dim(shown)).wrap());
            ui.add_space(6.0);
            widgets::danger_box(ui, "Its current contents will be permanently lost.");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if widgets::danger_button(ui, "Replace").clicked() {
                    decision = Some(true);
                }
                if widgets::secondary_button(ui, "Cancel").clicked() {
                    decision = Some(false);
                }
            });
        });
        if resp.should_close() {
            decision = Some(false);
        }
        match decision {
            Some(true) => {
                s.confirm_overwrite = false;
                s.start(ctx, true);
            }
            Some(false) => s.confirm_overwrite = false,
            None => {}
        }
    }
    t
}
