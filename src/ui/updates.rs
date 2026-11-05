//! Update checks, the "new version" banner and installing it.

use eframe::egui::{self, Frame, Margin, RichText};

use super::icons;
use super::jobs::{Job, Poll};
use super::theme::*;
use super::widgets;
use crate::prefs::AppPrefs;
use crate::timeutil::now_unix;
use crate::update::{self, Release, UpdateError};

/// Automatic checks happen at most this often.
const CHECK_INTERVAL_SECS: i64 = 24 * 3600;

#[derive(Default)]
pub struct Updates {
    check: Option<Job<Result<Option<Release>, UpdateError>>>,
    install: Option<Job<Result<(), UpdateError>>>,
    /// A newer, not yet installed release.
    pub available: Option<Release>,
    /// Result of the last check the user asked for, for Settings.
    pub status: Option<String>,
    /// The banner was closed with "Later" (until the next start).
    dismissed: bool,
    /// The new program is in place; restart into it.
    pub installed: bool,
    started: bool,
}

impl Updates {
    pub fn is_busy(&self) -> bool {
        self.check.is_some() || self.install.is_some()
    }

    pub fn is_installing(&self) -> bool {
        self.install.is_some()
    }

    /// Ask GitHub for a newer release in the background.
    pub fn check_now(&mut self, ctx: &egui::Context) {
        if self.check.is_none() && self.install.is_none() {
            self.status = None;
            self.check = Some(Job::spawn(ctx, update::check));
        }
    }

    pub fn install_now(&mut self, ctx: &egui::Context) {
        let Some(release) = self.available.clone() else {
            return;
        };
        if self.install.is_some() {
            return;
        }
        self.install = Some(Job::spawn(ctx, move || {
            let exe = std::env::current_exe().map_err(|e| UpdateError::Install(e.to_string()))?;
            let bytes = update::download(&release)?;
            update::install(&exe, &bytes)
        }));
    }

    /// Call every frame. Starts the daily check once per run and collects
    /// finished work; returns an error message to show, if any.
    pub fn tick(&mut self, ctx: &egui::Context, prefs: &mut AppPrefs) -> Option<String> {
        if !self.started {
            self.started = true;
            if let Ok(exe) = std::env::current_exe() {
                update::clean_up(&exe);
            }
            let due = now_unix() - prefs.last_update_check >= CHECK_INTERVAL_SECS;
            if prefs.check_updates && due && !cfg!(test) {
                self.check_now(ctx);
            }
        }
        let mut message = None;
        if let Some(job) = &self.check {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(r) => {
                    self.check = None;
                    prefs.last_update_check = now_unix();
                    prefs.save();
                    match r {
                        Ok(Some(rel)) => {
                            self.status = Some(format!("Version {} is available", rel.version));
                            self.available = Some(rel);
                            self.dismissed = false;
                        }
                        Ok(None) => {
                            self.status = Some(format!(
                                "VaultRust {} is the latest version",
                                update::current_version()
                            ))
                        }
                        Err(e) => self.status = Some(e.to_string()),
                    }
                }
                Poll::Failed => self.check = None,
            }
        }
        if let Some(job) = &self.install {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(Ok(())) => {
                    self.install = None;
                    self.installed = true;
                }
                Poll::Done(Err(e)) => {
                    self.install = None;
                    message = Some(e.to_string());
                }
                Poll::Failed => {
                    self.install = None;
                    message = Some("The update stopped unexpectedly".into());
                }
            }
        }
        message
    }

    /// The strip across the top of the window while an update is available.
    /// Returns true when the user chose to install it.
    pub fn banner(&mut self, ctx: &egui::Context) -> bool {
        let Some(rel) = &self.available else {
            return false;
        };
        if self.dismissed && !self.is_installing() {
            return false;
        }
        let mut install = false;
        let mut later = false;
        egui::TopBottomPanel::top("update_banner")
            .frame(
                Frame::new()
                    .fill(surface_2())
                    .stroke(egui::Stroke::new(1.0, border()))
                    .inner_margin(Margin::symmetric(16, 8)),
            )
            .show_separator_line(false)
            .show(ctx, |ui| {
                widgets::trailing_row(
                    ui,
                    egui::Align::Center,
                    |ui| {
                        if self.install.is_some() {
                            ui.label(dim("Downloading and checking the signature…"));
                            ui.add(egui::Spinner::new());
                            return;
                        }
                        if widgets::link_button(ui, "Later").clicked() {
                            later = true;
                        }
                        if widgets::primary_button(ui, "Update and restart")
                            .on_hover_text("Your vault is locked and saved first")
                            .clicked()
                        {
                            install = true;
                        }
                    },
                    |ui| {
                        ui.horizontal_centered(|ui| {
                            ui.label(
                                RichText::new(icons::ARROW_CIRCLE_UP)
                                    .color(accent())
                                    .size(17.0),
                            );
                            ui.label(strong(
                                format!("VaultRust {} is available", rel.version),
                                14.0,
                            ));
                            let notes = rel.notes.trim();
                            if !notes.is_empty() {
                                let short: String = notes.chars().take(1200).collect();
                                ui.label(faint("What's new")).on_hover_text(short);
                            }
                        });
                    },
                );
            });
        if later {
            self.dismissed = true;
        }
        install
    }
}

/// The "Updates" row in Settings.
pub fn settings_row(ui: &mut egui::Ui, updates: &mut Updates, prefs: &mut AppPrefs) {
    let mut auto = prefs.check_updates;
    widgets::switch_row(
        ui,
        &mut auto,
        "Check for updates automatically",
        &format!(
            "Once a day, VaultRust asks GitHub ({}) for a newer, signed release. No vault data is sent",
            update::REPO
        ),
    );
    if auto != prefs.check_updates {
        prefs.check_updates = auto;
        prefs.save();
    }
    widgets::divider(ui, 16.0);
    let desc = updates
        .status
        .clone()
        .unwrap_or_else(|| format!("You have version {}", update::current_version()));
    let mut check = false;
    let mut install = false;
    widgets::setting_row(ui, "Updates", &desc, 200.0, |ui| {
        if updates.is_busy() {
            ui.add(egui::Spinner::new());
        } else if updates.available.is_some() {
            install = widgets::primary_button(ui, "Update and restart").clicked();
        } else {
            check = widgets::secondary_button(ui, "Check now").clicked();
        }
    });
    if check {
        updates.check_now(ui.ctx());
    }
    if install {
        updates.install_now(ui.ctx());
    }
}
