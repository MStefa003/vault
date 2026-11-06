//! The welcome tour: a few cards shown once, after the first vault is
//! opened, covering what isn't obvious from the screens themselves (auto-type,
//! the QR scanner, quick open, clipboard clearing, backups).

use eframe::egui::{self, Align2, FontId, Id, Key, RichText, Sense, Vec2};

use super::icons;
use super::theme::*;
use super::widgets;
use crate::i18n::tr;
use crate::os_protect::{AUTO_TYPE_HOTKEY, QUICK_OPEN_HOTKEY};
use crate::trf;

struct Step {
    icon: &'static str,
    title: &'static str,
    text: String,
    tips: Vec<(&'static str, String)>,
}

fn steps() -> Vec<Step> {
    vec![
        Step {
            icon: icons::VAULT,
            title: tr("Welcome to VaultRust"),
            text: tr("Your passwords are kept in one encrypted file on this computer. Nothing is uploaded anywhere.")
                .into(),
            tips: vec![
                (
                    icons::KEY,
                    tr("Your master password unlocks everything. Nobody can reset it, so keep it somewhere you won't lose it.")
                        .into(),
                ),
                (
                    icons::FLOPPY_DISK,
                    tr("Use Back up now and then to keep a copy on a USB stick or another drive.").into(),
                ),
            ],
        },
        Step {
            icon: icons::PLUS_CIRCLE,
            title: tr("Save your logins"),
            text: tr("Click New item → Login and fill in the website, username and password.").into(),
            tips: vec![
                (icons::DICE_FIVE, tr("The dice button makes a strong password for you.").into()),
                (
                    icons::TEXT_AA,
                    tr("Leave the title empty and the item is named after its website.").into(),
                ),
                (
                    icons::DOWNLOAD_SIMPLE,
                    tr("Coming from Chrome, Edge or another password manager? Import brings everything over.")
                        .into(),
                ),
            ],
        },
        Step {
            icon: icons::COPY,
            title: tr("Use a password"),
            text: tr("Open an item, or hover it on the Overview, and click the copy button next to the username or password.")
                .into(),
            tips: vec![
                (
                    icons::CLOCK_COUNTDOWN,
                    tr("Copied passwords are wiped from the clipboard after 30 seconds.").into(),
                ),
                (
                    icons::MAGNIFYING_GLASS,
                    trf!("Ctrl+K searches the vault. {QUICK_OPEN_HOTKEY} opens the search from any app.", QUICK_OPEN_HOTKEY),
                ),
            ],
        },
        Step {
            icon: icons::KEYBOARD,
            title: tr("Log in without copying"),
            text: trf!(
                "Click into a login form in your browser or any app, press {AUTO_TYPE_HOTKEY} and pick the account. \
                 VaultRust types the username and password for you.", AUTO_TYPE_HOTKEY
            ),
            tips: vec![(
                icons::LIGHTBULB,
                tr("Accounts for the website you're on are listed first.").into(),
            )],
        },
        Step {
            icon: icons::QR_CODE,
            title: tr("Two-step codes"),
            text: tr("When a site shows a QR code to set up two-step verification, click Scan 2FA code. \
                   VaultRust reads it from your screen and shows the 6-digit code whenever you need it.")
                .into(),
            tips: vec![(
                icons::DEVICE_MOBILE_SLASH,
                tr("No phone needed — the code is copied like a password.").into(),
            )],
        },
        Step {
            icon: icons::SHIELD_CHECK,
            title: tr("Stay safe"),
            text: tr("VaultRust keeps an eye on things for you.").into(),
            tips: vec![
                (
                    icons::WARNING,
                    tr("The Security page lists weak, reused and old passwords.").into(),
                ),
                (
                    icons::LOCK,
                    tr("The vault locks itself after a few idle minutes and when Windows locks.").into(),
                ),
                (
                    icons::FINGERPRINT,
                    tr("Turn on Windows Hello in Settings to unlock with your face, fingerprint or PIN.")
                        .into(),
                ),
            ],
        },
    ]
}

/// Height reserved for a card's icon, text and tips.
const CARD_BODY_H: f32 = 300.0;

/// Where the tour is.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tour {
    pub step: usize,
}

/// Draw the tour. Returns true once it is finished or skipped.
pub fn show(ctx: &egui::Context, tour: &mut Tour) -> bool {
    let steps = steps();
    let last = steps.len() - 1;
    tour.step = tour.step.min(last);
    let mut done = false;
    let (next, back, skip) = ctx.input(|i| {
        (
            i.key_pressed(Key::ArrowRight) || i.key_pressed(Key::Enter),
            i.key_pressed(Key::ArrowLeft),
            i.key_pressed(Key::Escape),
        )
    });
    if skip {
        return true;
    }
    if next {
        if tour.step == last {
            return true;
        }
        tour.step += 1;
    }
    if back {
        tour.step = tour.step.saturating_sub(1);
    }
    let step = &steps[tour.step];

    // Clicking outside doesn't close it, so a stray click can't skip it.
    egui::Modal::new(Id::new("vaultrust_tour")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.horizontal(|ui| {
            ui.label(faint(format!("{} of {}", tour.step + 1, steps.len())));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if tour.step < last && widgets::link_button(ui, tr("Skip tour")).clicked() {
                    done = true;
                }
            });
        });
        ui.add_space(8.0);
        // Same height on every card, so Back / Next don't move under the
        // pointer while clicking through.
        ui.vertical(|ui| {
            ui.set_min_height(CARD_BODY_H);
            let (tile, _) = ui.allocate_exact_size(Vec2::splat(52.0), Sense::hover());
            ui.painter().rect_filled(tile, 14.0, accent_bg());
            ui.painter().text(
                tile.center(),
                Align2::CENTER_CENTER,
                step.icon,
                FontId::proportional(26.0),
                accent(),
            );
            ui.add_space(14.0);
            ui.label(strong(step.title, 20.0));
            ui.add_space(4.0);
            ui.label(RichText::new(&step.text).color(text_dim()).size(14.0));
            if !step.tips.is_empty() {
                ui.add_space(14.0);
                widgets::group(ui, |ui| {
                    ui.add_space(4.0);
                    for (icon, tip) in &step.tips {
                        ui.horizontal_top(|ui| {
                            ui.spacing_mut().item_spacing.x = 10.0;
                            ui.label(RichText::new(*icon).size(16.0).color(accent()));
                            ui.add(
                                egui::Label::new(RichText::new(tip).size(13.0).color(text()))
                                    .wrap(),
                            );
                        });
                        ui.add_space(6.0);
                    }
                });
            }
        });
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            // Progress dots.
            for i in 0..steps.len() {
                let (r, _) = ui.allocate_exact_size(Vec2::new(14.0, 8.0), Sense::hover());
                let color = if i == tour.step { accent() } else { rail() };
                ui.painter().circle_filled(r.center(), 3.5, color);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if tour.step == last {
                    tr("Get started")
                } else {
                    tr("Next")
                };
                if widgets::primary_button(ui, label).clicked() {
                    if tour.step == last {
                        done = true;
                    } else {
                        tour.step += 1;
                    }
                }
                if tour.step > 0 && widgets::secondary_button(ui, tr("Back")).clicked() {
                    tour.step -= 1;
                }
            });
        });
    });
    done
}
