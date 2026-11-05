//! Transient notifications in the bottom-right corner.

use std::time::{Duration, Instant};

use eframe::egui::{self, Align2, Color32, Frame, Id, Order, RichText, Stroke};

use super::icons;
use super::theme::*;

#[derive(Clone, Copy)]
enum Kind {
    Info,
    Success,
    Error,
}

#[derive(Default)]
pub struct Toasts {
    items: Vec<(String, Kind, Instant)>,
}

impl Toasts {
    fn push(&mut self, msg: String, kind: Kind, secs: u64) {
        self.items
            .push((msg, kind, Instant::now() + Duration::from_secs(secs)));
        if self.items.len() > 3 {
            self.items.remove(0);
        }
    }

    pub fn info(&mut self, msg: impl Into<String>) {
        self.push(msg.into(), Kind::Info, 4);
    }

    pub fn success(&mut self, msg: impl Into<String>) {
        self.push(msg.into(), Kind::Success, 4);
    }

    pub fn error(&mut self, msg: impl Into<String>) {
        self.push(msg.into(), Kind::Error, 8);
    }

    pub fn show(&mut self, ctx: &egui::Context) {
        let now = Instant::now();
        self.items.retain(|(_, _, until)| *until > now);
        if self.items.is_empty() {
            return;
        }
        egui::Area::new(Id::new("vaultrust_toasts"))
            .order(Order::Tooltip)
            .anchor(Align2::RIGHT_BOTTOM, [-16.0, -16.0])
            .interactable(false)
            .show(ctx, |ui| {
                for (msg, kind, _) in &self.items {
                    let (icon, color) = match kind {
                        Kind::Info => (icons::INFO, TEXT_DIM),
                        Kind::Success => (icons::CHECK_CIRCLE, ACCENT),
                        Kind::Error => (icons::WARNING_CIRCLE, DANGER),
                    };
                    Frame::new()
                        .fill(SURFACE_2)
                        .stroke(Stroke::new(1.0, BORDER))
                        .corner_radius(8.0)
                        .inner_margin(egui::Margin::symmetric(12, 9))
                        .shadow(egui::Shadow {
                            offset: [0, 4],
                            blur: 12,
                            spread: 0,
                            color: Color32::from_black_alpha(80),
                        })
                        .show(ui, |ui| {
                            ui.set_max_width(360.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(icon).color(color).size(15.0));
                                ui.label(RichText::new(msg).color(TEXT));
                            });
                        });
                    ui.add_space(6.0);
                }
            });
    }
}
