//! Security report: weak, reused and old passwords.

use eframe::egui::{self, Align2, Color32, CursorIcon, FontId, Rect, RichText, Sense, Vec2};

use super::icons::{self, kind_icon};
use super::main_view::{MainState, Nav};
use super::theme::*;
use super::widgets;
use super::Services;
use crate::model::Entry;
use crate::timeutil::{age_description, now_unix};

pub fn show(ui: &mut egui::Ui, ms: &mut MainState, _svc: &mut Services) {
    let mut open = None;
    egui::ScrollArea::vertical()
        .id_salt("security")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            widgets::page_header(ui, "Security", "Checked locally, on this computer only.");
            let h = &ms.health;
            let data = ms.vault.data();

            score_card(ui, h.score, &format!(
                "{} passwords checked · {} weak · {} reused · {} not changed in a year",
                h.total_passwords,
                h.weak.len(),
                h.reused_count(),
                h.old.len()
            ));
            ui.add_space(20.0);

            heading(ui, "Weak passwords", h.weak.len());
            if h.weak.is_empty() {
                ui.label(dim("None."));
            } else {
                widgets::group(ui, |ui| {
                    for (n, w) in h.weak.iter().enumerate() {
                        let Some(e) = data.entry(w.at.entry_id) else { continue };
                        if n > 0 {
                            widgets::divider(ui, 14.0);
                        }
                        let s = w.strength;
                        if issue_row(ui, e, s.label(), strength_color(s)).clicked() {
                            open = Some(e.id);
                        }
                    }
                });
            }
            ui.add_space(20.0);

            heading(ui, "Reused passwords", h.reused_count());
            if h.reused.is_empty() {
                ui.label(dim("None — every password is unique."));
            }
            for group in &h.reused {
                ui.label(faint(format!("Same password in {} items", group.len())));
                ui.add_space(2.0);
                widgets::group(ui, |ui| {
                    for (n, r) in group.iter().enumerate() {
                        let Some(e) = data.entry(r.entry_id) else { continue };
                        if n > 0 {
                            widgets::divider(ui, 14.0);
                        }
                        if issue_row(ui, e, "Reused", WARN).clicked() {
                            open = Some(e.id);
                        }
                    }
                });
                ui.add_space(10.0);
            }
            ui.add_space(10.0);

            heading(ui, "Old passwords", h.old.len());
            if h.old.is_empty() {
                ui.label(dim("None — all changed within the last year."));
            } else {
                let now = now_unix();
                widgets::group(ui, |ui| {
                    for (n, id) in h.old.iter().enumerate() {
                        let Some(e) = data.entry(*id) else { continue };
                        if n > 0 {
                            widgets::divider(ui, 14.0);
                        }
                        let when = format!("Changed {}", age_description(e.password_changed, now));
                        if issue_row(ui, e, &when, TEXT_DIM).clicked() {
                            open = Some(e.id);
                        }
                    }
                });
            }
            ui.add_space(16.0);
            ui.label(faint(format!(
                "{}  Strength is an estimate. See docs/SECURITY.md for what VaultRust can and can't protect against.",
                icons::INFO
            )));
        });
    if let Some(id) = open {
        ms.request(Nav::Open(id));
    }
}

fn score_card(ui: &mut egui::Ui, score: u32, summary: &str) {
    let (color, verdict) = match score {
        90..=100 => (ACCENT, "Excellent"),
        70..=89 => (WARN, "Could be better"),
        _ => (DANGER, "Needs attention"),
    };
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(strong(score.to_string(), 34.0).color(color));
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.add_space(6.0);
                ui.label(faint("of 100"));
            });
            ui.add_space(12.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.add_space(4.0);
                ui.label(strong(verdict, 15.0));
                ui.label(faint(summary));
            });
        });
        ui.add_space(8.0);
        let (rect, _) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), 4.0), Sense::hover());
        ui.painter().rect_filled(rect, 2.0, RAIL);
        let mut part = rect;
        part.set_width(rect.width() * score.min(100) as f32 / 100.0);
        ui.painter().rect_filled(part, 2.0, color);
    });
}

fn heading(ui: &mut egui::Ui, title: &str, count: usize) {
    ui.horizontal(|ui| {
        ui.label(strong(title, 15.0));
        if count > 0 {
            ui.label(
                RichText::new(count.to_string())
                    .size(12.5)
                    .color(TEXT_FAINT),
            );
        }
    });
    ui.add_space(4.0);
}

/// Clickable row: type tile, title, status on the right and a chevron.
fn issue_row(ui: &mut egui::Ui, e: &Entry, status: &str, color: Color32) -> egui::Response {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 40.0), Sense::click());
    if resp.hovered() {
        ui.painter()
            .rect_filled(rect.expand2(Vec2::new(8.0, 2.0)), 6.0, ROW_HOVER);
    }
    let tile = Rect::from_center_size(rect.left_center() + Vec2::new(14.0, 0.0), Vec2::splat(28.0));
    widgets::kind_tile(ui, tile, kind_icon(e.kind));
    let p = ui.painter_at(rect);
    p.text(
        rect.right_center(),
        Align2::RIGHT_CENTER,
        icons::CARET_RIGHT,
        FontId::proportional(13.0),
        if resp.hovered() { TEXT } else { TEXT_FAINT },
    );
    let status_rect = p.text(
        rect.right_center() - Vec2::new(24.0, 0.0),
        Align2::RIGHT_CENTER,
        status,
        FontId::proportional(12.5),
        color,
    );
    let tp = ui.painter_at(rect.with_max_x(status_rect.left() - 12.0));
    let sub = e.subtitle();
    let dy = if sub.is_empty() { 0.0 } else { -8.0 };
    tp.text(
        egui::pos2(tile.right() + 12.0, rect.center().y + dy),
        Align2::LEFT_CENTER,
        e.display_title(),
        FontId::proportional(14.0),
        TEXT,
    );
    if !sub.is_empty() {
        tp.text(
            egui::pos2(tile.right() + 12.0, rect.center().y + 9.0),
            Align2::LEFT_CENTER,
            sub,
            FontId::proportional(12.0),
            TEXT_FAINT,
        );
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}
