//! Security report: weak, reused and old passwords.

use eframe::egui::{self, Align2, Color32, CursorIcon, FontId, Rect, RichText, Sense, Vec2};

use super::icons;
use super::main_view::{MainState, Nav};
use super::theme::*;
use super::widgets;
use super::Services;
use crate::i18n::tr;
use crate::model::Entry;
use crate::timeutil::{age_description, expiry_description, now_unix};
use crate::trf;

pub fn show(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
    let mut open = None;
    let mut trash: Option<Vec<u64>> = None;
    egui::ScrollArea::vertical()
        .id_salt("security")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            widgets::page_header(ui, tr("Security"), tr("Checked locally, on this computer only."));
            let h = &ms.health;
            let data = ms.vault.data();

            if h.total_passwords == 0 {
                // A score for zero passwords would be meaningless.
                widgets::card(ui, |ui| {
                    ui.label(strong(tr("Nothing to check yet"), 15.0));
                    ui.label(faint(
                        tr("Once you add logins, VaultRust checks their passwords here for weak, reused and old ones."),
                    ));
                });
                ui.add_space(20.0);
            } else {
            score_card(ui, h.score, &trf!(
                "{} passwords checked · {} weak · {} reused · {} not changed in a year",
                h.total_passwords,
                h.weak.len(),
                h.reused_count(),
                h.old.len()
            ));
            ui.add_space(20.0);
            }

            if h.total_passwords > 0 {
            match &ms.breach.report {
                Some(b) if b.error.is_none() => {
                    heading(ui, tr("Found in data breaches"), b.hits.len());
                    if b.hits.is_empty() {
                        ui.label(dim(tr("None of your passwords appear in the list.")));
                    } else {
                        ui.label(faint(
                            tr("These exact passwords are known to attackers. Change them, even if they look strong."),
                        ));
                        ui.add_space(2.0);
                        widgets::group(ui, |ui| {
                            for (n, (r, count)) in b.hits.iter().enumerate() {
                                let Some(e) = data.entry(r.entry_id) else { continue };
                                if n > 0 {
                                    widgets::divider(ui, 14.0);
                                }
                                let seen = if *count > 1 {
                                    trf!("Seen {count} times", count)
                                } else {
                                    tr("Breached").to_string()
                                };
                                if issue_row(ui, e, &seen, danger()).clicked() {
                                    open = Some(e.id);
                                }
                            }
                        });
                    }
                    ui.add_space(20.0);
                }
                Some(b) => {
                    widgets::warning_box(ui, b.error.as_deref().unwrap_or_default());
                    ui.add_space(20.0);
                }
                None if ms.breach.is_running() => {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new());
                        ui.label(dim(tr("Checking passwords against the breach list…")));
                    });
                    ui.add_space(20.0);
                }
                None => {
                    ui.label(faint(trf!(
                        "{}  Add a Have I Been Pwned list in Settings to also check for breached passwords, offline.",
                        icons::INFO
                    )));
                    ui.add_space(20.0);
                }
            }

            heading(ui, tr("Weak passwords"), h.weak.len());
            if h.weak.is_empty() {
                ui.label(dim(tr("None.")));
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

            heading(ui, tr("Reused passwords"), h.reused_count());
            if h.reused.is_empty() {
                ui.label(dim(tr("None — every password is unique.")));
            }
            for group in &h.reused {
                ui.label(faint(trf!("Same password in {} items", group.len())));
                ui.add_space(2.0);
                widgets::group(ui, |ui| {
                    for (n, r) in group.iter().enumerate() {
                        let Some(e) = data.entry(r.entry_id) else { continue };
                        if n > 0 {
                            widgets::divider(ui, 14.0);
                        }
                        if issue_row(ui, e, tr("Reused"), warn()).clicked() {
                            open = Some(e.id);
                        }
                    }
                });
                ui.add_space(10.0);
            }
            ui.add_space(10.0);

            if !h.duplicates.is_empty() {
                heading(ui, tr("Possible duplicates"), h.duplicates.len());
                ui.label(faint(
                    tr("Items for the same account (same website and username). Keep one and move the rest to the Trash."),
                ));
                ui.add_space(4.0);
                for group in &h.duplicates {
                    let items: Vec<&Entry> = group.iter().filter_map(|id| data.entry(*id)).collect();
                    let Some(keep) = items.iter().max_by_key(|e| (e.modified, e.created)) else {
                        continue;
                    };
                    let keep = keep.id;
                    if items.len() < 2 {
                        continue;
                    }
                    let first = items[0];
                    let site = first
                        .first_of(crate::model::FieldKind::Url)
                        .map(crate::autotype::url_host)
                        .filter(|h| !h.is_empty())
                        .unwrap_or_else(|| first.display_title().to_string());
                    widgets::trailing_row(
                        ui,
                        egui::Align::Center,
                        |ui| {
                            if widgets::link_button(ui, tr("Keep the newest, move the others to Trash"))
                                .on_hover_text(tr("Keeps the item updated most recently; Undo brings the others back"))
                                .clicked()
                            {
                                trash = Some(
                                    items.iter().map(|e| e.id).filter(|id| *id != keep).collect(),
                                );
                            }
                        },
                        |ui| {
                            ui.label(faint(trf!("{} items for {site}", items.len(), site)));
                        },
                    );
                    widgets::group(ui, |ui| {
                        for (n, e) in items.iter().enumerate() {
                            if n > 0 {
                                widgets::divider(ui, 14.0);
                            }
                            let status = if e.id == keep {
                                trf!("Newest · updated {}", crate::timeutil::format_date(e.modified))
                            } else {
                                trf!("Updated {}", crate::timeutil::format_date(e.modified))
                            };
                            let color = if e.id == keep { accent() } else { text_dim() };
                            if issue_row(ui, e, &status, color).clicked() {
                                open = Some(e.id);
                            }
                        }
                    });
                    ui.add_space(10.0);
                }
                ui.add_space(10.0);
            }

            let now = now_unix();
            for (title, list) in [(tr("Expired"), &h.expired), (tr("Expiring soon"), &h.expiring)] {
                if list.is_empty() {
                    continue;
                }
                heading(ui, title, list.len());
                widgets::group(ui, |ui| {
                    for (n, (id, at)) in list.iter().enumerate() {
                        let Some(e) = data.entry(*id) else { continue };
                        if n > 0 {
                            widgets::divider(ui, 14.0);
                        }
                        let color = if *at <= now { danger() } else { warn() };
                        if issue_row(ui, e, &expiry_description(*at, now), color).clicked() {
                            open = Some(e.id);
                        }
                    }
                });
                ui.add_space(20.0);
            }

            heading(ui, tr("Old passwords"), h.old.len());
            if h.old.is_empty() {
                ui.label(dim(tr("None — all changed within the last year.")));
            } else {
                let now = now_unix();
                widgets::group(ui, |ui| {
                    for (n, id) in h.old.iter().enumerate() {
                        let Some(e) = data.entry(*id) else { continue };
                        if n > 0 {
                            widgets::divider(ui, 14.0);
                        }
                        let when = trf!("Changed {}", age_description(e.password_changed, now));
                        if issue_row(ui, e, &when, text_dim()).clicked() {
                            open = Some(e.id);
                        }
                    }
                });
            }
            ui.add_space(20.0);
            }
            activity_log(ui, &data.audit);
            ui.add_space(16.0);
            ui.label(faint(trf!(
                "{}  Strength is an estimate. See docs/SECURITY.md for what VaultRust can and can't protect against.",
                icons::INFO
            )));
        });
    if let Some(ids) = trash {
        ms.trash_many(svc, &ids);
    } else if let Some(id) = open {
        ms.request(Nav::Open(id));
    }
}

fn score_card(ui: &mut egui::Ui, score: u32, summary: &str) {
    let (color, verdict) = match score {
        90..=100 => (accent(), tr("Excellent")),
        70..=89 => (warn(), tr("Could be better")),
        _ => (danger(), tr("Needs attention")),
    };
    widgets::card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(strong(score.to_string(), 34.0).color(color));
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.add_space(6.0);
                ui.label(faint(tr("of 100")));
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
        ui.painter().rect_filled(rect, 2.0, rail());
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
                    .color(text_faint()),
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
            .rect_filled(rect.expand2(Vec2::new(8.0, 2.0)), 6.0, row_hover());
    }
    let tile = Rect::from_center_size(rect.left_center() + Vec2::new(14.0, 0.0), Vec2::splat(28.0));
    widgets::entry_tile(ui, tile, e);
    let p = ui.painter_at(rect);
    p.text(
        rect.right_center(),
        Align2::RIGHT_CENTER,
        icons::CARET_RIGHT,
        FontId::proportional(13.0),
        if resp.hovered() { text() } else { text_faint() },
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
        text(),
    );
    if !sub.is_empty() {
        tp.text(
            egui::pos2(tile.right() + 12.0, rect.center().y + 9.0),
            Align2::LEFT_CENTER,
            sub,
            FontId::proportional(12.0),
            text_faint(),
        );
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// Newest-first list of what happened to this vault (stored encrypted
/// inside it). Exports and switched-off protections stand out.
fn activity_log(ui: &mut egui::Ui, events: &[crate::model::AuditEvent]) {
    heading(ui, tr("Activity"), events.len());
    if events.is_empty() {
        ui.label(dim(tr("Nothing recorded yet.")));
        return;
    }
    ui.label(faint(tr(
        "Recorded inside the encrypted vault; times are UTC.",
    )));
    ui.add_space(2.0);
    widgets::group(ui, |ui| {
        egui::ScrollArea::vertical()
            .id_salt("activity")
            .max_height(260.0)
            .show(ui, |ui| {
                for (n, ev) in events.iter().rev().enumerate() {
                    if n > 0 {
                        widgets::divider(ui, 14.0);
                    }
                    widgets::trailing_row_h(
                        ui,
                        24.0,
                        egui::Align::Center,
                        |ui| {
                            ui.label(faint(crate::timeutil::format_datetime(ev.at)));
                        },
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 8.0;
                                let color = if ev.kind.is_sensitive() {
                                    warn()
                                } else {
                                    text()
                                };
                                ui.label(RichText::new(ev.kind.label()).color(color));
                                if !ev.detail.is_empty() {
                                    ui.add(egui::Label::new(faint(&ev.detail)).truncate());
                                }
                            });
                        },
                    );
                }
            });
    });
}
