//! Home: search first, then favorites with one-click copy, password health,
//! and recently edited items. An empty vault gets a getting-started panel.

use eframe::egui::{
    self, Align2, Button, CursorIcon, FontId, Frame, Id, Key, Modifiers, Rect, RichText, Sense,
    Stroke, TextEdit, Vec2,
};
use zeroize::Zeroizing;

use super::entries::Category;
use super::icons::{self, kind_icon};
use super::main_view::{MainState, Nav, Page};
use super::theme::*;
use super::widgets;
use super::{settings_page, Services};
use crate::analysis::{HealthReport, PasswordRef};
use crate::model::{Entry, EntryKind, FieldKind};
use crate::timeutil::{age_description, now_unix};

const SEARCH_ID: &str = "vaultrust_home_search";
/// Backups older than this are flagged.
const STALE_BACKUP_DAYS: i64 = 30;

enum Act {
    Nav(Nav),
    Copy(Zeroizing<String>, &'static str),
    Backup,
    Import,
}

pub fn show(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
    let mut acts: Vec<Act> = Vec::new();

    if ui.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::F)) {
        ui.memory_mut(|m| m.request_focus(Id::new(SEARCH_ID)));
    }

    egui::ScrollArea::vertical()
        .id_salt("home")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Keep the content at a readable width on large windows.
            let width = ui.available_width().min(880.0);
            ui.set_max_width(width);

            header(ui, ms, &mut acts);
            ui.add_space(14.0);

            let data = ms.vault.data();
            if data.entries.is_empty() {
                empty_vault(ui, &mut acts);
                return;
            }

            search_box(ui, &mut ms.home_query, data.entries.len());
            ui.add_space(18.0);

            let q = ms.home_query.trim().to_lowercase();
            if !q.is_empty() {
                let mut hits: Vec<&Entry> = data.entries.iter().filter(|e| e.matches(&q)).collect();
                hits.sort_by(|a, b| {
                    let starts = |e: &Entry| e.title.to_lowercase().starts_with(&q);
                    starts(b)
                        .cmp(&starts(a))
                        .then_with(|| b.favorite.cmp(&a.favorite))
                        .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
                });
                if ui.input(|i| i.key_pressed(Key::Enter)) {
                    if let Some(first) = hits.first() {
                        acts.push(Act::Nav(Nav::Open(first.id)));
                    }
                }
                heading(
                    ui,
                    &format!(
                        "{} result{}",
                        hits.len(),
                        if hits.len() == 1 { "" } else { "s" }
                    ),
                    None,
                );
                if hits.is_empty() {
                    ui.label(dim(
                        "Nothing matches. Search covers titles, usernames, emails and websites.",
                    ));
                }
                for e in hits.iter().take(20) {
                    item_row(ui, e, e.kind.label(), &mut acts);
                }
                return;
            }

            let favorites: Vec<&Entry> = data.entries.iter().filter(|e| e.favorite).collect();
            if !favorites.is_empty() {
                heading(ui, "Favorites", None);
                favorites_grid(ui, &favorites, &mut acts);
                ui.add_space(20.0);
            }

            if let Some(n) = heading(
                ui,
                "Password health",
                Some(("Review", Nav::Page(Page::Security))),
            ) {
                acts.push(Act::Nav(n));
            }
            health_strip(ui, &ms.health);
            ui.add_space(20.0);

            let all = Nav::Page(Page::Items(Category::All));
            if let Some(n) = heading(ui, "Recently edited", Some(("All items", all))) {
                acts.push(Act::Nav(n));
            }
            let mut recent: Vec<&Entry> = data.entries.iter().collect();
            recent.sort_by_key(|e| std::cmp::Reverse(e.modified));
            let now = now_unix();
            for e in recent.into_iter().take(8) {
                let when = format!("{} · {}", e.kind.label(), age_description(e.modified, now));
                item_row(ui, e, &when, &mut acts);
            }
            if favorites.is_empty() {
                ui.add_space(14.0);
                ui.label(faint(format!(
                    "{}  Star items you use often to pin them here.",
                    icons::STAR
                )));
            }
        });

    for act in acts {
        match act {
            Act::Nav(n) => ms.request(n),
            Act::Copy(v, what) => ms.copy_secret(svc, &v, what),
            Act::Backup => ms.start_backup(svc),
            Act::Import => settings_page::start_import(ms, svc),
        }
    }
}

fn header(ui: &mut egui::Ui, ms: &MainState, acts: &mut Vec<Act>) {
    let data = ms.vault.data();
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.label(strong(&data.name, 24.0));
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let n = data.entries.len();
                ui.label(dim(format!("{n} item{}", if n == 1 { "" } else { "s" })));
                ui.label(faint("·"));
                let now = now_unix();
                let (text, color) = if data.last_backup == 0 {
                    ("Never backed up".to_string(), WARN)
                } else if now - data.last_backup > STALE_BACKUP_DAYS * 86_400 {
                    (
                        format!("Last backup {}", age_description(data.last_backup, now)),
                        WARN,
                    )
                } else {
                    (
                        format!("Backed up {}", age_description(data.last_backup, now)),
                        TEXT_DIM,
                    )
                };
                if color == WARN {
                    ui.label(RichText::new(icons::WARNING).color(WARN).size(13.0));
                }
                ui.label(RichText::new(text).color(color));
            });
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let resp = widgets::primary_button(
                ui,
                &format!("{}  New  {}", icons::PLUS, icons::CARET_DOWN),
            );
            egui::Popup::menu(&resp).show(|ui| {
                ui.set_min_width(180.0);
                for k in EntryKind::ALL {
                    if ui.button(icons::with(kind_icon(k), k.label())).clicked() {
                        acts.push(Act::Nav(Nav::New(Category::for_kind(k), k)));
                        ui.close();
                    }
                }
            });
            if widgets::secondary_button(ui, &icons::with(icons::FLOPPY_DISK, "Back up"))
                .on_hover_text("Save an encrypted copy of this vault")
                .clicked()
            {
                acts.push(Act::Backup);
            }
        });
    });
}

fn heading(ui: &mut egui::Ui, title: &str, link: Option<(&str, Nav)>) -> Option<Nav> {
    let mut clicked = None;
    ui.horizontal(|ui| {
        ui.label(strong(title, 14.5));
        if let Some((text, nav)) = link {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::link_button(ui, &format!("{text}  {}", icons::ARROW_RIGHT)).clicked() {
                    clicked = Some(nav);
                }
            });
        }
    });
    ui.add_space(4.0);
    clicked
}

fn search_box(ui: &mut egui::Ui, query: &mut String, count: usize) {
    Frame::new()
        .fill(INPUT)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(14, 9))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(icons::MAGNIFYING_GLASS)
                        .size(17.0)
                        .color(TEXT_FAINT),
                );
                let hint_w = 46.0;
                let resp = ui.add(
                    TextEdit::singleline(query)
                        .id(Id::new(SEARCH_ID))
                        .frame(false)
                        .font(FontId::proportional(15.5))
                        .hint_text(format!("Search {count} items"))
                        .desired_width(ui.available_width() - hint_w),
                );
                if resp.has_focus() && ui.input(|i| i.key_pressed(Key::Escape)) {
                    query.clear();
                }
                ui.label(faint("Ctrl+F"));
            });
        });
}

/// Body click is registered before the buttons so the buttons win where they
/// overlap (later widgets are on top in egui).
fn copy_buttons(
    ui: &mut egui::Ui,
    e: &Entry,
    right: f32,
    center_y: f32,
    acts: &mut Vec<Act>,
) -> f32 {
    let mut x = right;
    for (kind, icon, what, tip) in [
        (FieldKind::Password, icons::KEY, "Password", "Copy password"),
        (
            FieldKind::Username,
            icons::USER,
            "Username",
            "Copy username",
        ),
    ] {
        let value = e.first_of(kind).or_else(|| {
            (kind == FieldKind::Username)
                .then(|| e.first_of(FieldKind::Email))
                .flatten()
        });
        if let Some(v) = value {
            let r = Rect::from_center_size(
                egui::pos2(x - 14.0, center_y),
                Vec2::splat(widgets::ICON_BUTTON),
            );
            // A detached child Ui: unlike `ui.put`, it doesn't move the
            // parent's layout cursor.
            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(r));
            let b = child
                .add_sized(
                    r.size(),
                    Button::new(RichText::new(icon).size(15.0).color(TEXT_DIM))
                        .frame_when_inactive(false)
                        .corner_radius(6.0),
                )
                .on_hover_text(tip)
                .on_hover_cursor(CursorIcon::PointingHand);
            if b.clicked() {
                acts.push(Act::Copy(Zeroizing::new(v.to_string()), what));
            }
            x -= widgets::ICON_BUTTON + 4.0;
        }
    }
    x
}

fn favorites_grid(ui: &mut egui::Ui, favorites: &[&Entry], acts: &mut Vec<Act>) {
    const COLS: usize = 3;
    let gap = 10.0;
    const TILE_H: f32 = 58.0;
    let full = ui.available_width();
    let w = (full - gap * (COLS as f32 - 1.0)) / COLS as f32;
    let rows = favorites.len().div_ceil(COLS);
    // Allocate the whole grid once and place tiles at computed positions, so
    // the layout never squeezes or overlaps them.
    let height = rows as f32 * TILE_H + (rows.saturating_sub(1)) as f32 * gap;
    let (grid, _) = ui.allocate_exact_size(Vec2::new(full, height), Sense::hover());
    for (i, e) in favorites.iter().enumerate() {
        let (r, c) = (i / COLS, i % COLS);
        let min = grid.min + Vec2::new(c as f32 * (w + gap), r as f32 * (TILE_H + gap));
        favorite_tile(ui, e, Rect::from_min_size(min, Vec2::new(w, TILE_H)), acts);
    }
}

fn favorite_tile(ui: &mut egui::Ui, e: &Entry, rect: Rect, acts: &mut Vec<Act>) {
    let body = ui.interact(rect, Id::new(("fav_tile", e.id)), Sense::click());
    let hovered = ui.rect_contains_pointer(rect);
    let p = ui.painter();
    p.rect(
        rect,
        8.0,
        if hovered { SURFACE_2 } else { SURFACE },
        Stroke::new(1.0, BORDER),
        egui::StrokeKind::Inside,
    );
    let tile = Rect::from_center_size(rect.left_center() + Vec2::new(26.0, 0.0), Vec2::splat(32.0));
    p.rect_filled(tile, 7.0, INPUT);
    p.text(
        tile.center(),
        Align2::CENTER_CENTER,
        kind_icon(e.kind),
        FontId::proportional(17.0),
        ACCENT,
    );

    let text_right = copy_buttons(ui, e, rect.right() - 8.0, rect.center().y, acts);
    let clip = ui.painter_at(Rect::from_min_max(
        rect.min,
        egui::pos2(text_right - 4.0, rect.max.y),
    ));
    let x = tile.right() + 10.0;
    let sub = e.subtitle();
    let dy = if sub.is_empty() { 0.0 } else { 8.0 };
    clip.text(
        egui::pos2(x, rect.center().y - dy),
        Align2::LEFT_CENTER,
        e.display_title(),
        FontId::new(14.0, semibold()),
        TEXT,
    );
    if !sub.is_empty() {
        clip.text(
            egui::pos2(x, rect.center().y + 9.0),
            Align2::LEFT_CENTER,
            sub,
            FontId::proportional(12.0),
            TEXT_FAINT,
        );
    }
    if body.on_hover_cursor(CursorIcon::PointingHand).clicked() {
        acts.push(Act::Nav(Nav::Open(e.id)));
    }
}

fn item_row(ui: &mut egui::Ui, e: &Entry, detail: &str, acts: &mut Vec<Act>) {
    let (rect, body) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 44.0), Sense::click());
    let hovered = ui.rect_contains_pointer(rect);
    let p = ui.painter().clone();
    if hovered {
        p.rect_filled(rect, 6.0, SURFACE);
    }
    p.line_segment(
        [
            rect.left_bottom() + Vec2::new(46.0, 0.0),
            rect.right_bottom(),
        ],
        Stroke::new(1.0, egui::Color32::from_rgb(0x1f, 0x21, 0x24)),
    );
    let tile = Rect::from_center_size(rect.left_center() + Vec2::new(20.0, 0.0), Vec2::splat(28.0));
    widgets::kind_tile(ui, tile, kind_icon(e.kind));

    // Copy buttons only appear on hover to keep the list quiet.
    let mut right = rect.right() - 6.0;
    if hovered {
        right = copy_buttons(ui, e, right, rect.center().y, acts);
    }
    let detail_g = p.layout_no_wrap(detail.to_string(), FontId::proportional(12.0), TEXT_FAINT);
    let dw = detail_g.size().x;
    p.galley(
        egui::pos2(right - 6.0 - dw, rect.center().y - detail_g.size().y / 2.0),
        detail_g,
        TEXT_FAINT,
    );
    let clip = ui.painter_at(Rect::from_min_max(
        rect.min,
        egui::pos2(right - dw - 18.0, rect.max.y),
    ));
    let x = tile.right() + 12.0;
    let sub = e.subtitle();
    let dy = if sub.is_empty() { 0.0 } else { 8.0 };
    clip.text(
        egui::pos2(x, rect.center().y - dy),
        Align2::LEFT_CENTER,
        e.display_title(),
        FontId::proportional(14.0),
        TEXT,
    );
    if !sub.is_empty() {
        clip.text(
            egui::pos2(x, rect.center().y + 9.0),
            Align2::LEFT_CENTER,
            sub,
            FontId::proportional(12.0),
            TEXT_FAINT,
        );
    }
    if body.on_hover_cursor(CursorIcon::PointingHand).clicked() {
        acts.push(Act::Nav(Nav::Open(e.id)));
    }
}

fn health_strip(ui: &mut egui::Ui, h: &HealthReport) {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(16, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if h.total_passwords == 0 {
                ui.label(dim("No passwords stored yet."));
                return;
            }
            let weak: Vec<&PasswordRef> = h.weak.iter().map(|w| &w.at).collect();
            let reused_only = h
                .reused
                .iter()
                .flatten()
                .filter(|r| !weak.contains(r))
                .count();
            let total = h.total_passwords;
            let good = total.saturating_sub(weak.len() + reused_only);

            let (rect, _) =
                ui.allocate_exact_size(Vec2::new(ui.available_width(), 8.0), Sense::hover());
            let p = ui.painter();
            p.rect_filled(rect, 4.0, SURFACE_2);
            let mut x = rect.left();
            for (n, color) in [
                (good, ACCENT_FILL),
                (reused_only, WARN),
                (weak.len(), DANGER),
            ] {
                if n == 0 {
                    continue;
                }
                let seg_w = rect.width() * n as f32 / total as f32;
                let seg =
                    Rect::from_min_size(egui::pos2(x, rect.top()), Vec2::new(seg_w, rect.height()));
                p.rect_filled(seg.shrink2(Vec2::new(1.0, 0.0)), 4.0, color);
                x += seg_w;
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 16.0;
                for (n, label, color) in [
                    (good, "fine", ACCENT),
                    (weak.len(), "weak", DANGER),
                    (reused_only, "reused", WARN),
                    (h.old.len(), "older than a year", TEXT_DIM),
                ] {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 5.0;
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
                        ui.painter().circle_filled(
                            r.center(),
                            3.5,
                            if n > 0 { color } else { SURFACE_2 },
                        );
                        ui.label(RichText::new(n.to_string()).color(TEXT).family(semibold()));
                        ui.label(dim(label));
                    });
                }
            });
        });
}

fn empty_vault(ui: &mut egui::Ui, acts: &mut Vec<Act>) {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(28, 26))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(strong("Your vault is empty", 18.0));
            ui.label(dim(
                "Add your first item, or bring your passwords over from another app.",
            ));
            ui.add_space(16.0);
            let options: [(&str, &str, &str, Option<EntryKind>); 3] = [
                (
                    kind_icon(EntryKind::Login),
                    "Add a login",
                    "Website or app account",
                    Some(EntryKind::Login),
                ),
                (
                    icons::DOWNLOAD_SIMPLE,
                    "Import",
                    "CSV or JSON from Chrome, Bitwarden, 1Password…",
                    None,
                ),
                (
                    kind_icon(EntryKind::SecureNote),
                    "Write a secure note",
                    "Recovery codes, PINs, anything",
                    Some(EntryKind::SecureNote),
                ),
            ];
            ui.columns(3, |cols| {
                for (col, (icon, title, sub, kind)) in cols.iter_mut().zip(options) {
                    let (rect, resp) = col.allocate_exact_size(
                        Vec2::new(col.available_width(), 92.0),
                        Sense::click(),
                    );
                    let p = col.painter();
                    p.rect(
                        rect,
                        8.0,
                        if resp.hovered() { SURFACE_2 } else { BG },
                        Stroke::new(1.0, BORDER),
                        egui::StrokeKind::Inside,
                    );
                    p.text(
                        rect.left_top() + Vec2::new(14.0, 14.0),
                        Align2::LEFT_TOP,
                        icon,
                        FontId::proportional(20.0),
                        ACCENT,
                    );
                    p.text(
                        rect.left_top() + Vec2::new(14.0, 46.0),
                        Align2::LEFT_TOP,
                        title,
                        FontId::new(14.0, semibold()),
                        TEXT,
                    );
                    col.painter_at(rect.shrink(4.0)).text(
                        rect.left_top() + Vec2::new(14.0, 66.0),
                        Align2::LEFT_TOP,
                        sub,
                        FontId::proportional(12.0),
                        TEXT_FAINT,
                    );
                    if resp.on_hover_cursor(CursorIcon::PointingHand).clicked() {
                        acts.push(match kind {
                            Some(k) => Act::Nav(Nav::New(Category::for_kind(k), k)),
                            None => Act::Import,
                        });
                    }
                }
            });
        });
}
