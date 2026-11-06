//! Home.
//!
//! Layout, top to bottom:
//! 1. Search, drawn as an underlined line rather than a box, with "New item"
//!    beside it.
//! 2. Pinned items as letter tiles coloured by site, like a launcher: the
//!    page's one visual focal point, and the quickest way to an item.
//! 3. Password health as a single proportional bar (strong / fair / weak)
//!    with the counts and problems beneath it, plus the backup status.
//! 4. Recently used items as a table with column headings.
//!
//! An empty vault gets one getting-started panel instead.

use eframe::egui::{
    self, Align2, Button, Color32, CursorIcon, FontId, Id, Key, Modifiers, Rect, RichText, Sense,
    Stroke, TextEdit, Vec2,
};
use zeroize::Zeroizing;

use super::entries::Category;
use super::icons::{self, kind_icon};
use super::main_view::{MainState, Nav, Page};
use super::theme::*;
use super::widgets;
use super::{settings_page, Services};
use crate::autotype::url_host;
use crate::model::{Entry, EntryKind, FieldKind};
use crate::timeutil::{age_description, now_unix};
use crate::totp::{format_code, Totp};

const SEARCH_ID: &str = "vaultrust_home_search";
/// Backups older than this are flagged.
const STALE_BACKUP_DAYS: i64 = 30;
const ROW_H: f32 = 40.0;
const TILE_W: f32 = 116.0;
const TILE_H: f32 = 112.0;
const TILE_GAP: f32 = 8.0;
const SECTION_GAP: f32 = 30.0;
/// Readable content width on large windows.
const MAX_WIDTH: f32 = 1040.0;
/// Approximate height of the empty-vault welcome, for centring it.
const EMPTY_BLOCK_H: f32 = 400.0;

enum Act {
    Nav(Nav),
    Copy(Zeroizing<String>, &'static str, u64),
    Backup,
    Import,
    ScanQr,
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
            if ms.vault.data().entries.is_empty() {
                // A welcome in the middle of the page instead of an empty
                // dashboard.
                let free = ui.available_height() - EMPTY_BLOCK_H;
                ui.add_space((free * 0.42).max(24.0));
                widgets::centered_column(ui, 440.0, |ui| empty_vault(ui, &mut acts));
                return;
            }
            // Centred, and pushed down a little on tall windows, so a
            // maximised window doesn't leave everything in the top-left.
            let screen_h = ui.ctx().content_rect().height();
            ui.add_space(((screen_h - 820.0) / 6.0).clamp(4.0, 48.0));
            // Leave room for the scroll bar, which is drawn over the content.
            let width = MAX_WIDTH.min(ui.available_width() - 16.0);
            widgets::centered_column(ui, width, |ui| content(ui, ms, &mut acts));
        });

    for act in acts {
        match act {
            Act::Nav(n) => ms.request(n),
            Act::Copy(v, what, id) => ms.copy_from(svc, id, &v, what),
            Act::Backup => ms.start_backup(svc),
            Act::Import => settings_page::start_import(ms, svc),
            Act::ScanQr => ms.qr_requested = true,
        }
    }
}

fn content(ui: &mut egui::Ui, ms: &mut MainState, acts: &mut Vec<Act>) {
    let count = ms.vault.data().entries.len();
    top_bar(ui, &mut ms.home_query, count, acts);
    ui.add_space(SECTION_GAP);

    let q = ms.home_query.trim().to_lowercase();
    if !q.is_empty() {
        search_results(ui, ms, &q, acts);
        return;
    }

    let now = now_unix();
    pinned(ui, ms, now, acts);
    ui.add_space(SECTION_GAP);
    health(ui, ms, now, acts);
    ui.add_space(SECTION_GAP);
    recent(ui, ms, now, acts);
    ui.add_space(16.0);
}

fn new_item_button(ui: &mut egui::Ui, acts: &mut Vec<Act>) {
    let resp = widgets::primary_button(
        ui,
        &format!("{}  New item  {}", icons::PLUS, icons::CARET_DOWN),
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
}

/// Underlined search line with "New item" on the right.
fn top_bar(ui: &mut egui::Ui, query: &mut String, count: usize, acts: &mut Vec<Act>) {
    let focused = ui.memory(|m| m.has_focus(Id::new(SEARCH_ID)));
    let row = widgets::trailing_row_h(
        ui,
        40.0,
        egui::Align::Center,
        |ui| {
            new_item_button(ui, acts);
            ui.add_space(4.0);
            if widgets::secondary_button(ui, &icons::with(icons::QR_CODE, "Scan 2FA code"))
                .on_hover_text(
                    "Setting up two-step verification? Show the site's QR code on screen and \
                     VaultRust adds the code to the matching login",
                )
                .clicked()
            {
                acts.push(Act::ScanQr);
            }
            ui.add_space(20.0);
        },
        |ui| {
            ui.horizontal_centered(|ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                ui.label(
                    RichText::new(icons::MAGNIFYING_GLASS)
                        .size(19.0)
                        .color(if focused { accent() } else { text_faint() }),
                );
                let hint_w = 64.0;
                let resp = ui.add(
                    TextEdit::singleline(query)
                        .id(Id::new(SEARCH_ID))
                        .frame(false)
                        .font(FontId::proportional(18.0))
                        .hint_text(hint(format!("Search {count} items")))
                        .desired_width(ui.available_width() - hint_w),
                );
                if resp.has_focus() && ui.input(|i| i.key_pressed(Key::Escape)) {
                    query.clear();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(faint("Ctrl+K"));
                });
            });
            ui.min_rect()
        },
    );
    let (stroke_w, color) = if focused {
        (2.0, accent())
    } else {
        (1.0_f32, border())
    };
    ui.painter().hline(
        row.x_range(),
        row.bottom() + 6.0,
        Stroke::new(stroke_w, color),
    );
    ui.add_space(6.0);
}

fn section_title(ui: &mut egui::Ui, title: &str, extra: impl FnOnce(&mut egui::Ui)) {
    widgets::trailing_row_h(ui, 20.0, egui::Align::Center, extra, |ui| {
        ui.horizontal_centered(|ui| {
            ui.label(section_label(&title.to_uppercase()));
        });
    });
    ui.add_space(8.0);
}

/// A link sized to sit on a section heading's line.
fn small_link(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let resp = ui
        .add(
            egui::Label::new(RichText::new(text).size(12.5).color(text_dim()))
                .sense(Sense::click()),
        )
        .on_hover_cursor(CursorIcon::PointingHand);
    if resp.hovered() {
        ui.painter().hline(
            resp.rect.x_range(),
            resp.rect.bottom(),
            Stroke::new(1.0_f32, text_dim()),
        );
    }
    resp
}

// ---------------------------------------------------------------- pinned

fn pinned(ui: &mut egui::Ui, ms: &MainState, now: i64, acts: &mut Vec<Act>) {
    let data = ms.vault.data();
    let mut items: Vec<&Entry> = data.entries.iter().filter(|e| e.favorite).collect();
    items.sort_by_key(|e| e.title.to_lowercase());

    section_title(ui, "Pinned", |ui| {
        if !items.is_empty() && small_link(ui, "Favorites").clicked() {
            acts.push(Act::Nav(Nav::Page(Page::Items(Category::Favorites))));
        }
    });
    if items.is_empty() {
        ui.label(dim(format!(
            "Star items you use often ({}) and they appear here.",
            icons::STAR
        )));
        return;
    }

    let width = ui.available_width();
    let per_row = (((width + TILE_GAP) / (TILE_W + TILE_GAP)).floor() as usize).max(1);
    for chunk in items.chunks(per_row).take(2) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = TILE_GAP;
            for e in chunk {
                tile(ui, e, now, acts);
            }
        });
        ui.add_space(TILE_GAP - ui.spacing().item_spacing.y);
    }
}

fn truncated(
    p: &egui::Painter,
    text: String,
    font: FontId,
    color: Color32,
    max_w: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::simple_singleline(text, font, color);
    job.wrap = egui::text::TextWrapping::truncate_at_width(max_w);
    p.layout_job(job)
}

/// A launcher tile: letter tile, title, and the username (or the live
/// one-time code). Hovering swaps the last line for copy buttons.
fn tile(ui: &mut egui::Ui, e: &Entry, now: i64, acts: &mut Vec<Act>) {
    let (rect, body) = ui.allocate_exact_size(Vec2::new(TILE_W, TILE_H), Sense::click());
    let hovered = ui.rect_contains_pointer(rect);
    let p = ui.painter().clone();
    if hovered {
        p.rect_filled(rect, RADIUS, surface());
    }
    let mono = Rect::from_center_size(
        egui::pos2(rect.center().x, rect.top() + 34.0),
        Vec2::splat(44.0),
    );
    widgets::entry_tile(ui, mono, e);

    let inner_w = TILE_W - 16.0;
    let title = truncated(
        &p,
        e.display_title().to_string(),
        FontId::proportional(13.5),
        text(),
        inner_w,
    );
    p.galley(
        egui::pos2(rect.center().x - title.size().x / 2.0, rect.top() + 66.0),
        title,
        text(),
    );

    let line_y = rect.top() + 92.0;
    if hovered {
        let buttons = copy_targets(e, now);
        let w = buttons.len() as f32 * (widgets::ICON_BUTTON + 2.0) - 2.0;
        let mut x = rect.center().x + w / 2.0;
        for (label, tip, value, what) in buttons.into_iter().rev() {
            let r = Rect::from_min_size(
                egui::pos2(
                    x - widgets::ICON_BUTTON,
                    line_y - widgets::ICON_BUTTON / 2.0,
                ),
                Vec2::splat(widgets::ICON_BUTTON),
            );
            if overlay_button(
                ui,
                r,
                RichText::new(label).size(15.0).color(text_dim()),
                &tip,
            ) {
                acts.push(Act::Copy(value, what, e.id));
            }
            x -= widgets::ICON_BUTTON + 2.0;
        }
    } else {
        let (line, mono_font) = match e.totp_secret().and_then(|s| Totp::parse(s).ok()) {
            Some(t) => (format_code(&t.code_at(now)), true),
            None => (e.subtitle(), false),
        };
        let font = if mono_font {
            FontId::monospace(12.5)
        } else {
            FontId::proportional(12.0)
        };
        let g = truncated(&p, line, font, text_faint(), inner_w);
        p.galley(
            egui::pos2(
                rect.center().x - g.size().x / 2.0,
                line_y - g.size().y / 2.0,
            ),
            g,
            text_faint(),
        );
    }
    if body.on_hover_cursor(CursorIcon::PointingHand).clicked() {
        acts.push(Act::Nav(Nav::Open(e.id)));
    }
}

/// What can be copied from an entry: (icon or code, tooltip, value, name).
fn copy_targets(e: &Entry, now: i64) -> Vec<(String, String, Zeroizing<String>, &'static str)> {
    let mut out = Vec::new();
    if let Some(v) = e
        .first_of(FieldKind::Username)
        .or_else(|| e.first_of(FieldKind::Email))
    {
        out.push((
            icons::USER.to_string(),
            "Copy username".to_string(),
            Zeroizing::new(v.to_string()),
            "Username",
        ));
    }
    if let Some(v) = e.first_of(FieldKind::Password) {
        out.push((
            icons::PASSWORD.to_string(),
            "Copy password".to_string(),
            Zeroizing::new(v.to_string()),
            "Password",
        ));
    }
    if let Some(t) = e.totp_secret().and_then(|s| Totp::parse(s).ok()) {
        out.push((
            icons::CLOCK_COUNTDOWN.to_string(),
            format!("Copy one-time code · {}s left", t.remaining_at(now)),
            Zeroizing::new(t.code_at(now)),
            "One-time code",
        ));
    }
    out
}

/// A button placed at an exact rect without moving the layout cursor. Must
/// be added after the row's own click area so it wins where they overlap.
fn overlay_button(ui: &mut egui::Ui, r: Rect, label: RichText, tip: &str) -> bool {
    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(r));
    child
        .add_sized(
            r.size(),
            Button::new(label)
                .frame_when_inactive(false)
                .corner_radius(RADIUS_SM),
        )
        .on_hover_text(tip)
        .on_hover_cursor(CursorIcon::PointingHand)
        .clicked()
}

// ---------------------------------------------------------------- health

fn health(ui: &mut egui::Ui, ms: &MainState, now: i64, acts: &mut Vec<Act>) {
    let h = &ms.health;
    let data = ms.vault.data();

    section_title(ui, "Password health", |ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        let stale = data.last_backup == 0 || now - data.last_backup > STALE_BACKUP_DAYS * 86_400;
        if small_link(ui, if stale { "Back up now" } else { "Back up" })
            .on_hover_text("Save a verified, encrypted copy of this vault")
            .clicked()
        {
            acts.push(Act::Backup);
        }
        let status = if data.last_backup == 0 {
            "Never backed up".to_string()
        } else {
            format!("Backed up {}", age_description(data.last_backup, now))
        };
        ui.label(
            RichText::new(status)
                .size(12.5)
                .color(if stale { warn() } else { text_faint() }),
        );
    });

    if h.total_passwords == 0 {
        ui.label(dim("No passwords yet."));
        return;
    }

    // The bar: one segment per strength band, widths proportional to counts.
    let (bar, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 10.0), Sense::hover());
    let p = ui.painter();
    p.rect_filled(bar, 5.0, rail());
    let total = h.total_passwords as f32;
    let bands = [
        (h.strong(), accent_fill()),
        (h.fair, warn()),
        (h.weak.len(), danger()),
    ];
    let mut x = bar.left();
    let shown = bands.iter().filter(|(n, _)| *n > 0).count();
    let gaps = 3.0 * shown.saturating_sub(1) as f32;
    let mut drawn = 0;
    for (n, color) in bands {
        if n == 0 {
            continue;
        }
        drawn += 1;
        let w = if drawn == shown {
            bar.right() - x
        } else {
            ((bar.width() - gaps) * n as f32 / total).max(4.0)
        };
        let seg = Rect::from_min_size(egui::pos2(x, bar.top()), Vec2::new(w, bar.height()));
        p.rect_filled(seg, 5.0, color);
        x += w + 3.0;
    }
    ui.add_space(10.0);

    let security = || Act::Nav(Nav::Page(Page::Security));
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 18.0;
        legend(ui, Some(accent_fill()), h.strong(), "strong", None);
        legend(ui, Some(warn()), h.fair, "fair", None);
        if legend(
            ui,
            Some(danger()),
            h.weak.len(),
            "weak",
            (!h.weak.is_empty()).then_some("Review weak passwords"),
        ) {
            acts.push(security());
        }

        let mut problems: Vec<(usize, &str, Color32)> = vec![
            (h.reused_count(), "reused", warn()),
            (h.expired.len(), "expired", danger()),
            (h.expiring.len(), "expiring soon", warn()),
            (h.old.len(), "over a year old", text_dim()),
        ];
        if let Some(b) = &ms.breach.report {
            problems.insert(0, (b.hits.len(), "in data breaches", danger()));
        }
        problems.retain(|(n, _, _)| *n > 0);

        let (r, _) = ui.allocate_exact_size(Vec2::new(1.0, 16.0), Sense::hover());
        ui.painter()
            .vline(r.center().x, r.y_range(), Stroke::new(1.0_f32, divider()));

        if problems.is_empty() && h.weak.is_empty() {
            ui.label(
                RichText::new(icons::with(icons::CHECK, "No reused or breached passwords"))
                    .size(13.0)
                    .color(text_dim()),
            );
        }
        for (n, label, color) in problems {
            if issue(ui, n, label, color) {
                acts.push(security());
            }
        }
    });

    if let Some(err) = ms.breach.report.as_ref().and_then(|b| b.error.as_ref()) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(icons::with(icons::WARNING, err))
                    .size(12.5)
                    .color(warn()),
            );
            if widgets::link_button(ui, "Settings").clicked() {
                acts.push(Act::Nav(Nav::Page(Page::Settings)));
            }
        });
    }
}

/// "■ 12 strong" under the bar; clickable when `tip` is set.
fn legend(
    ui: &mut egui::Ui,
    swatch: Option<Color32>,
    n: usize,
    label: &str,
    tip: Option<&str>,
) -> bool {
    let resp = ui
        .horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            if let Some(c) = swatch {
                let (r, _) = ui.allocate_exact_size(Vec2::new(8.0, 14.0), Sense::hover());
                ui.painter().rect_filled(
                    Rect::from_center_size(r.center(), Vec2::splat(8.0)),
                    2.0,
                    c,
                );
            }
            ui.label(
                RichText::new(n.to_string())
                    .family(semibold())
                    .size(13.5)
                    .color(text()),
            );
            ui.label(RichText::new(label).size(13.0).color(text_dim()));
        })
        .response;
    clickable(ui, resp, tip)
}

/// "2 reused" with the number in the problem's colour; opens Security.
fn issue(ui: &mut egui::Ui, n: usize, label: &str, color: Color32) -> bool {
    let resp = ui
        .horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            ui.label(
                RichText::new(n.to_string())
                    .family(semibold())
                    .size(13.5)
                    .color(color),
            );
            ui.label(RichText::new(label).size(13.0).color(text_dim()));
        })
        .response;
    clickable(ui, resp, Some("Review in Security"))
}

fn clickable(ui: &egui::Ui, resp: egui::Response, tip: Option<&str>) -> bool {
    let Some(tip) = tip else { return false };
    let resp = resp
        .interact(Sense::click())
        .on_hover_text(tip)
        .on_hover_cursor(CursorIcon::PointingHand);
    if resp.hovered() {
        ui.painter().hline(
            resp.rect.x_range(),
            resp.rect.bottom() + 1.0,
            Stroke::new(1.0_f32, text_faint()),
        );
    }
    resp.clicked()
}

// ---------------------------------------------------------------- table

/// Column layout for the item table.
struct Columns {
    user: f32,
    site: Option<f32>,
}

impl Columns {
    fn new(width: f32) -> Self {
        Self {
            user: width * 0.42,
            site: (width >= 620.0).then_some(width * 0.69),
        }
    }
}

fn table_header(ui: &mut egui::Ui, title: &str, last: &str) {
    let width = ui.available_width();
    let cols = Columns::new(width);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 20.0), Sense::hover());
    let p = ui.painter();
    let label = |x: f32, text: &str, align: Align2| {
        p.text(
            egui::pos2(x, rect.center().y),
            align,
            text.to_uppercase(),
            FontId::new(11.5, semibold()),
            text_faint(),
        );
    };
    label(rect.left(), title, Align2::LEFT_CENTER);
    label(rect.left() + cols.user, "Username", Align2::LEFT_CENTER);
    if let Some(site) = cols.site {
        label(rect.left() + site, "Website", Align2::LEFT_CENTER);
    }
    label(rect.right() - 8.0, last, Align2::RIGHT_CENTER);
    ui.add_space(4.0);
    let y = ui.cursor().top();
    ui.painter()
        .hline(rect.x_range(), y, Stroke::new(1.0_f32, border()));
}

fn table_row(ui: &mut egui::Ui, e: &Entry, last: &str, now: i64, acts: &mut Vec<Act>) {
    let width = ui.available_width();
    let cols = Columns::new(width);
    let (rect, body) = ui.allocate_exact_size(Vec2::new(width, ROW_H), Sense::click());
    let hovered = ui.rect_contains_pointer(rect);
    let p = ui.painter().clone();
    if hovered {
        p.rect_filled(rect, RADIUS_SM, row_hover());
    }
    p.hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0_f32, divider()),
    );
    let cy = rect.center().y;

    let mono = Rect::from_center_size(egui::pos2(rect.left() + 18.0, cy), Vec2::splat(26.0));
    widgets::entry_tile(ui, mono, e);

    let cell = |x0: f32, x1: f32, text: String, size: f32, color: Color32| {
        if text.is_empty() {
            return;
        }
        let g = truncated(
            &p,
            text,
            FontId::proportional(size),
            color,
            (x1 - x0 - 12.0).max(0.0),
        );
        p.galley(egui::pos2(x0, cy - g.size().y / 2.0), g, color);
    };
    let user_x = rect.left() + cols.user;
    let site_x = cols.site.map(|s| rect.left() + s);
    cell(
        rect.left() + 42.0,
        user_x,
        e.display_title().to_string(),
        14.0,
        text(),
    );
    let user_end = site_x.unwrap_or(rect.right() - 110.0);
    cell(user_x, user_end, e.subtitle(), 13.0, text_dim());

    if hovered {
        let targets = copy_targets(e, now);
        let mut x = rect.right() - 6.0;
        for (label, tip, value, what) in targets.into_iter().rev() {
            let r = Rect::from_min_size(
                egui::pos2(x - widgets::ICON_BUTTON, cy - widgets::ICON_BUTTON / 2.0),
                Vec2::splat(widgets::ICON_BUTTON),
            );
            if overlay_button(
                ui,
                r,
                RichText::new(label).size(15.0).color(text_dim()),
                &tip,
            ) {
                acts.push(Act::Copy(value, what, e.id));
            }
            x -= widgets::ICON_BUTTON + 2.0;
        }
        if let Some(sx) = site_x {
            cell(sx, x, site_label(e), 13.0, text_faint());
        }
    } else {
        let g = p.layout_no_wrap(last.to_string(), FontId::proportional(12.5), text_faint());
        let lw = g.size().x;
        p.galley(
            egui::pos2(rect.right() - 8.0 - lw, cy - g.size().y / 2.0),
            g,
            text_faint(),
        );
        if let Some(sx) = site_x {
            cell(
                sx,
                rect.right() - 8.0 - lw - 8.0,
                site_label(e),
                13.0,
                text_faint(),
            );
        }
    }
    if body.on_hover_cursor(CursorIcon::PointingHand).clicked() {
        acts.push(Act::Nav(Nav::Open(e.id)));
    }
}

fn site_label(e: &Entry) -> String {
    e.first_of(FieldKind::Url).map(url_host).unwrap_or_default()
}

fn recent(ui: &mut egui::Ui, ms: &MainState, now: i64, acts: &mut Vec<Act>) {
    let data = ms.vault.data();
    let mut used: Vec<&Entry> = data.entries.iter().filter(|e| e.last_used > 0).collect();
    let (title, last, items): (&str, &str, Vec<&Entry>) = if used.is_empty() {
        let mut edited: Vec<&Entry> = data.entries.iter().collect();
        edited.sort_by_key(|e| std::cmp::Reverse(e.modified));
        ("Recently edited", "Edited", edited)
    } else {
        used.sort_by_key(|e| std::cmp::Reverse(e.last_used));
        ("Recently used", "Used", used)
    };
    table_header(ui, title, last);
    // More rows on taller windows.
    let rows = ((ui.ctx().content_rect().height() - 560.0) / ROW_H).clamp(5.0, 15.0) as usize;
    for e in items.iter().take(rows) {
        let at = if e.last_used > 0 {
            e.last_used
        } else {
            e.modified
        };
        table_row(ui, e, &age_description(at, now), now, acts);
    }
    ui.add_space(10.0);
    if widgets::link_button(ui, &format!("Show all {} items", data.entries.len())).clicked() {
        acts.push(Act::Nav(Nav::Page(Page::Items(Category::All))));
    }
}

fn search_results(ui: &mut egui::Ui, ms: &MainState, q: &str, acts: &mut Vec<Act>) {
    let data = ms.vault.data();
    let mut hits: Vec<(i32, &Entry)> = data
        .entries
        .iter()
        .filter_map(|e| e.search_score(q).map(|s| (s, e)))
        .collect();
    hits.sort_by(|(sa, a), (sb, b)| {
        sb.cmp(sa)
            .then_with(|| b.favorite.cmp(&a.favorite))
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });
    if ui.input(|i| i.key_pressed(Key::Enter)) {
        if let Some((_, first)) = hits.first() {
            acts.push(Act::Nav(Nav::Open(first.id)));
        }
    }
    if hits.is_empty() {
        ui.label(dim(
            "Nothing matches. Search covers titles, tags, usernames, emails and websites — never passwords.",
        ));
        return;
    }
    let title = format!(
        "{} result{}  ·  Enter opens the first",
        hits.len(),
        if hits.len() == 1 { "" } else { "s" }
    );
    table_header(ui, &title, "Type");
    let now = now_unix();
    for (_, e) in hits.iter().take(25) {
        table_row(ui, e, e.kind.label(), now, acts);
    }
}

/// First run: what the vault is for and the three ways to fill it.
fn empty_vault(ui: &mut egui::Ui, acts: &mut Vec<Act>) {
    ui.vertical_centered(|ui| {
        let (tile, _) = ui.allocate_exact_size(Vec2::splat(64.0), Sense::hover());
        let p = ui.painter();
        p.rect_filled(tile, 16.0, accent_bg());
        p.text(
            tile.center(),
            Align2::CENTER_CENTER,
            icons::VAULT,
            FontId::proportional(32.0),
            accent(),
        );
        ui.add_space(18.0);
        ui.label(strong("Your vault is empty", 22.0));
        ui.add_space(4.0);
        ui.label(dim(
            "Everything you save here is encrypted on this computer. Start with a login, \
             or bring your passwords over from your browser.",
        ));
        ui.add_space(22.0);
    });
    if widgets::primary_button_wide(
        ui,
        &icons::with(kind_icon(EntryKind::Login), "Add a login"),
        true,
    )
    .clicked()
    {
        acts.push(Act::Nav(Nav::New(Category::Logins, EntryKind::Login)));
    }
    ui.add_space(4.0);
    if widgets::secondary_button_wide(
        ui,
        &icons::with(icons::DOWNLOAD_SIMPLE, "Import from a browser or password manager…"),
    )
    .on_hover_text("Chrome, Edge, Firefox, Bitwarden, 1Password, LastPass or KeePass — read entirely on this computer")
    .clicked()
    {
        acts.push(Act::Import);
    }
    ui.add_space(4.0);
    if widgets::secondary_button_wide(
        ui,
        &icons::with(icons::QR_CODE, "Scan a two-step (2FA) QR code"),
    )
    .on_hover_text("Show a site's 2FA setup QR code on screen and VaultRust reads it")
    .clicked()
    {
        acts.push(Act::ScanQr);
    }
    ui.add_space(20.0);
    ui.vertical_centered(|ui| ui.label(faint("Or add something else")));
    ui.add_space(2.0);
    let others = [
        (EntryKind::CreditCard, "Card"),
        (EntryKind::SecureNote, "Note"),
        (EntryKind::Identity, "Identity"),
        (EntryKind::ApiKey, "API key"),
        (EntryKind::Wifi, "Wi-Fi"),
    ];
    let labels: Vec<&str> = others.iter().map(|(_, l)| *l).collect();
    if let Some(i) = widgets::centered_links(ui, &labels) {
        let k = others[i].0;
        acts.push(Act::Nav(Nav::New(Category::for_kind(k), k)));
    }
}
