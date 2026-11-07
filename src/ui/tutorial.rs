//! The welcome tour: a few steps shown once, after the first vault is
//! opened, covering what isn't obvious from the screens themselves (auto-type,
//! the QR scanner, quick open, clipboard clearing, locking).
//!
//! The screen is dimmed except for a spotlight on the button a step is
//! about, with a card beside it. Between steps the spotlight and the card
//! glide to the next button; steps about something without a button (the
//! welcome, auto-type) shrink the spotlight away and centre the card.
//! Screens mark the buttons the tour can point at with [`mark`].

use eframe::egui::{
    self, epaint, pos2, vec2, Align2, Color32, FontId, Id, Key, Order, Pos2, Rect, RichText, Sense,
    Shape, Stroke, StrokeKind, Vec2,
};

use super::icons;
use super::theme::*;
use super::widgets;
use crate::i18n::tr;
use crate::os_protect::{AUTO_TYPE_HOTKEY, QUICK_OPEN_HOTKEY};
use crate::trf;

/// Something on screen a step can point at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Spot {
    Search,
    NewItem,
    ScanQr,
    Security,
    Lock,
    Settings,
}

/// Note where `spot` is drawn this frame, for the tour to point at.
pub fn mark(ui: &egui::Ui, spot: Spot, rect: Rect) {
    let pass = ui.ctx().cumulative_pass_nr();
    ui.ctx()
        .data_mut(|d| d.insert_temp(Id::new(("tour_spot", spot)), (rect, pass)));
}

/// Where `spot` was drawn, if it was drawn this frame or the last.
fn spot_rect(ctx: &egui::Context, spot: Spot) -> Option<Rect> {
    let pass = ctx.cumulative_pass_nr();
    ctx.data(|d| d.get_temp::<(Rect, u64)>(Id::new(("tour_spot", spot))))
        .filter(|(_, at)| *at + 1 >= pass)
        .map(|(r, _)| r)
}

struct Step {
    icon: &'static str,
    title: &'static str,
    text: String,
    tips: Vec<(&'static str, String)>,
    spot: Option<Spot>,
}

fn steps() -> Vec<Step> {
    vec![
        Step {
            icon: icons::VAULT,
            title: tr("Welcome to VaultRust"),
            text: tr("Your passwords are kept in one encrypted file on this computer. Nothing is uploaded anywhere.")
                .into(),
            tips: vec![(
                icons::KEY,
                tr("Your master password unlocks everything. Nobody can reset it, so keep it somewhere you won't lose it.")
                    .into(),
            )],
            spot: None,
        },
        Step {
            icon: icons::PLUS_CIRCLE,
            title: tr("Save your logins"),
            text: tr("Click New item → Login and fill in the website, username and password.").into(),
            tips: vec![
                (icons::DICE_FIVE, tr("The dice button makes a strong password for you.").into()),
                (
                    icons::DOWNLOAD_SIMPLE,
                    tr("Coming from Chrome, Edge or another password manager? Import brings everything over.")
                        .into(),
                ),
            ],
            spot: Some(Spot::NewItem),
        },
        Step {
            icon: icons::COPY,
            title: tr("Use a password"),
            text: tr("Open an item, or hover it on the Overview, and click the copy button next to the username or password.")
                .into(),
            tips: vec![
                (
                    icons::MAGNIFYING_GLASS,
                    trf!("Ctrl+K searches the vault. {QUICK_OPEN_HOTKEY} opens the search from any app.", QUICK_OPEN_HOTKEY),
                ),
                (
                    icons::CLOCK_COUNTDOWN,
                    tr("Copied passwords are wiped from the clipboard after 30 seconds.").into(),
                ),
            ],
            spot: Some(Spot::Search),
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
            spot: None,
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
            spot: Some(Spot::ScanQr),
        },
        Step {
            icon: icons::SHIELD_CHECK,
            title: tr("Stay safe"),
            text: tr("VaultRust keeps an eye on things for you.").into(),
            tips: vec![(
                icons::WARNING,
                tr("The Security page lists weak, reused and old passwords.").into(),
            )],
            spot: Some(Spot::Security),
        },
        Step {
            icon: icons::LOCK,
            title: tr("Lock when you step away"),
            text: tr("Click Lock vault or press Ctrl+L.").into(),
            tips: vec![(
                icons::TIMER,
                tr("The vault locks itself after a few idle minutes and when Windows locks.").into(),
            )],
            spot: Some(Spot::Lock),
        },
        Step {
            icon: icons::GEAR_SIX,
            title: tr("Make it yours"),
            text: tr("Settings is where you set up quick unlock, backups and the browser extension.").into(),
            tips: vec![
                (
                    icons::FINGERPRINT,
                    tr("Turn on Windows Hello in Settings to unlock with your face, fingerprint or PIN.")
                        .into(),
                ),
                (
                    icons::BROWSER,
                    tr("The browser extension fills in logins, cards and addresses in Chrome, Edge, Brave and Firefox.")
                        .into(),
                ),
                (
                    icons::FLOPPY_DISK,
                    tr("Use Back up now and then to keep a copy on a USB stick or another drive.").into(),
                ),
            ],
            spot: Some(Spot::Settings),
        },
    ]
}

/// Width of the card's content.
const CARD_W: f32 = 340.0;
/// Space between the spotlight and the card, and the screen's edge.
const GAP: f32 = 18.0;
/// Room around a highlighted button.
const PAD: f32 = 6.0;
/// How quickly the spotlight and card glide (higher is faster).
const GLIDE: f32 = 11.0;

/// Where the tour is, and where its spotlight and card are drawn now.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Tour {
    pub step: usize,
    hole: Option<Rect>,
    card: Option<Pos2>,
    /// When the tour started and when the step last changed (`ctx` time).
    started: Option<f64>,
    changed: Option<(usize, f64)>,
}

impl Tour {
    /// The tour, starting at `step`.
    #[cfg(test)]
    pub fn at(step: usize) -> Self {
        Tour {
            step,
            ..Default::default()
        }
    }
}

/// `from` moved a share `k` of the way to `to`.
fn glide_rect(from: Rect, to: Rect, k: f32) -> Rect {
    Rect::from_min_max(from.min.lerp(to.min, k), from.max.lerp(to.max, k))
}

/// Dim `screen` except for a rounded `hole`.
fn dim_around(p: &egui::Painter, screen: Rect, hole: Rect, radius: f32, color: Color32) {
    if hole.width() < 1.0 || hole.height() < 1.0 {
        p.rect_filled(screen, 0.0, color);
        return;
    }
    let (s, h) = (screen, hole);
    for r in [
        Rect::from_min_max(s.min, pos2(s.max.x, h.min.y)),
        Rect::from_min_max(pos2(s.min.x, h.max.y), s.max),
        Rect::from_min_max(pos2(s.min.x, h.min.y), pos2(h.min.x, h.max.y)),
        Rect::from_min_max(pos2(h.max.x, h.min.y), pos2(s.max.x, h.max.y)),
    ] {
        if r.is_positive() {
            p.rect_filled(r, 0.0, color);
        }
    }
    // Fill the hole's corners outside its rounding.
    let r = radius.min(h.width() / 2.0).min(h.height() / 2.0);
    let quarter = std::f32::consts::FRAC_PI_2;
    let corners = [
        (h.left_top(), h.left_top() + vec2(r, r), 2.0),
        (h.right_top(), h.right_top() + vec2(-r, r), 3.0),
        (h.right_bottom(), h.right_bottom() + vec2(-r, -r), 0.0),
        (h.left_bottom(), h.left_bottom() + vec2(r, -r), 1.0),
    ];
    let mut mesh = epaint::Mesh::default();
    for (corner, center, start) in corners {
        let base = mesh.vertices.len() as u32;
        mesh.colored_vertex(corner, color);
        const N: u32 = 8;
        for i in 0..=N {
            let a = (start + i as f32 / N as f32) * quarter;
            mesh.colored_vertex(center + r * vec2(a.cos(), a.sin()), color);
        }
        for i in 1..=N {
            mesh.add_triangle(base, base + i, base + i + 1);
        }
    }
    p.add(Shape::mesh(mesh));
}

/// Where the card goes for a highlighted `target`: beside it if it is on
/// the left (the sidebar), otherwise below it, or above if there is no room.
/// Also returns which side of the card faces the target.
fn place_card(screen: Rect, target: Rect, size: Vec2) -> (Pos2, Align2) {
    let clamp_y = |y: f32| y.clamp(screen.top() + GAP, screen.bottom() - GAP - size.y);
    let clamp_x = |x: f32| x.clamp(screen.left() + GAP, screen.right() - GAP - size.x);
    if target.center().x < screen.left() + screen.width() * 0.3 {
        let y = clamp_y(target.center().y - size.y / 2.0);
        return (pos2(target.right() + GAP, y), Align2::LEFT_CENTER);
    }
    let x = clamp_x(target.center().x - size.x / 2.0);
    if target.bottom() + GAP + size.y <= screen.bottom() - GAP {
        (pos2(x, target.bottom() + GAP), Align2::CENTER_TOP)
    } else {
        (pos2(x, target.top() - GAP - size.y), Align2::CENTER_BOTTOM)
    }
}

/// Draw the tour. Returns true once it is finished or skipped.
pub fn show(ctx: &egui::Context, tour: &mut Tour) -> bool {
    let steps = steps();
    let last = steps.len() - 1;
    tour.step = tour.step.min(last);
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

    let now = ctx.input(|i| i.time);
    let animate = !cfg!(test);
    let started = *tour.started.get_or_insert(now);
    if tour.changed.is_none_or(|(s, _)| s != tour.step) {
        tour.changed = Some((tour.step, now));
    }
    let since_change = tour.changed.map_or(1.0, |(_, t)| now - t) as f32;
    let fade = if animate {
        ((now - started) as f32 / 0.3).min(1.0)
    } else {
        1.0
    };
    let k = if animate {
        1.0 - (-ctx.input(|i| i.stable_dt).min(0.1) * GLIDE).exp()
    } else {
        1.0
    };

    let screen = ctx.content_rect();
    let card_id = Id::new("vaultrust_tour_card");
    let card_size = ctx
        .memory(|m| m.area_rect(card_id))
        .map_or(vec2(CARD_W + 40.0, 300.0), |r| r.size());
    let target = step
        .spot
        .and_then(|s| spot_rect(ctx, s))
        .filter(|r| screen.intersects(*r))
        .map(|r| r.expand(PAD));
    let (want_hole, want_card, facing) = match target {
        Some(t) => {
            let (pos, facing) = place_card(screen, t, card_size);
            (t, pos, Some(facing))
        }
        // Nothing to point at: the spotlight closes in the middle.
        None => (
            Rect::from_center_size(screen.center(), Vec2::ZERO),
            screen.center() - card_size / 2.0,
            None,
        ),
    };
    let hole = glide_rect(tour.hole.unwrap_or(want_hole), want_hole, k);
    let card = tour.card.unwrap_or(want_card).lerp(want_card, k);
    let moving = (hole.min - want_hole.min).length() + (hole.max - want_hole.max).length() > 0.5
        || (card - want_card).length() > 0.5;
    tour.hole = Some(if moving { hole } else { want_hole });
    tour.card = Some(if moving { card } else { want_card });
    if animate && (moving || fade < 1.0 || since_change < 0.3 || target.is_some()) {
        ctx.request_repaint();
    }

    // The dimmed screen, which also keeps clicks off the app underneath.
    egui::Area::new(Id::new("vaultrust_tour_dim"))
        .order(Order::Foreground)
        .fixed_pos(screen.min)
        .show(ctx, |ui| {
            ui.allocate_rect(screen, Sense::click_and_drag());
            let p = ui.painter();
            let alpha = if is_dark() { 165.0 } else { 120.0 };
            let dim = Color32::from_black_alpha((alpha * fade) as u8);
            let radius = 10.0;
            dim_around(p, screen, hole, radius, dim);
            if hole.width() >= 1.0 {
                p.rect_stroke(
                    hole,
                    radius,
                    Stroke::new(2.0_f32, accent().gamma_multiply(fade)),
                    StrokeKind::Outside,
                );
                // A ring that keeps rippling outwards.
                if animate && !moving {
                    let t = (now % 1.6) as f32 / 1.6;
                    let grow = t * 12.0;
                    p.rect_stroke(
                        hole.expand(grow),
                        radius + grow,
                        Stroke::new(2.0_f32, accent().gamma_multiply((1.0 - t) * 0.55 * fade)),
                        StrokeKind::Outside,
                    );
                }
            }
        });

    let mut done = false;
    let content_fade = if animate {
        (since_change / 0.22).min(1.0) * fade
    } else {
        1.0
    };
    let area = egui::Area::new(card_id)
        .order(Order::Tooltip)
        .fixed_pos(tour.card.unwrap_or(want_card))
        .show(ctx, |ui| {
            ui.set_opacity(fade);
            egui::Frame::new()
                .fill(surface())
                .stroke(Stroke::new(1.0_f32, border()))
                .corner_radius(14.0)
                .inner_margin(egui::Margin::same(20))
                .shadow(epaint::Shadow {
                    offset: [0, 10],
                    blur: 30,
                    spread: 0,
                    color: Color32::from_black_alpha(if is_dark() { 140 } else { 60 }),
                })
                .show(ui, |ui| {
                    ui.set_width(CARD_W);
                    card_body(ui, tour, &steps, content_fade, &mut done);
                });
        });

    // A small pointer from the card to what it is about.
    if let (Some(facing), false) = (facing, moving) {
        let r = area.response.rect;
        let size = 9.0;
        let tip_toward = hole.center();
        let pts = match facing {
            Align2::LEFT_CENTER => {
                let y = tip_toward.y.clamp(r.top() + 22.0, r.bottom() - 22.0);
                [
                    pos2(r.left() - size, y),
                    pos2(r.left() + 1.0, y - size),
                    pos2(r.left() + 1.0, y + size),
                ]
            }
            Align2::CENTER_TOP => {
                let x = tip_toward.x.clamp(r.left() + 22.0, r.right() - 22.0);
                [
                    pos2(x, r.top() - size),
                    pos2(x + size, r.top() + 1.0),
                    pos2(x - size, r.top() + 1.0),
                ]
            }
            _ => {
                let x = tip_toward.x.clamp(r.left() + 22.0, r.right() - 22.0);
                [
                    pos2(x, r.bottom() + size),
                    pos2(x - size, r.bottom() - 1.0),
                    pos2(x + size, r.bottom() - 1.0),
                ]
            }
        };
        ctx.layer_painter(egui::LayerId::new(Order::Tooltip, card_id))
            .add(Shape::convex_polygon(
                pts.to_vec(),
                surface().gamma_multiply(fade),
                Stroke::NONE,
            ));
    }
    done
}

/// The card's contents: step count, icon, title, text, tips, progress and
/// the buttons.
fn card_body(ui: &mut egui::Ui, tour: &mut Tour, steps: &[Step], fade: f32, done: &mut bool) {
    let last = steps.len() - 1;
    let step = &steps[tour.step];
    ui.horizontal(|ui| {
        ui.label(faint(format!("{} / {}", tour.step + 1, steps.len())));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if tour.step < last && widgets::link_button(ui, tr("Skip tour")).clicked() {
                *done = true;
            }
        });
    });
    ui.add_space(10.0);
    ui.scope(|ui| {
        // The new step's text fades in.
        ui.set_opacity(fade);
        ui.horizontal(|ui| {
            let (tile, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
            ui.painter().rect_filled(tile, 12.0, accent_bg());
            ui.painter().text(
                tile.center(),
                Align2::CENTER_CENTER,
                step.icon,
                FontId::proportional(22.0),
                accent(),
            );
            ui.add_space(6.0);
            ui.add(egui::Label::new(strong(step.title, 18.0)).wrap());
        });
        ui.add_space(10.0);
        ui.add(egui::Label::new(RichText::new(&step.text).color(text_dim()).size(14.0)).wrap());
        if !step.tips.is_empty() {
            ui.add_space(12.0);
            for (icon, tip) in &step.tips {
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    ui.label(RichText::new(*icon).size(15.0).color(accent()));
                    ui.add(egui::Label::new(RichText::new(tip).size(13.0).color(text())).wrap());
                });
                ui.add_space(4.0);
            }
        }
    });
    ui.add_space(14.0);
    ui.horizontal(|ui| {
        // Progress: the current step is a longer pill that slides along.
        let (strip, _) =
            ui.allocate_exact_size(vec2(steps.len() as f32 * 12.0 + 12.0, 10.0), Sense::hover());
        let x = ui.ctx().animate_value_with_time(
            Id::new("vaultrust_tour_dot"),
            tour.step as f32,
            if cfg!(test) { 0.0 } else { 0.25 },
        );
        for i in 0..steps.len() {
            let c = strip.left_center() + vec2(i as f32 * 12.0 + 4.0, 0.0);
            let shift = if (i as f32) > x { 12.0 } else { 0.0 };
            ui.painter()
                .circle_filled(c + vec2(shift, 0.0), 3.0, rail());
        }
        let start = strip.left_center() + vec2(x * 12.0 + 4.0, 0.0);
        ui.painter().rect_filled(
            Rect::from_min_max(start - vec2(3.0, 3.0), start + vec2(15.0, 3.0)),
            3.0,
            accent(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let label = if tour.step == last {
                tr("Get started")
            } else {
                tr("Next")
            };
            if widgets::primary_button(ui, label).clicked() {
                if tour.step == last {
                    *done = true;
                } else {
                    tour.step += 1;
                }
            }
            if tour.step > 0 && widgets::secondary_button(ui, tr("Back")).clicked() {
                tour.step -= 1;
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_card_sits_beside_or_below_what_it_points_at() {
        let screen = Rect::from_min_size(Pos2::ZERO, vec2(1200.0, 800.0));
        let size = vec2(380.0, 280.0);
        // Sidebar: to the right.
        let (pos, facing) = place_card(
            screen,
            Rect::from_min_size(pos2(10.0, 600.0), vec2(200.0, 30.0)),
            size,
        );
        assert_eq!(facing, Align2::LEFT_CENTER);
        assert_eq!(pos.x, 228.0);
        assert!(pos.y + size.y <= 800.0 - GAP);
        // Top bar: below, kept on screen.
        let (pos, facing) = place_card(
            screen,
            Rect::from_min_size(pos2(1040.0, 30.0), vec2(130.0, 36.0)),
            size,
        );
        assert_eq!(facing, Align2::CENTER_TOP);
        assert_eq!(pos, pos2(1200.0 - GAP - size.x, 66.0 + GAP));
        // Near the bottom: above.
        let (_, facing) = place_card(
            screen,
            Rect::from_min_size(pos2(600.0, 700.0), vec2(100.0, 30.0)),
            size,
        );
        assert_eq!(facing, Align2::CENTER_BOTTOM);
    }
}
