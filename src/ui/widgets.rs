//! Reusable widgets.

use eframe::egui::{
    self, Align, Align2, Button, Color32, CursorIcon, FontId, Frame, Layout, Rect, Response,
    RichText, Sense, Stroke, TextEdit, Ui, Vec2,
};

use super::icons;
use super::theme::{self, *};
use crate::analysis::StrengthReport;

/// Fixed mask so a secret's length is not revealed.
pub const MASK: &str = "••••••••••••";
pub const ICON_BUTTON: f32 = 28.0;
const BUTTON_H: f32 = 32.0;

/// A surface panel. Elevation comes from the lighter fill alone; borders on
/// every container made the screens look boxed-in.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(surface())
        .corner_radius(RADIUS)
        .inner_margin(16.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A card with a title.
pub fn section<R>(ui: &mut Ui, title: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    card(ui, |ui| {
        ui.label(strong(title, 15.0));
        ui.add_space(4.0);
        add(ui)
    })
}

/// A fixed-width column centred in the available space.
pub fn centered_column<R>(ui: &mut Ui, width: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
    let width = width.min(ui.available_width());
    let pad = ((ui.available_width() - width) / 2.0).max(0.0);
    ui.horizontal_top(|ui| {
        ui.add_space(pad);
        ui.allocate_ui_with_layout(
            Vec2::new(width, ui.available_height()),
            Layout::top_down(Align::Min),
            |ui| {
                ui.set_width(width);
                add(ui)
            },
        )
        .inner
    })
    .inner
}

fn filled(text: &str, fill: Color32, color: Color32) -> Button<'static> {
    Button::new(RichText::new(text).color(color).family(semibold()))
        .fill(fill)
        .stroke(Stroke::NONE)
        .corner_radius(6.0)
        .min_size(Vec2::new(0.0, BUTTON_H))
}

pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(filled(text, accent_fill(), Color32::WHITE))
        .on_hover_cursor(CursorIcon::PointingHand)
}

pub fn primary_button_enabled(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    ui.add_enabled(enabled, filled(text, accent_fill(), Color32::WHITE))
        .on_hover_cursor(CursorIcon::PointingHand)
}

/// Full-width button with its label centred (egui left-aligns the label of a
/// stretched `Button`).
fn wide_button(ui: &mut Ui, text: &str, primary: bool, enabled: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), 38.0),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, text));
    let hot = enabled && resp.hovered();
    let pressed = enabled && resp.is_pointer_button_down_on();
    let (mut fill, stroke, mut color) = if primary {
        (accent_fill(), Stroke::NONE, Color32::WHITE)
    } else {
        (
            surface_2(),
            Stroke::new(1.0, border()),
            super::theme::text(),
        )
    };
    if pressed {
        fill = fill.lerp_to_gamma(Color32::BLACK, 0.12);
    } else if hot {
        fill = fill.lerp_to_gamma(Color32::WHITE, 0.07);
    }
    if !enabled {
        fill = fill.lerp_to_gamma(bg(), 0.45);
        color = color.gamma_multiply(0.55);
    }
    let p = ui.painter();
    p.rect(rect, RADIUS_SM, fill, stroke, egui::StrokeKind::Inside);
    let font = if primary {
        FontId::new(14.0, semibold())
    } else {
        FontId::proportional(14.0)
    };
    p.text(rect.center(), Align2::CENTER_CENTER, text, font, color);
    if enabled {
        resp.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        resp
    }
}

pub fn primary_button_wide(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    wide_button(ui, text, true, enabled)
}

pub fn secondary_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(
        Button::new(text)
            .fill(surface_2())
            .stroke(Stroke::new(1.0, border()))
            .corner_radius(6.0)
            .min_size(Vec2::new(0.0, BUTTON_H)),
    )
    .on_hover_cursor(CursorIcon::PointingHand)
}

pub fn secondary_button_wide(ui: &mut Ui, text: &str) -> Response {
    wide_button(ui, text, false, true)
}

/// A row of frameless links, centred, separated by dots. Returns the index
/// of the clicked link.
pub fn centered_links(ui: &mut Ui, links: &[&str]) -> Option<usize> {
    let pad = ui.spacing().button_padding.x * 2.0;
    let gap = 20.0;
    let widths: Vec<f32> = links
        .iter()
        .map(|l| {
            ui.painter()
                .layout_no_wrap(l.to_string(), FontId::proportional(14.0), text_dim())
                .size()
                .x
                + pad
        })
        .collect();
    let total: f32 = widths.iter().sum::<f32>() + gap * (links.len().saturating_sub(1)) as f32;
    let mut clicked = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.add_space(((ui.available_width() - total) / 2.0).max(0.0));
        for (i, l) in links.iter().enumerate() {
            if i > 0 {
                let (r, _) = ui.allocate_exact_size(Vec2::new(gap, 18.0), Sense::hover());
                ui.painter().circle_filled(r.center(), 1.5, text_faint());
            }
            if link_button(ui, l).clicked() {
                clicked = Some(i);
            }
        }
    });
    clicked
}

pub fn danger_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(filled(text, danger_fill(), Color32::WHITE))
        .on_hover_cursor(CursorIcon::PointingHand)
}

pub fn danger_button_enabled(ui: &mut Ui, text: &str, enabled: bool) -> Response {
    ui.add_enabled(enabled, filled(text, danger_fill(), Color32::WHITE))
        .on_hover_cursor(CursorIcon::PointingHand)
}

/// Frameless text button (links, "Back", secondary navigation).
pub fn link_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(Button::new(RichText::new(text).color(text_dim())).frame(false))
        .on_hover_cursor(CursorIcon::PointingHand)
}

/// Square icon button that only shows a frame on hover.
pub fn icon_button(ui: &mut Ui, icon: &str, tooltip: &str) -> Response {
    ui.add_sized(
        [ICON_BUTTON, ICON_BUTTON],
        Button::new(RichText::new(icon).size(16.0).color(text_dim()))
            .frame_when_inactive(false)
            .corner_radius(6.0),
    )
    .on_hover_text(tooltip)
    .on_hover_cursor(CursorIcon::PointingHand)
}

/// Icon button that stays highlighted while `on`.
pub fn toggle_icon(ui: &mut Ui, on: bool, icon: &str, tooltip: &str) -> Response {
    let button = if on {
        Button::new(RichText::new(icon).size(16.0).color(accent()))
            .fill(accent_bg())
            .corner_radius(6.0)
    } else {
        Button::new(RichText::new(icon).size(16.0).color(text_dim()))
            .frame_when_inactive(false)
            .corner_radius(6.0)
    };
    ui.add_sized([ICON_BUTTON, ICON_BUTTON], button)
        .on_hover_text(tooltip)
        .on_hover_cursor(CursorIcon::PointingHand)
}

/// A row whose trailing controls are anchored to the right edge while the
/// main content (top-down, left-aligned) fills the remaining width.
/// `buttons` runs first and lays out right-to-left.
pub fn trailing_row<R>(
    ui: &mut Ui,
    align: Align,
    buttons: impl FnOnce(&mut Ui),
    main: impl FnOnce(&mut Ui) -> R,
) -> R {
    let row_h = ui.spacing().interact_size.y;
    trailing_row_h(ui, row_h, align, buttons, main)
}

/// [`trailing_row`] with an explicit row height.
pub fn trailing_row_h<R>(
    ui: &mut Ui,
    row_h: f32,
    align: Align,
    buttons: impl FnOnce(&mut Ui),
    main: impl FnOnce(&mut Ui) -> R,
) -> R {
    ui.allocate_ui_with_layout(
        Vec2::new(ui.available_width(), row_h),
        Layout::right_to_left(align),
        |ui| {
            buttons(ui);
            ui.allocate_ui_with_layout(
                Vec2::new(ui.available_width(), row_h),
                Layout::top_down(Align::Min),
                main,
            )
            .inner
        },
    )
    .inner
}

pub fn text_input(ui: &mut Ui, value: &mut String, hint: &str) -> Response {
    ui.add(
        TextEdit::singleline(value)
            .hint_text(theme::hint(hint))
            .desired_width(f32::INFINITY)
            .margin(Vec2::new(10.0, 7.0)),
    )
}

/// Password entry with the show/hide toggle inside the field's right edge.
pub fn password_input(ui: &mut Ui, value: &mut String, reveal: &mut bool, hint: &str) -> Response {
    let shown = *reveal;
    let resp = ui.add(
        TextEdit::singleline(value)
            .password(!shown)
            .hint_text(theme::hint(hint))
            .desired_width(f32::INFINITY)
            .margin(egui::Margin {
                left: 10,
                right: 38,
                top: 7,
                bottom: 7,
            }),
    );
    let button = Rect::from_center_size(
        egui::pos2(resp.rect.right() - 19.0, resp.rect.center().y),
        Vec2::splat(26.0),
    );
    let toggle = ui
        .interact(button, resp.id.with("reveal"), Sense::click())
        .on_hover_text(if shown { "Hide" } else { "Show" })
        .on_hover_cursor(CursorIcon::PointingHand);
    let p = ui.painter();
    if toggle.hovered() {
        p.rect_filled(button, 5.0, hover());
    }
    p.text(
        button.center(),
        Align2::CENTER_CENTER,
        if shown { icons::EYE_SLASH } else { icons::EYE },
        FontId::proportional(16.0),
        if shown || toggle.hovered() {
            text()
        } else {
            text_faint()
        },
    );
    if toggle.clicked() && ui.is_enabled() {
        *reveal = !*reveal;
    }
    resp
}

/// On/off switch.
pub fn switch(ui: &mut Ui, on: &mut bool) -> Response {
    let (rect, mut resp) = ui.allocate_exact_size(Vec2::new(34.0, 20.0), Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let value = *on;
    resp.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), value, "")
    });
    let t = ui.ctx().animate_bool_responsive(resp.id, value);
    let p = ui.painter();
    let mut track = rail().lerp_to_gamma(accent_fill(), t);
    if resp.hovered() {
        track = track.lerp_to_gamma(Color32::WHITE, 0.08);
    }
    p.rect_filled(rect, 10.0, track);
    let x = egui::lerp((rect.left() + 10.0)..=(rect.right() - 10.0), t);
    p.circle_filled(
        egui::pos2(x, rect.center().y),
        7.0,
        text_dim().lerp_to_gamma(Color32::WHITE, t),
    );
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// A settings row: title and optional description on the left, `control`
/// (laid out right-to-left, at most `control_width` wide) on the right.
pub fn setting_row(
    ui: &mut Ui,
    title: &str,
    desc: &str,
    control_width: f32,
    control: impl FnOnce(&mut Ui),
) {
    let w = ui.available_width();
    let h = if desc.is_empty() { 32.0 } else { 44.0 };
    ui.allocate_ui_with_layout(
        Vec2::new(w, h),
        Layout::right_to_left(Align::Center),
        |ui| {
            ui.set_min_height(h);
            ui.allocate_ui_with_layout(
                Vec2::new(control_width, h),
                Layout::right_to_left(Align::Center),
                control,
            );
            ui.add_space(16.0);
            ui.allocate_ui_with_layout(
                Vec2::new(ui.available_width(), h),
                Layout::top_down(Align::Min),
                |ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    let text_h = if desc.is_empty() { 18.0 } else { 36.0 };
                    ui.add_space(((h - text_h) / 2.0).max(0.0));
                    ui.add(egui::Label::new(RichText::new(title).color(text())).truncate());
                    if !desc.is_empty() {
                        ui.add(egui::Label::new(faint(desc)).truncate());
                    }
                },
            );
        },
    );
}

/// A setting row with a switch; clicking the text toggles it too.
pub fn switch_row(ui: &mut Ui, on: &mut bool, title: &str, desc: &str) -> Response {
    let mut resp = None;
    let top = ui.cursor().min;
    setting_row(ui, title, desc, 40.0, |ui| resp = Some(switch(ui, on)));
    let row = Rect::from_min_max(
        top,
        egui::pos2(ui.max_rect().right(), ui.min_rect().bottom()),
    );
    let mut resp = resp.expect("switch is always drawn");
    let text_click = ui
        .interact(
            row.with_max_x(resp.rect.left() - 8.0),
            resp.id.with("row"),
            Sense::click(),
        )
        .on_hover_cursor(CursorIcon::PointingHand);
    if text_click.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    resp
}

/// Horizontal slider with a round knob and an accent trail. The value is
/// not drawn; put a `DragValue` or label next to it.
pub fn slider(ui: &mut Ui, slider: egui::Slider<'_>) -> Response {
    ui.scope(|ui| {
        let s = ui.style_mut();
        s.spacing.interact_size.y = 18.0;
        s.spacing.slider_rail_height = 4.0;
        s.visuals.selection.bg_fill = accent_fill();
        // The rail is painted with `inactive.bg_fill` and the knob with the
        // current state's fill, so a solid knob comes from a square handle
        // with full corner rounding and a thick inside stroke.
        s.visuals.handle_shape = egui::style::HandleShape::Rect { aspect_ratio: 1.0 };
        let w = &mut s.visuals.widgets;
        w.inactive.bg_fill = rail();
        for (v, color) in [
            (&mut w.inactive, text()),
            (&mut w.hovered, Color32::WHITE),
            (&mut w.active, Color32::WHITE),
        ] {
            v.fg_stroke = Stroke::new(10.0, color);
            v.corner_radius = egui::CornerRadius::same(10);
            v.expansion = 0.0;
        }
        ui.add(slider.show_value(false).trailing_fill(true))
    })
    .inner
    .on_hover_cursor(CursorIcon::PointingHand)
}

/// Caret for combo boxes, matching the rest of the icon set.
pub fn combo_caret(ui: &Ui, rect: Rect, visuals: &egui::style::WidgetVisuals, _open: bool) {
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        icons::CARET_DOWN,
        FontId::proportional(12.0),
        visuals.fg_stroke.color,
    );
}

/// A rounded container for a list of rows separated by [`divider`]s.
pub fn group<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(super::theme::group())
        .corner_radius(RADIUS)
        .inner_margin(egui::Margin::symmetric(14, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// Full-width hairline between rows of a [`group`] or [`card`].
pub fn divider(ui: &mut Ui, bleed: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 9.0), Sense::hover());
    ui.painter().hline(
        (rect.left() - bleed)..=(rect.right() + bleed),
        rect.center().y,
        Stroke::new(1.0, super::theme::divider()),
    );
}

/// Truncating label followed by trailing buttons.
pub fn truncated_path_row(ui: &mut Ui, text: &str, buttons: impl FnOnce(&mut Ui)) {
    trailing_row(ui, Align::Center, buttons, |ui| {
        ui.add_space(6.0);
        ui.add(egui::Label::new(dim(text)).truncate());
    });
}

/// Thin meter plus label for a password strength estimate.
pub fn strength_meter(ui: &mut Ui, report: &StrengthReport) {
    let color = theme::strength_color(report.strength);
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 4.0), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 2.0, surface_2());
    let mut part = rect;
    part.set_width(rect.width() * report.strength.fraction());
    p.rect_filled(part, 2.0, color);
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(report.strength.label())
                .color(color)
                .size(12.5),
        );
        let mut detail = format!("about {:.0} bits", report.bits);
        if let Some(w) = report.warnings.first() {
            detail.push_str(&format!(" · {}", w.to_lowercase()));
        }
        ui.label(faint(detail));
    });
}

/// Small rounded label.
pub fn pill(ui: &mut Ui, text: &str, fg: Color32) -> Response {
    let bg = Color32::from_rgba_unmultiplied(fg.r(), fg.g(), fg.b(), 28);
    Frame::new()
        .fill(bg)
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(6, 1))
        .show(ui, |ui| ui.label(RichText::new(text).size(11.5).color(fg)))
        .response
}

/// Quiet outlined label for a tag.
pub fn tag_chip(ui: &mut Ui, text: &str) -> Response {
    Frame::new()
        .stroke(Stroke::new(1.0, border()))
        .corner_radius(RADIUS_SM)
        .inner_margin(egui::Margin::symmetric(7, 1))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("# {text}"))
                    .size(11.5)
                    .color(text_dim()),
            )
        })
        .response
}

/// Tag chip with a remove button; returns true when the × is clicked.
pub fn tag_chip_removable(ui: &mut Ui, text: &str) -> bool {
    let mut removed = false;
    Frame::new()
        .fill(surface_2())
        .corner_radius(RADIUS_SM)
        .inner_margin(egui::Margin {
            left: 8,
            right: 4,
            top: 2,
            bottom: 2,
        })
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.horizontal(|ui| {
                ui.label(RichText::new(text).size(12.5).color(super::theme::text()));
                removed = ui
                    .add(
                        Button::new(RichText::new(icons::X).size(11.0).color(text_faint()))
                            .frame_when_inactive(false)
                            .corner_radius(4.0)
                            .min_size(Vec2::splat(18.0)),
                    )
                    .on_hover_text("Remove tag")
                    .clicked();
            });
        });
    removed
}

/// Small ring that empties as a one-time code approaches expiry, with the
/// seconds left next to it.
pub fn countdown(ui: &mut Ui, remaining: u64, period: u64) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
    let p = ui.painter();
    let c = rect.center();
    let r = 6.5;
    let frac = remaining as f32 / period.max(1) as f32;
    let color = if remaining <= 5 { warn() } else { text_faint() };
    p.circle_stroke(c, r, Stroke::new(2.0, rail()));
    let steps = 32;
    let start = -std::f32::consts::FRAC_PI_2;
    let points: Vec<egui::Pos2> = (0..=steps)
        .map(|i| {
            let a = start + std::f32::consts::TAU * frac * i as f32 / steps as f32;
            egui::pos2(c.x + r * a.cos(), c.y + r * a.sin())
        })
        .collect();
    p.add(egui::Shape::line(points, Stroke::new(2.0, color)));
    ui.label(
        RichText::new(format!("{remaining}s"))
            .size(11.5)
            .color(color),
    );
}

/// Sidebar navigation item.
pub fn nav_item(
    ui: &mut Ui,
    icon: &str,
    label: &str,
    badge: Option<(String, Color32)>,
    selected: bool,
) -> Response {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 30.0), Sense::click());
    let hovered = resp.hovered();
    let p = ui.painter();
    if selected {
        p.rect_filled(rect, RADIUS_SM, surface_2());
        // A short accent bar marks the current page.
        p.rect_filled(
            Rect::from_min_size(
                rect.left_top() + Vec2::new(0.0, 8.0),
                Vec2::new(2.0, rect.height() - 16.0),
            ),
            1.0,
            accent(),
        );
    } else if hovered {
        p.rect_filled(rect, RADIUS_SM, surface());
    }
    let (icon_color, text_color) = if selected || hovered {
        (text(), text())
    } else {
        (text_faint(), text_dim())
    };
    p.text(
        rect.left_center() + Vec2::new(12.0, 0.0),
        Align2::LEFT_CENTER,
        icon,
        FontId::proportional(16.0),
        icon_color,
    );
    // Long labels (tags) are clipped before the badge.
    ui.painter_at(rect.with_max_x(rect.right() - 34.0)).text(
        rect.left_center() + Vec2::new(38.0, 0.0),
        Align2::LEFT_CENTER,
        label,
        FontId::proportional(13.5),
        text_color,
    );
    if let Some((b, color)) = badge {
        p.text(
            rect.right_center() - Vec2::new(10.0, 0.0),
            Align2::RIGHT_CENTER,
            b,
            FontId::proportional(12.0),
            color,
        );
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// Logo: green rounded tile with a padlock drawn from shapes.
pub fn logo(ui: &mut Ui, size: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter();
    let s = size;
    p.rect_filled(rect, s * 0.24, accent());
    let dark = LOGO_INK;
    let c = rect.center();
    let body = Rect::from_center_size(c + Vec2::new(0.0, s * 0.09), Vec2::new(s * 0.46, s * 0.34));
    let r = s * 0.15;
    let top = body.top() - s * 0.02;
    let stroke = Stroke::new(s * 0.075, dark);
    let arc: Vec<egui::Pos2> = (0..=24)
        .map(|i| {
            let a = std::f32::consts::PI * (1.0 + i as f32 / 24.0);
            egui::pos2(c.x + r * a.cos(), top + r * a.sin())
        })
        .collect();
    p.add(egui::Shape::line(arc, stroke));
    for x in [c.x - r, c.x + r] {
        p.line_segment(
            [egui::pos2(x, top), egui::pos2(x, body.top() + 1.0)],
            stroke,
        );
    }
    p.rect_filled(body, s * 0.06, dark);
    let hole = c + Vec2::new(0.0, s * 0.06);
    p.circle_filled(hole, s * 0.045, accent());
    p.rect_filled(
        Rect::from_center_size(
            hole + Vec2::new(0.0, s * 0.05),
            Vec2::new(s * 0.035, s * 0.08),
        ),
        1.0,
        accent(),
    );
    resp
}

/// Small rounded tile with an entry-type icon.
pub fn kind_tile(ui: &Ui, rect: Rect, icon: &str) {
    let p = ui.painter();
    p.rect_filled(rect, 6.0, surface_2());
    p.text(
        rect.center(),
        Align2::CENTER_CENTER,
        icon,
        FontId::proportional(16.0),
        text_dim(),
    );
}

/// Muted tile colours for monograms; white text is readable on all of them
/// in both themes.
const TILE_COLORS: [Color32; 10] = [
    Color32::from_rgb(0x3d, 0x6c, 0x9e),
    Color32::from_rgb(0x8a, 0x55, 0x9a),
    Color32::from_rgb(0xa9, 0x55, 0x3c),
    Color32::from_rgb(0x3e, 0x7c, 0x80),
    Color32::from_rgb(0x9a, 0x73, 0x2a),
    Color32::from_rgb(0x5f, 0x63, 0xad),
    Color32::from_rgb(0x99, 0x4a, 0x67),
    Color32::from_rgb(0x5a, 0x78, 0x38),
    Color32::from_rgb(0x76, 0x62, 0x55),
    Color32::from_rgb(0x2f, 0x7d, 0x5c),
];

/// An entry's letter tile: the first letter of its title on a colour picked
/// from its website (or title), so every item for the same site looks the
/// same and lists can be scanned by colour as well as by name.
pub fn entry_tile(ui: &Ui, rect: Rect, e: &crate::model::Entry) {
    let p = ui.painter();
    let letter = e
        .title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string());
    let Some(letter) = letter else {
        kind_tile(ui, rect, icons::kind_icon(e.kind));
        return;
    };
    let seed = e
        .first_of(crate::model::FieldKind::Url)
        .map(crate::autotype::url_host)
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| e.title.trim().to_lowercase());
    // FNV-1a: stable across runs, unlike the std hasher.
    let hash = seed.bytes().fold(0x811c_9dc5_u32, |h, b| {
        (h ^ b as u32).wrapping_mul(0x0100_0193)
    });
    let color = TILE_COLORS[hash as usize % TILE_COLORS.len()];
    let side = rect.width().min(rect.height());
    p.rect_filled(rect, (side * 0.24).round(), color);
    p.text(
        rect.center() + Vec2::new(0.0, -0.5),
        Align2::CENTER_CENTER,
        letter,
        FontId::new((side * 0.48).round(), semibold()),
        Color32::WHITE,
    );
}

/// "834 bytes", "12 KB", "3.4 MB".
pub fn file_size(n: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * 1024;
    if n < KB {
        format!("{n} bytes")
    } else if n < MB {
        format!("{} KB", n.div_ceil(KB))
    } else {
        format!("{:.1} MB", n as f64 / MB as f64)
    }
}

pub fn error_text(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(icons::with(icons::WARNING_CIRCLE, text)).color(danger()));
}

fn notice(ui: &mut Ui, icon: &str, text: &str, color: Color32) {
    Frame::new()
        .fill(Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            18,
        ))
        .stroke(Stroke::new(
            1.0,
            Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 60),
        ))
        .corner_radius(6.0)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.label(RichText::new(icon).color(color).size(15.0));
                ui.add(egui::Label::new(RichText::new(text).color(super::theme::text())).wrap());
            });
        });
}

pub fn warning_box(ui: &mut Ui, text: &str) {
    notice(ui, icons::WARNING, text, warn());
}

pub fn danger_box(ui: &mut Ui, text: &str) {
    notice(ui, icons::WARNING_OCTAGON, text, danger());
}

/// Quiet reminder at the bottom of the start and unlock screens.
pub fn offline_footer(ui: &Ui) {
    let r = ui.max_rect();
    let mut job = egui::text::LayoutJob::default();
    let font = FontId::proportional(12.0);
    job.append(
        icons::SHIELD_CHECK,
        0.0,
        egui::TextFormat::simple(font.clone(), accent()),
    );
    job.append(
        "Encrypted on this device  ·  Your vault never leaves it",
        6.0,
        egui::TextFormat::simple(font, text_faint()),
    );
    let galley = ui.painter().layout_job(job);
    let pos = egui::pos2(
        r.center().x - galley.size().x / 2.0,
        r.bottom() - galley.size().y,
    );
    ui.painter().galley(pos, galley, text_faint());
}

/// A path for display, with the user profile folder shortened to `~`.
pub fn short_path(path: &std::path::Path) -> String {
    let full = path.display().to_string();
    match std::env::var("USERPROFILE") {
        Ok(home) if !home.is_empty() && full.to_lowercase().starts_with(&home.to_lowercase()) => {
            format!("~{}", &full[home.len()..])
        }
        _ => full,
    }
}

/// Page title with an optional one-line description.
pub fn page_header(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.label(strong(title, 22.0));
    if !subtitle.is_empty() {
        ui.label(dim(subtitle));
    }
    ui.add_space(12.0);
}

/// Page title on the left, actions on the right.
pub fn page_header_with(ui: &mut Ui, title: &str, subtitle: &str, actions: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(strong(title, 22.0));
            if !subtitle.is_empty() {
                ui.label(dim(subtitle));
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), actions);
    });
    ui.add_space(12.0);
}
