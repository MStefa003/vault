//! Visual theme: dark charcoal, restrained green accent, Segoe UI.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, IconData, Margin,
    RichText, Shadow, Stroke, TextStyle, Vec2,
};

pub const BG: Color32 = Color32::from_rgb(0x15, 0x16, 0x18);
pub const SIDEBAR: Color32 = Color32::from_rgb(0x11, 0x12, 0x14);
pub const SURFACE: Color32 = Color32::from_rgb(0x1c, 0x1e, 0x21);
pub const SURFACE_2: Color32 = Color32::from_rgb(0x24, 0x27, 0x2b);
pub const INPUT: Color32 = Color32::from_rgb(0x12, 0x13, 0x15);
pub const HOVER: Color32 = Color32::from_rgb(0x29, 0x2c, 0x31);
/// Hover background for list rows on a SURFACE panel.
pub const ROW_HOVER: Color32 = Color32::from_rgb(0x21, 0x23, 0x27);
pub const BORDER: Color32 = Color32::from_rgb(0x2b, 0x2e, 0x33);
/// Hairline between rows inside a group.
pub const DIVIDER: Color32 = Color32::from_rgb(0x26, 0x29, 0x2d);
/// Slider rails and switch tracks when off.
pub const RAIL: Color32 = Color32::from_rgb(0x34, 0x38, 0x3e);
/// Background of grouped field lists (between INPUT and SURFACE).
pub const GROUP: Color32 = Color32::from_rgb(0x18, 0x1a, 0x1c);
pub const TEXT: Color32 = Color32::from_rgb(0xe3, 0xe5, 0xe8);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x9a, 0xa0, 0xa8);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x68, 0x6e, 0x76);
/// Accent for text, icons and indicators.
pub const ACCENT: Color32 = Color32::from_rgb(0x5c, 0xc4, 0x91);
/// Accent for filled buttons (darker, so white text stays readable).
pub const ACCENT_FILL: Color32 = Color32::from_rgb(0x2b, 0x86, 0x5c);
/// ACCENT at ~14% opacity (premultiplied), for selection backgrounds.
pub const ACCENT_BG: Color32 = Color32::from_rgba_premultiplied(13, 27, 20, 36);
pub const DANGER: Color32 = Color32::from_rgb(0xe5, 0x5b, 0x5f);
pub const DANGER_FILL: Color32 = Color32::from_rgb(0xb3, 0x3a, 0x40);
pub const WARN: Color32 = Color32::from_rgb(0xe0, 0xa6, 0x3e);

pub const RADIUS: f32 = 8.0;

pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn strong(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text)
        .family(semibold())
        .size(size)
        .color(TEXT)
}

pub fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text).color(TEXT_DIM)
}

pub fn small(text: impl Into<String>) -> RichText {
    RichText::new(text).size(12.5).color(TEXT_DIM)
}

pub fn faint(text: impl Into<String>) -> RichText {
    RichText::new(text).size(12.0).color(TEXT_FAINT)
}

pub fn section_label(text: &str) -> RichText {
    RichText::new(text)
        .size(11.5)
        .color(TEXT_FAINT)
        .family(semibold())
}

pub fn strength_color(s: crate::analysis::Strength) -> Color32 {
    use crate::analysis::Strength::*;
    match s {
        VeryWeak => DANGER,
        Weak => Color32::from_rgb(0xe0, 0x80, 0x4a),
        Fair => WARN,
        Strong => Color32::from_rgb(0x4a, 0xa8, 0x7a),
        VeryStrong => ACCENT,
    }
}

pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);

    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = SURFACE;
    v.extreme_bg_color = INPUT;
    v.text_edit_bg_color = Some(INPUT);
    v.faint_bg_color = SURFACE_2;
    v.code_bg_color = INPUT;
    v.window_stroke = Stroke::new(1.0, BORDER);
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(8);
    v.window_shadow = Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(110),
    };
    v.popup_shadow = Shadow {
        offset: [0, 4],
        blur: 12,
        spread: 0,
        color: Color32::from_black_alpha(90),
    };
    v.hyperlink_color = ACCENT;
    v.selection.bg_fill = Color32::from_rgba_unmultiplied(0x5c, 0xc4, 0x91, 0x48);
    v.selection.stroke = Stroke::new(1.0, ACCENT);
    v.text_cursor.stroke = Stroke::new(2.0, ACCENT);
    v.warn_fg_color = WARN;
    v.error_fg_color = DANGER;
    v.slider_trailing_fill = true;
    v.striped = false;

    let r = CornerRadius::same(6);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = SURFACE;
    w.noninteractive.weak_bg_fill = SURFACE;
    w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_DIM);
    w.noninteractive.corner_radius = r;

    w.inactive.bg_fill = SURFACE_2;
    w.inactive.weak_bg_fill = SURFACE_2;
    w.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    w.inactive.corner_radius = r;

    w.hovered.bg_fill = HOVER;
    w.hovered.weak_bg_fill = HOVER;
    w.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x3a, 0x3e, 0x44));
    w.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    w.hovered.corner_radius = r;
    w.hovered.expansion = 0.0;

    w.active.bg_fill = ACCENT_FILL;
    w.active.weak_bg_fill = Color32::from_rgb(0x30, 0x34, 0x39);
    w.active.bg_stroke = Stroke::new(1.0, ACCENT);
    w.active.fg_stroke = Stroke::new(1.0, TEXT);
    w.active.corner_radius = r;
    w.active.expansion = 0.0;

    w.open.bg_fill = SURFACE_2;
    w.open.weak_bg_fill = SURFACE_2;
    w.open.bg_stroke = Stroke::new(1.0, BORDER);
    w.open.corner_radius = r;

    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals = v;
    style.text_styles = [
        (TextStyle::Heading, FontId::new(20.0, semibold())),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(14.0, FontFamily::Monospace),
        ),
    ]
    .into();
    style.spacing.item_spacing = Vec2::new(8.0, 7.0);
    style.spacing.button_padding = Vec2::new(12.0, 5.0);
    style.spacing.interact_size = Vec2::new(40.0, 30.0);
    style.spacing.window_margin = Margin::same(18);
    style.spacing.menu_margin = Margin::same(6);
    style.spacing.slider_width = 220.0;
    style.spacing.icon_width = 16.0;
    // Revealed secrets must not be selectable into egui's own clipboard
    // path, which would bypass automatic clearing.
    style.interaction.selectable_labels = false;
    style.url_in_tooltip = false;
    style.animation_time = 0.08;

    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.set_style_of(egui::Theme::Dark, style);
}

/// Segoe UI / Consolas from the local Windows font directory (never
/// downloaded), the bundled Phosphor icon font, and egui's bundled fonts as
/// fallbacks.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let dir = std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("Fonts");
    let mut load = |key: &str, file: &str| -> bool {
        match std::fs::read(dir.join(file)) {
            Ok(bytes) => {
                fonts
                    .font_data
                    .insert(key.to_string(), Arc::new(FontData::from_owned(bytes)));
                true
            }
            Err(_) => false,
        }
    };
    let have_regular = load("segoe", "segoeui.ttf");
    let have_semibold = load("segoe-sb", "seguisb.ttf");
    let have_mono = load("consolas", "consola.ttf");

    if have_regular {
        if let Some(f) = fonts.families.get_mut(&FontFamily::Proportional) {
            f.insert(0, "segoe".into());
        }
    }
    if have_mono {
        if let Some(f) = fonts.families.get_mut(&FontFamily::Monospace) {
            f.insert(0, "consolas".into());
        }
    }
    // Inserts "phosphor" right after the primary proportional font.
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);

    let mut sb: Vec<String> = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    if have_semibold {
        sb.insert(0, "segoe-sb".to_string());
    }
    fonts.families.insert(semibold(), sb);
    ctx.set_fonts(fonts);
}

/// Window icon: a green rounded tile with a dark padlock.
pub fn app_icon() -> IconData {
    const N: usize = 64;
    let mut rgba = vec![0u8; N * N * 4];
    let c = (N as f32 - 1.0) / 2.0;
    for y in 0..N {
        for x in 0..N {
            let (fx, fy) = (x as f32, y as f32);
            let r = 14.0;
            let dx = (fx - c).abs() - (c - r);
            let dy = (fy - c).abs() - (c - r);
            let outside = dx.max(0.0).hypot(dy.max(0.0)) - r;
            if outside > 0.5 {
                continue;
            }
            let alpha = ((0.5 - outside).clamp(0.0, 1.0) * 255.0) as u8;
            // Padlock: body rectangle + shackle ring.
            let in_body = (fx - c).abs() < 14.0 && fy > c - 4.0 && fy < c + 16.0;
            let ring = (fx - c).hypot(fy - (c - 6.0));
            let in_shackle = fy < c - 2.0 && (7.0..11.5).contains(&ring);
            let in_hole = (fx - c).hypot(fy - (c + 4.0)) < 3.5
                || ((fx - c).abs() < 1.6 && fy > c + 4.0 && fy < c + 10.0);
            let px = &mut rgba[(y * N + x) * 4..(y * N + x) * 4 + 4];
            if (in_body && !in_hole) || in_shackle {
                px.copy_from_slice(&[0x11, 0x12, 0x14, alpha]);
            } else {
                px.copy_from_slice(&[0x5c, 0xc4, 0x91, alpha]);
            }
        }
    }
    IconData {
        rgba,
        width: N as u32,
        height: N as u32,
    }
}
