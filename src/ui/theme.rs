//! Visual theme.
//!
//! One decision per axis, applied everywhere:
//! * Neutrals: a warm graphite ramp in dark mode and a warm paper ramp in
//!   light mode (not the usual blue-grey). Higher elevation means a lighter
//!   surface rather than a shadow.
//! * Colour: a single jade accent, used only for the primary action, focus
//!   and the current page; red / amber / green carry meaning and nothing else.
//! * Shape: [`RADIUS`] for containers, [`RADIUS_SM`] for controls and rows.
//! * Type: Segoe UI, a 12 / 13.5 / 14 / 20+ scale, semibold for headings.
//!
//! Colours are read through small functions (`bg()`, `text()`, …) from the
//! active [`Palette`], so the whole UI switches with [`apply`].

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, IconData, Margin,
    RichText, Shadow, Stroke, TextStyle, Vec2,
};

/// Every colour the UI uses, for one theme.
pub struct Palette {
    pub bg: Color32,
    pub sidebar: Color32,
    pub surface: Color32,
    pub surface_2: Color32,
    pub input: Color32,
    pub hover: Color32,
    /// Hover background for list rows.
    pub row_hover: Color32,
    pub border: Color32,
    /// Hairline between rows.
    pub divider: Color32,
    /// Slider rails and switch tracks when off.
    pub rail: Color32,
    /// Background of grouped field lists.
    pub group: Color32,
    pub text: Color32,
    pub text_dim: Color32,
    pub text_faint: Color32,
    /// Accent for text, icons and indicators.
    pub accent: Color32,
    /// Accent for filled buttons (white text stays readable on it).
    pub accent_fill: Color32,
    /// The accent at low opacity (premultiplied), for selection backgrounds.
    pub accent_bg: Color32,
    pub danger: Color32,
    pub danger_fill: Color32,
    pub warn: Color32,
    /// Stroke of hovered controls.
    pub hover_stroke: Color32,
    /// Pressed secondary controls.
    pub pressed: Color32,
    pub shadow_alpha: u8,
}

pub const DARK: Palette = Palette {
    bg: Color32::from_rgb(0x17, 0x16, 0x15),
    sidebar: Color32::from_rgb(0x12, 0x11, 0x10),
    surface: Color32::from_rgb(0x1e, 0x1d, 0x1b),
    surface_2: Color32::from_rgb(0x28, 0x26, 0x23),
    input: Color32::from_rgb(0x12, 0x11, 0x10),
    hover: Color32::from_rgb(0x2d, 0x2b, 0x28),
    row_hover: Color32::from_rgb(0x21, 0x20, 0x1e),
    border: Color32::from_rgb(0x2e, 0x2c, 0x29),
    divider: Color32::from_rgb(0x25, 0x23, 0x21),
    rail: Color32::from_rgb(0x3a, 0x37, 0x33),
    group: Color32::from_rgb(0x1a, 0x19, 0x17),
    text: Color32::from_rgb(0xec, 0xe8, 0xe2),
    text_dim: Color32::from_rgb(0xa5, 0x9f, 0x96),
    text_faint: Color32::from_rgb(0x74, 0x6f, 0x68),
    accent: Color32::from_rgb(0x6f, 0xc2, 0x9b),
    accent_fill: Color32::from_rgb(0x2f, 0x85, 0x60),
    accent_bg: Color32::from_rgba_premultiplied(16, 27, 22, 36),
    danger: Color32::from_rgb(0xe8, 0x66, 0x5f),
    danger_fill: Color32::from_rgb(0xb0, 0x3d, 0x37),
    warn: Color32::from_rgb(0xe2, 0xa5, 0x45),
    hover_stroke: Color32::from_rgb(0x42, 0x3e, 0x39),
    pressed: Color32::from_rgb(0x34, 0x31, 0x2d),
    shadow_alpha: 110,
};

/// Warm paper tones; accent and status colours are darker than in dark mode
/// so they keep their contrast on a light background.
pub const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xf6, 0xf4, 0xf0),
    sidebar: Color32::from_rgb(0xec, 0xe9, 0xe3),
    surface: Color32::from_rgb(0xff, 0xff, 0xff),
    surface_2: Color32::from_rgb(0xef, 0xec, 0xe7),
    input: Color32::from_rgb(0xff, 0xff, 0xff),
    hover: Color32::from_rgb(0xe6, 0xe2, 0xdb),
    row_hover: Color32::from_rgb(0xf3, 0xf0, 0xeb),
    border: Color32::from_rgb(0xdd, 0xd8, 0xd0),
    divider: Color32::from_rgb(0xec, 0xe8, 0xe2),
    rail: Color32::from_rgb(0xd3, 0xcd, 0xc4),
    group: Color32::from_rgb(0xf8, 0xf6, 0xf3),
    text: Color32::from_rgb(0x1f, 0x1d, 0x1a),
    text_dim: Color32::from_rgb(0x5b, 0x56, 0x4f),
    text_faint: Color32::from_rgb(0x8a, 0x84, 0x7b),
    accent: Color32::from_rgb(0x1e, 0x7a, 0x54),
    accent_fill: Color32::from_rgb(0x23, 0x7f, 0x58),
    accent_bg: Color32::from_rgba_premultiplied(4, 15, 10, 31),
    danger: Color32::from_rgb(0xc0, 0x3f, 0x37),
    danger_fill: Color32::from_rgb(0xb5, 0x37, 0x2f),
    warn: Color32::from_rgb(0xa8, 0x6a, 0x12),
    hover_stroke: Color32::from_rgb(0xc4, 0xbd, 0xb2),
    pressed: Color32::from_rgb(0xdd, 0xd7, 0xce),
    shadow_alpha: 40,
};

static DARK_MODE: AtomicBool = AtomicBool::new(true);

/// The active palette.
pub fn palette() -> &'static Palette {
    if DARK_MODE.load(Ordering::Relaxed) {
        &DARK
    } else {
        &LIGHT
    }
}

pub fn is_dark() -> bool {
    DARK_MODE.load(Ordering::Relaxed)
}

macro_rules! tokens {
    ($($name:ident),* $(,)?) => {
        $(
            #[inline]
            pub fn $name() -> Color32 {
                palette().$name
            }
        )*
    };
}

tokens!(
    bg,
    sidebar,
    surface,
    surface_2,
    input,
    hover,
    row_hover,
    border,
    divider,
    rail,
    group,
    text,
    text_dim,
    text_faint,
    accent,
    accent_fill,
    accent_bg,
    danger,
    danger_fill,
    warn,
);

/// The padlock in the logo, dark in both themes.
pub const LOGO_INK: Color32 = Color32::from_rgb(0x12, 0x11, 0x10);

/// Corner radius of containers (cards, groups, dialogs).
pub const RADIUS: f32 = 8.0;
/// Corner radius of controls and rows inside containers.
pub const RADIUS_SM: f32 = 6.0;

pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn strong(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text)
        .family(semibold())
        .size(size)
        .color(self::text())
}

pub fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text).color(text_dim())
}

pub fn small(text: impl Into<String>) -> RichText {
    RichText::new(text).size(12.5).color(text_dim())
}

pub fn faint(text: impl Into<String>) -> RichText {
    RichText::new(text).size(12.0).color(text_faint())
}

/// Placeholder text in an empty input. The colour has to be explicit:
/// `override_text_color` would otherwise draw it like typed text.
pub fn hint(text: impl Into<String>) -> RichText {
    RichText::new(text).color(text_faint())
}

pub fn section_label(text: &str) -> RichText {
    RichText::new(text)
        .size(11.5)
        .color(text_faint())
        .family(semibold())
}

pub fn strength_color(s: crate::analysis::Strength) -> Color32 {
    use crate::analysis::Strength::*;
    match s {
        VeryWeak => danger(),
        Weak if is_dark() => Color32::from_rgb(0xe0, 0x80, 0x4a),
        Weak => Color32::from_rgb(0xb8, 0x55, 0x22),
        Fair => warn(),
        Strong if is_dark() => Color32::from_rgb(0x4a, 0xa8, 0x7a),
        Strong => Color32::from_rgb(0x2e, 0x8a, 0x60),
        VeryStrong => accent(),
    }
}

/// Install the fonts. Call once; they become usable on the next frame.
pub fn install(ctx: &egui::Context) {
    install_fonts(ctx);
}

/// Switch every colour (and egui's own visuals) to the dark or light theme.
pub fn apply(ctx: &egui::Context, dark: bool) {
    DARK_MODE.store(dark, Ordering::Relaxed);
    let p = palette();

    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.extreme_bg_color = p.input;
    v.text_edit_bg_color = Some(p.input);
    v.faint_bg_color = p.surface_2;
    v.code_bg_color = p.input;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(8);
    v.window_shadow = Shadow {
        offset: [0, 8],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(p.shadow_alpha),
    };
    v.popup_shadow = Shadow {
        offset: [0, 4],
        blur: 12,
        spread: 0,
        color: Color32::from_black_alpha(p.shadow_alpha.saturating_sub(20)),
    };
    v.hyperlink_color = p.accent;
    v.selection.bg_fill =
        Color32::from_rgba_unmultiplied(p.accent.r(), p.accent.g(), p.accent.b(), 0x48);
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.text_cursor.stroke = Stroke::new(2.0, p.accent);
    v.warn_fg_color = p.warn;
    v.error_fg_color = p.danger;
    v.slider_trailing_fill = true;
    v.striped = false;
    v.override_text_color = Some(p.text);

    let r = CornerRadius::same(6);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.surface;
    w.noninteractive.weak_bg_fill = p.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text_dim);
    w.noninteractive.corner_radius = r;

    w.inactive.bg_fill = p.surface_2;
    w.inactive.weak_bg_fill = p.surface_2;
    w.inactive.bg_stroke = Stroke::new(1.0, p.border);
    w.inactive.fg_stroke = Stroke::new(1.0, p.text);
    w.inactive.corner_radius = r;

    w.hovered.bg_fill = p.hover;
    w.hovered.weak_bg_fill = p.hover;
    w.hovered.bg_stroke = Stroke::new(1.0, p.hover_stroke);
    w.hovered.fg_stroke = Stroke::new(1.0, p.text);
    w.hovered.corner_radius = r;
    w.hovered.expansion = 0.0;

    w.active.bg_fill = p.accent_fill;
    w.active.weak_bg_fill = p.pressed;
    w.active.bg_stroke = Stroke::new(1.0, p.accent);
    w.active.fg_stroke = Stroke::new(1.0, p.text);
    w.active.corner_radius = r;
    w.active.expansion = 0.0;

    w.open.bg_fill = p.surface_2;
    w.open.weak_bg_fill = p.surface_2;
    w.open.bg_stroke = Stroke::new(1.0, p.border);
    w.open.corner_radius = r;

    let theme = if dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    };
    let mut style = (*ctx.style_of(theme)).clone();
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

    ctx.set_theme(if dark {
        egui::ThemePreference::Dark
    } else {
        egui::ThemePreference::Light
    });
    ctx.set_style_of(theme, style);
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
                px.copy_from_slice(&[0x12, 0x11, 0x10, alpha]);
            } else {
                px.copy_from_slice(&[0x6f, 0xc2, 0x9b, alpha]);
            }
        }
    }
    IconData {
        rgba,
        width: N as u32,
        height: N as u32,
    }
}
