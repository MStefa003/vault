//! Password / passphrase generator.

use eframe::egui::{self, Align, Frame, RichText, Stroke};
use zeroize::Zeroizing;

use super::icons;
use super::main_view::MainState;
use super::theme::*;
use super::widgets::{self, section};
use super::Services;
use crate::analysis::estimate_strength;
use crate::generator::{
    generate_passphrase, generate_password, wordlist, GeneratorOptions, PassphraseOptions,
    AMBIGUOUS, MAX_LENGTH, MAX_WORDS, MIN_LENGTH, MIN_WORDS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Password,
    Passphrase,
}

pub struct GenState {
    mode: Mode,
    output: Zeroizing<String>,
    error: Option<String>,
    last: Option<(Mode, GeneratorOptions, PassphraseOptions)>,
}

impl Default for GenState {
    fn default() -> Self {
        GenState {
            mode: Mode::Password,
            output: Zeroizing::new(String::new()),
            error: None,
            last: None,
        }
    }
}

impl GenState {
    fn regenerate(&mut self, g: &GeneratorOptions, p: &PassphraseOptions) {
        self.error = None;
        match self.mode {
            Mode::Password => match generate_password(g) {
                Ok(pw) => self.output = pw,
                Err(e) => {
                    self.output = Zeroizing::new(String::new());
                    self.error = Some(e.to_string());
                }
            },
            Mode::Passphrase => self.output = generate_passphrase(p),
        }
        self.last = Some((self.mode, g.clone(), p.clone()));
    }
}

/// Two-option segmented control.
fn segmented(ui: &mut egui::Ui, mode: &mut Mode) {
    Frame::new()
        .fill(surface())
        .stroke(Stroke::new(1.0_f32, border()))
        .corner_radius(7.0)
        .inner_margin(3.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (m, label) in [
                    (Mode::Password, "Password"),
                    (Mode::Passphrase, "Passphrase"),
                ] {
                    let on = *mode == m;
                    let b = egui::Button::new(RichText::new(label).color(if on {
                        text()
                    } else {
                        text_dim()
                    }))
                    .fill(if on {
                        surface_2()
                    } else {
                        egui::Color32::TRANSPARENT
                    })
                    .stroke(Stroke::NONE)
                    .corner_radius(5.0)
                    .min_size(egui::vec2(110.0, 26.0));
                    if ui.add(b).clicked() {
                        *mode = m;
                    }
                }
            });
        });
}

/// Generated secret in monospace, with digits and symbols tinted so
/// look-alike characters are easier to tell apart.
fn colored_secret(text: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let font = egui::FontId::monospace(20.0);
    for c in text.chars() {
        let color = if c.is_ascii_digit() {
            accent()
        } else if c.is_alphabetic() {
            super::theme::text()
        } else {
            warn()
        };
        let mut buf = [0u8; 4];
        job.append(
            c.encode_utf8(&mut buf),
            0.0,
            egui::TextFormat::simple(font.clone(), color),
        );
    }
    job
}

/// Toggleable pill.
fn chip(ui: &mut egui::Ui, on: &mut bool, label: &str) -> egui::Response {
    let (fill, stroke, color) = if *on {
        (accent_bg(), accent_fill(), text())
    } else {
        (surface_2(), border(), text_dim())
    };
    let resp = ui
        .add(
            egui::Button::new(
                RichText::new(label)
                    .color(color)
                    .family(egui::FontFamily::Monospace),
            )
            .fill(fill)
            .stroke(Stroke::new(1.0_f32, stroke))
            .corner_radius(14.0)
            .min_size(egui::vec2(48.0, 28.0)),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if resp.clicked() {
        *on = !*on;
    }
    resp
}

pub fn show(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
    egui::ScrollArea::vertical()
        .id_salt("generator")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            widgets::page_header(
                ui,
                "Generator",
                "Uses the operating system's secure random number generator.",
            );

            let mut g = ms.vault.data().settings.generator.clone();
            let mut p = ms.vault.data().settings.passphrase.clone();
            let st = &mut ms.gen;
            let mut copy = false;
            let mut regenerate = false;

            segmented(ui, &mut st.mode);
            ui.add_space(10.0);

            Frame::new()
                .fill(input())
                .stroke(Stroke::new(1.0_f32, border()))
                .corner_radius(RADIUS)
                .inner_margin(egui::Margin::symmetric(16, 14))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    widgets::trailing_row(
                        ui,
                        Align::Center,
                        |ui| {
                            if widgets::primary_button(ui, &icons::with(icons::COPY, "Copy"))
                                .clicked()
                            {
                                copy = true;
                            }
                            if widgets::icon_button(ui, icons::ARROWS_CLOCKWISE, "Generate another")
                                .clicked()
                            {
                                regenerate = true;
                            }
                        },
                        |ui| match &st.error {
                            Some(e) => {
                                ui.add(
                                    egui::Label::new(RichText::new(e.as_str()).color(danger()))
                                        .wrap(),
                                );
                            }
                            None => {
                                ui.add(egui::Label::new(colored_secret(&st.output)).wrap());
                            }
                        },
                    );
                    if !st.output.is_empty() {
                        ui.add_space(10.0);
                        let bits = match st.mode {
                            Mode::Password => g.entropy_bits(),
                            Mode::Passphrase => p.entropy_bits(),
                        };
                        let est = estimate_strength(&st.output);
                        let color = strength_color(est.strength);
                        let (rect, _) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width(), 3.0),
                            egui::Sense::hover(),
                        );
                        ui.painter().rect_filled(rect, 1.5, rail());
                        let mut part = rect;
                        part.set_width(rect.width() * est.strength.fraction());
                        ui.painter().rect_filled(part, 1.5, color);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(est.strength.label()).color(color).size(12.5));
                            ui.label(faint(format!("· {bits:.0} bits of entropy")));
                        });
                    }
                });
            ui.add_space(12.0);

            match st.mode {
                Mode::Password => section(ui, "Options", |ui| {
                    widgets::setting_row(
                        ui,
                        "Length",
                        &format!("{MIN_LENGTH}–{MAX_LENGTH} characters"),
                        320.0,
                        |ui| {
                            ui.add_sized(
                                [56.0, 28.0],
                                egui::DragValue::new(&mut g.length).range(MIN_LENGTH..=MAX_LENGTH),
                            );
                            ui.add_space(4.0);
                            ui.spacing_mut().slider_width = 220.0;
                            widgets::slider(
                                ui,
                                egui::Slider::new(&mut g.length, MIN_LENGTH..=64)
                                    .clamping(egui::SliderClamping::Never),
                            );
                        },
                    );
                    widgets::divider(ui, 16.0);
                    widgets::setting_row(
                        ui,
                        "Characters",
                        &format!("{} possible characters", g.pool().len()),
                        330.0,
                        |ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            // Right-to-left, so listed in reverse.
                            chip(ui, &mut g.symbols, "!#$%&*");
                            chip(ui, &mut g.digits, "0–9");
                            chip(ui, &mut g.lowercase, "a–z");
                            chip(ui, &mut g.uppercase, "A–Z");
                        },
                    );
                    widgets::divider(ui, 16.0);
                    widgets::switch_row(
                        ui,
                        &mut g.exclude_ambiguous,
                        "Avoid look-alike characters",
                        AMBIGUOUS,
                    );
                    widgets::divider(ui, 16.0);
                    widgets::switch_row(
                        ui,
                        &mut g.require_each_class,
                        "Use every selected set at least once",
                        "",
                    );
                    widgets::divider(ui, 16.0);
                    widgets::setting_row(
                        ui,
                        "Extra characters",
                        "Added to the pool",
                        240.0,
                        |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut g.custom_chars)
                                    .desired_width(220.0)
                                    .font(egui::TextStyle::Monospace)
                                    .margin(egui::vec2(10.0, 6.0)),
                            );
                        },
                    );
                    widgets::divider(ui, 16.0);
                    widgets::switch_row(
                        ui,
                        &mut g.custom_only,
                        "Use only the extra characters",
                        "",
                    );
                }),
                Mode::Passphrase => section(ui, "Options", |ui| {
                    widgets::setting_row(
                        ui,
                        "Words",
                        &format!("From a list of {} words", wordlist().len()),
                        320.0,
                        |ui| {
                            ui.add_sized(
                                [56.0, 28.0],
                                egui::DragValue::new(&mut p.words).range(MIN_WORDS..=MAX_WORDS),
                            );
                            ui.add_space(4.0);
                            ui.spacing_mut().slider_width = 220.0;
                            widgets::slider(
                                ui,
                                egui::Slider::new(&mut p.words, MIN_WORDS..=MAX_WORDS),
                            );
                        },
                    );
                    widgets::divider(ui, 16.0);
                    widgets::setting_row(ui, "Separator", "", 330.0, |ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        ui.add(
                            egui::TextEdit::singleline(&mut p.separator)
                                .desired_width(44.0)
                                .char_limit(3)
                                .font(egui::TextStyle::Monospace)
                                .horizontal_align(Align::Center)
                                .margin(egui::vec2(6.0, 6.0)),
                        );
                        for (s, label) in [(" ", "space"), ("_", "_"), (".", "."), ("-", "-")] {
                            let mut on = p.separator == s;
                            if chip(ui, &mut on, label).clicked() {
                                p.separator = s.into();
                            }
                        }
                    });
                    widgets::divider(ui, 16.0);
                    widgets::switch_row(ui, &mut p.capitalize, "Capitalize words", "");
                    widgets::divider(ui, 16.0);
                    widgets::switch_row(ui, &mut p.include_number, "Add a digit", "");
                }),
            }

            g.sanitize();
            p.sanitize();
            let changed = st
                .last
                .as_ref()
                .is_none_or(|(m, lg, lp)| *m != st.mode || *lg != g || *lp != p);
            if changed || regenerate {
                st.regenerate(&g, &p);
            }
            if copy && !st.output.is_empty() {
                let out = st.output.clone();
                ms.copy_secret(svc, &out, "Password");
            }
            let s = &ms.vault.data().settings;
            if s.generator != g || s.passphrase != p {
                let settings = &mut ms.vault.data_mut().settings;
                settings.generator = g;
                settings.passphrase = p;
                ms.schedule_settings_save();
            }
        });
}
