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

/// What a toast's button does when clicked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastAction {
    /// Put a just-trashed item back.
    RestoreEntry(u64),
}

struct Toast {
    msg: String,
    kind: Kind,
    until: Instant,
    action: Option<(&'static str, ToastAction)>,
}

#[derive(Default)]
pub struct Toasts {
    items: Vec<Toast>,
    clicked: Option<ToastAction>,
}

impl Toasts {
    fn push(&mut self, msg: String, kind: Kind, secs: u64) {
        self.push_toast(Toast {
            msg,
            kind,
            until: Instant::now() + Duration::from_secs(secs),
            action: None,
        });
    }

    fn push_toast(&mut self, t: Toast) {
        self.items.push(t);
        if self.items.len() > 3 {
            self.items.remove(0);
        }
    }

    /// A success message with a button (such as "Undo"), shown a little
    /// longer so there is time to use it.
    pub fn with_action(
        &mut self,
        msg: impl Into<String>,
        label: &'static str,
        action: ToastAction,
    ) {
        self.push_toast(Toast {
            msg: msg.into(),
            kind: Kind::Success,
            until: Instant::now() + Duration::from_secs(8),
            action: Some((label, action)),
        });
    }

    /// The most recent visible toast action, for keyboard shortcuts (Ctrl+Z).
    pub fn latest_action(&self) -> Option<ToastAction> {
        let now = Instant::now();
        self.items
            .iter()
            .rev()
            .filter(|t| t.until > now)
            .find_map(|t| t.action.map(|(_, a)| a))
    }

    /// Take the action whose button was clicked (or that was triggered by
    /// [`Toasts::trigger`]), removing its toast.
    pub fn take_clicked(&mut self) -> Option<ToastAction> {
        let a = self.clicked.take()?;
        self.items.retain(|t| t.action.map(|(_, x)| x) != Some(a));
        Some(a)
    }

    pub fn trigger(&mut self, action: ToastAction) {
        self.clicked = Some(action);
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
        self.items.retain(|t| t.until > now);
        if self.items.is_empty() {
            return;
        }
        // Keep repainting so toasts disappear on time even when idle.
        if let Some(next) = self.items.iter().map(|t| t.until).min() {
            ctx.request_repaint_after(next.saturating_duration_since(now));
        }
        let interactive = self.items.iter().any(|t| t.action.is_some());
        let mut clicked = None;
        egui::Area::new(Id::new("vaultrust_toasts"))
            .order(Order::Tooltip)
            .anchor(Align2::RIGHT_BOTTOM, [-16.0, -16.0])
            .interactable(interactive)
            .show(ctx, |ui| {
                for t in &self.items {
                    let (msg, kind) = (&t.msg, t.kind);
                    let (icon, color) = match kind {
                        Kind::Info => (icons::INFO, text_dim()),
                        Kind::Success => (icons::CHECK_CIRCLE, accent()),
                        Kind::Error => (icons::WARNING_CIRCLE, danger()),
                    };
                    Frame::new()
                        .fill(surface_2())
                        .stroke(Stroke::new(1.0, border()))
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
                                ui.label(RichText::new(msg).color(text()));
                                if let Some((label, action)) = t.action {
                                    ui.add_space(6.0);
                                    let b = ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new(label)
                                                    .color(accent())
                                                    .family(semibold()),
                                            )
                                            .frame(false),
                                        )
                                        .on_hover_text("Ctrl+Z")
                                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                                    if b.clicked() {
                                        clicked = Some(action);
                                    }
                                }
                            });
                        });
                    ui.add_space(6.0);
                }
            });
        if clicked.is_some() {
            self.clicked = clicked;
            ctx.request_repaint();
        }
    }
}
