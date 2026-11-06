//! Start screen: create or open a vault.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Align2, CursorIcon, FontId, Frame, Rect, Sense, Vec2};

use super::icons;
use super::theme::*;
use super::widgets::{self, centered_column};
use super::{Services, Transition};
use crate::i18n::tr;
use crate::trf;

pub struct WelcomeState;

pub fn pick_vault_file() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title(tr("Open vault"))
        .add_filter(tr("VaultRust vault"), &["vault"])
        .add_filter(tr("All files"), &["*"])
        .pick_file()
}

pub fn show(ctx: &egui::Context, _s: &mut WelcomeState, svc: &mut Services) -> Option<Transition> {
    let mut t = None;
    egui::CentralPanel::default()
        .frame(Frame::new().fill(bg()).inner_margin(24.0))
        .show(ctx, |ui| {
            widgets::offline_footer(ui);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let recent = svc.recent.paths.len().min(6) as f32;
                    let content_h = 300.0
                        + if recent > 0.0 {
                            40.0 + recent * 46.0
                        } else {
                            0.0
                        };
                    ui.add_space(((ui.available_height() - content_h) / 2.0 - 24.0).max(24.0));
                    centered_column(ui, 400.0, |ui| {
                        ui.vertical_centered(|ui| {
                            widgets::logo(ui, 52.0);
                            ui.add_space(12.0);
                            ui.label(strong("VaultRust", 24.0));
                            ui.add_space(2.0);
                            ui.label(dim(tr("Your passwords, encrypted on this computer.")));
                        });
                        ui.add_space(28.0);

                        if widgets::primary_button_wide(
                            ui,
                            &icons::with(icons::PLUS, tr("Create a new vault")),
                            true,
                        )
                        .clicked()
                        {
                            t = Some(Transition::Create);
                        }
                        ui.add_space(2.0);
                        if widgets::secondary_button_wide(
                            ui,
                            &icons::with(icons::FOLDER_OPEN, tr("Open a vault file…")),
                        )
                        .clicked()
                        {
                            if let Some(p) = pick_vault_file() {
                                t = Some(Transition::Unlock(p));
                            }
                        }

                        if !svc.recent.paths.is_empty() {
                            ui.add_space(26.0);
                            ui.label(section_label(tr("RECENT VAULTS")));
                            ui.add_space(2.0);
                            let mut remove = None;
                            ui.spacing_mut().item_spacing.y = 2.0;
                            for p in svc.recent.paths.clone() {
                                match recent_row(ui, &p) {
                                    RowAction::Open => t = Some(Transition::Unlock(p.clone())),
                                    RowAction::Remove => remove = Some(p.clone()),
                                    RowAction::None => {}
                                }
                            }
                            if let Some(p) = remove {
                                svc.recent.remove(&p);
                            }
                        }
                    });
                });
        });
    t
}

enum RowAction {
    None,
    Open,
    Remove,
}

fn recent_row(ui: &mut egui::Ui, path: &Path) -> RowAction {
    let exists = path.exists();
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 44.0), Sense::click());
    let remove_rect = Rect::from_center_size(
        rect.right_center() - Vec2::new(18.0, 0.0),
        Vec2::splat(24.0),
    );
    let remove = ui.interact(remove_rect, resp.id.with("remove"), Sense::click());
    let row_hot = resp.hovered() || remove.hovered();
    let p = ui.painter_at(rect);
    if row_hot {
        p.rect_filled(rect, 6.0, surface());
    }
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let dir = path.parent().map(widgets::short_path).unwrap_or_default();
    p.text(
        rect.left_center() + Vec2::new(10.0, 0.0),
        Align2::LEFT_CENTER,
        icons::VAULT,
        FontId::proportional(18.0),
        if exists { text_dim() } else { text_faint() },
    );
    let text = ui.painter_at(rect.with_max_x(remove_rect.min.x - 6.0));
    text.text(
        rect.left_center() + Vec2::new(38.0, -8.0),
        Align2::LEFT_CENTER,
        name,
        FontId::proportional(14.0),
        if exists {
            super::theme::text()
        } else {
            text_faint()
        },
    );
    text.text(
        rect.left_center() + Vec2::new(38.0, 9.0),
        Align2::LEFT_CENTER,
        if exists {
            dir
        } else {
            trf!("Missing — {dir}", dir)
        },
        FontId::proportional(11.5),
        text_faint(),
    );
    if row_hot {
        p.text(
            remove_rect.center(),
            Align2::CENTER_CENTER,
            icons::X,
            FontId::proportional(13.0),
            if remove.hovered() {
                super::theme::text()
            } else {
                text_faint()
            },
        );
    }
    let remove = remove
        .on_hover_text(tr("Remove from this list (the file is kept)"))
        .on_hover_cursor(CursorIcon::PointingHand);
    if remove.clicked() {
        return RowAction::Remove;
    }
    if resp.on_hover_cursor(CursorIcon::PointingHand).clicked() && exists {
        return RowAction::Open;
    }
    RowAction::None
}
