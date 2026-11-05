//! Trash: deleted items, restorable until they expire.

use eframe::egui::{self, Align};

use super::icons::{self, kind_icon};
use super::main_view::MainState;
use super::modals::Modal;
use super::theme::*;
use super::widgets;
use super::Services;
use crate::model::TRASH_RETENTION_DAYS;
use crate::timeutil::{age_description, now_unix};

enum Act {
    Restore(u64),
    Purge(u64),
    Empty,
}

pub fn show(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services) {
    let mut act = None;
    let data = ms.vault.data();
    let n = data.trash.len();
    widgets::page_header_with(
        ui,
        "Trash",
        &format!(
            "Deleted items stay here for {TRASH_RETENTION_DAYS} days, then are removed for good."
        ),
        |ui| {
            if n > 0 && widgets::secondary_button(ui, "Empty Trash…").clicked() {
                act = Some(Act::Empty);
            }
        },
    );
    egui::ScrollArea::vertical()
        .id_salt("trash")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if n == 0 {
                ui.add_space(8.0);
                ui.label(dim("The Trash is empty."));
                return;
            }
            let now = now_unix();
            let mut items: Vec<_> = data.trash.iter().collect();
            items.sort_by_key(|t| std::cmp::Reverse(t.deleted));
            widgets::group(ui, |ui| {
                for (i, t) in items.iter().enumerate() {
                    if i > 0 {
                        widgets::divider(ui, 14.0);
                    }
                    let e = &t.entry;
                    let left = TRASH_RETENTION_DAYS - (now - t.deleted) / 86_400;
                    widgets::trailing_row_h(
                        ui,
                        42.0,
                        Align::Center,
                        |ui| {
                            if widgets::icon_button(ui, icons::X, "Delete forever").clicked() {
                                act = Some(Act::Purge(e.id));
                            }
                            if widgets::secondary_button(
                                ui,
                                &icons::with(icons::ARROW_COUNTER_CLOCKWISE, "Restore"),
                            )
                            .clicked()
                            {
                                act = Some(Act::Restore(e.id));
                            }
                        },
                        |ui| {
                            ui.horizontal_centered(|ui| {
                                ui.spacing_mut().item_spacing.x = 10.0;
                                ui.label(
                                    egui::RichText::new(kind_icon(e.kind))
                                        .color(text_faint())
                                        .size(15.0),
                                );
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 1.0;
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(e.display_title()).color(text()),
                                        )
                                        .truncate(),
                                    );
                                    ui.label(faint(format!(
                                        "Deleted {} · removed in {} day{}",
                                        age_description(t.deleted, now),
                                        left.max(0),
                                        if left == 1 { "" } else { "s" }
                                    )));
                                });
                            });
                        },
                    );
                }
            });
        });

    match act {
        Some(Act::Restore(id)) => {
            if ms.vault.data_mut().restore_entry(id) && ms.commit(svc.toasts) {
                svc.toasts.success("Restored");
            }
        }
        Some(Act::Purge(id)) => ms.modal = Some(Modal::PurgeEntry(id)),
        Some(Act::Empty) => ms.modal = Some(Modal::EmptyTrash),
        None => {}
    }
}
