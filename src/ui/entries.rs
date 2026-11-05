//! Item manager: list, detail view and editor for every entry type.
//!
//! Shortcuts: Ctrl+F search, Ctrl+N new item, Ctrl+S save, Esc close editor.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Align2, CursorIcon, FontId, Frame, Id, Key, Layout, Margin, Modifiers, Rect,
    RichText, Sense, Stroke, TextEdit, TextStyle, Vec2,
};
use zeroize::{Zeroize, Zeroizing};

use super::icons::{self, kind_icon};
use super::main_view::{MainState, Nav};
use super::modals::Modal;
use super::theme::*;
use super::widgets::{self, card, MASK};
use super::Services;
use crate::analysis::{estimate_strength, HealthReport};
use crate::generator::{generate_password, GeneratorOptions};
use crate::model::{Entry, EntryKind, Field, FieldKind};
use crate::timeutil::{age_description, format_date, now_unix};

const SEARCH_ID: &str = "vaultrust_item_search";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    All,
    Favorites,
    Logins,
    Notes,
    Cards,
    ApiKeys,
    Identities,
    Infrastructure,
    Wifi,
    Custom,
}

impl Category {
    pub const ALL: [Category; 10] = [
        Category::All,
        Category::Favorites,
        Category::Logins,
        Category::Notes,
        Category::Cards,
        Category::ApiKeys,
        Category::Identities,
        Category::Infrastructure,
        Category::Wifi,
        Category::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::All => "All items",
            Category::Favorites => "Favorites",
            Category::Logins => "Logins",
            Category::Notes => "Secure notes",
            Category::Cards => "Cards",
            Category::ApiKeys => "API keys",
            Category::Identities => "Identities",
            Category::Infrastructure => "Servers & databases",
            Category::Wifi => "Wi-Fi",
            Category::Custom => "Other",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Category::All => icons::SQUARES_FOUR,
            Category::Favorites => icons::STAR,
            Category::Logins => kind_icon(EntryKind::Login),
            Category::Notes => kind_icon(EntryKind::SecureNote),
            Category::Cards => kind_icon(EntryKind::CreditCard),
            Category::ApiKeys => kind_icon(EntryKind::ApiKey),
            Category::Identities => kind_icon(EntryKind::Identity),
            Category::Infrastructure => kind_icon(EntryKind::Server),
            Category::Wifi => kind_icon(EntryKind::Wifi),
            Category::Custom => kind_icon(EntryKind::Custom),
        }
    }

    /// Kinds offered by the "New" button on this page.
    pub fn kinds(self) -> &'static [EntryKind] {
        match self {
            Category::All | Category::Favorites => &EntryKind::ALL,
            Category::Logins => &[EntryKind::Login, EntryKind::Email],
            Category::Notes => &[EntryKind::SecureNote],
            Category::Cards => &[EntryKind::CreditCard],
            Category::ApiKeys => &[EntryKind::ApiKey],
            Category::Identities => &[EntryKind::Identity],
            Category::Infrastructure => &[EntryKind::Server, EntryKind::Database],
            Category::Wifi => &[EntryKind::Wifi],
            Category::Custom => &[EntryKind::Custom],
        }
    }

    pub fn includes(self, e: &Entry) -> bool {
        match self {
            Category::All => true,
            Category::Favorites => e.favorite,
            _ => self.kinds().contains(&e.kind),
        }
    }

    pub fn for_kind(kind: EntryKind) -> Category {
        Category::ALL
            .into_iter()
            .skip(2)
            .find(|c| c.kinds().contains(&kind))
            .unwrap_or(Category::All)
    }
}

pub struct Editor {
    pub entry: Entry,
    original: Entry,
    pub is_new: bool,
    reveal: HashMap<usize, Instant>,
    error: Option<String>,
}

impl Editor {
    fn new(entry: Entry, is_new: bool) -> Self {
        Editor {
            original: entry.clone(),
            entry,
            is_new,
            reveal: HashMap::new(),
            error: None,
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.entry != self.original
    }
}

#[derive(Default)]
pub struct ItemsState {
    pub selected: Option<u64>,
    pub search: String,
    pub editor: Option<Editor>,
    /// Revealed (entry, field) pairs and when they were revealed.
    revealed: HashMap<(u64, usize), Instant>,
}

impl ItemsState {
    pub fn select(&mut self, id: u64) {
        self.selected = Some(id);
        self.editor = None;
        self.revealed.clear();
    }

    pub fn new_entry(&mut self, kind: EntryKind) {
        self.selected = None;
        self.revealed.clear();
        self.editor = Some(Editor::new(Entry::new(kind), true));
    }

    /// Mask revealed secrets again once they have been visible for `timeout`.
    fn expire_reveals(&mut self, timeout: Duration, now: Instant) -> bool {
        let before = self.revealed.len();
        self.revealed
            .retain(|_, t| now.duration_since(*t) < timeout);
        let mut changed = self.revealed.len() != before;
        if let Some(ed) = &mut self.editor {
            let n = ed.reveal.len();
            ed.reveal.retain(|_, t| now.duration_since(*t) < timeout);
            changed |= ed.reveal.len() != n;
        }
        changed
    }

    fn any_revealed(&self) -> bool {
        !self.revealed.is_empty() || self.editor.as_ref().is_some_and(|e| !e.reveal.is_empty())
    }
}

enum Act {
    Nav(Nav),
    Edit(u64),
    Delete(u64),
    ToggleFav(u64),
    Copy(Zeroizing<String>, String),
    Reveal(u64, usize),
    Save,
}

pub fn show(ui: &mut egui::Ui, ms: &mut MainState, svc: &mut Services, cat: Category) {
    let mut acts = Vec::new();
    let now = Instant::now();
    let timeout = Duration::from_secs(u64::from(ms.vault.data().settings.reveal_timeout_secs));
    ms.items.expire_reveals(timeout, now);
    if ms.items.any_revealed() {
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }

    // Keyboard shortcuts.
    let editing = ms.items.editor.is_some() && ms.modal.is_none();
    let popup_open = egui::Popup::is_any_open(ui.ctx());
    let (find, new, save, escape) = ui.input_mut(|i| {
        (
            i.consume_key(Modifiers::COMMAND, Key::F),
            i.consume_key(Modifiers::COMMAND, Key::N),
            editing && i.consume_key(Modifiers::COMMAND, Key::S),
            editing && !popup_open && i.consume_key(Modifiers::NONE, Key::Escape),
        )
    });
    if find {
        ui.memory_mut(|m| m.request_focus(Id::new(SEARCH_ID)));
    }
    if new {
        acts.push(Act::Nav(Nav::New(cat, cat.kinds()[0])));
    }
    if save {
        acts.push(Act::Save);
    }
    if escape {
        acts.push(Act::Nav(Nav::CloseEditor));
    }

    let count = ms
        .vault
        .data()
        .entries
        .iter()
        .filter(|e| cat.includes(e))
        .count();
    widgets::page_header_with(
        ui,
        cat.label(),
        &format!("{count} item{}", if count == 1 { "" } else { "s" }),
        |ui| {
            let kinds = cat.kinds();
            if kinds.len() == 1 {
                if widgets::primary_button(ui, &icons::with(icons::PLUS, "New"))
                    .on_hover_text("Ctrl+N")
                    .clicked()
                {
                    acts.push(Act::Nav(Nav::New(cat, kinds[0])));
                }
            } else {
                let resp = widgets::primary_button(
                    ui,
                    &format!("{}  New  {}", icons::PLUS, icons::CARET_DOWN),
                );
                egui::Popup::menu(&resp).show(|ui| {
                    ui.set_min_width(180.0);
                    for k in kinds {
                        if ui.button(icons::with(kind_icon(*k), k.label())).clicked() {
                            acts.push(Act::Nav(Nav::New(cat, *k)));
                            ui.close();
                        }
                    }
                });
            }
        },
    );

    egui::SidePanel::left("items_list")
        .exact_width(310.0)
        .resizable(false)
        .show_separator_line(false)
        .frame(Frame::new().inner_margin(Margin {
            left: 0,
            right: 14,
            top: 0,
            bottom: 0,
        }))
        .show_inside(ui, |ui| list_ui(ui, ms, cat, &mut acts));

    egui::CentralPanel::default()
        .frame(Frame::new())
        .show_inside(ui, |ui| {
            let data = ms.vault.data();
            if let Some(ed) = &mut ms.items.editor {
                editor_ui(ui, ed, &data.settings.generator, &mut acts);
            } else if let Some(e) = ms.items.selected.and_then(|id| data.entry(id)) {
                detail_ui(ui, e, &ms.items.revealed, &ms.health, &mut acts);
            } else {
                empty_detail(ui, count == 0);
            }
        });

    for act in acts {
        apply(ms, svc, act);
    }
}

fn apply(ms: &mut MainState, svc: &mut Services, act: Act) {
    match act {
        Act::Nav(n) => ms.request(n),
        Act::Edit(id) => {
            if let Some(e) = ms.vault.data().entry(id) {
                ms.items.editor = Some(Editor::new(e.clone(), false));
            }
        }
        Act::Delete(id) => ms.modal = Some(Modal::DeleteEntry(id)),
        Act::ToggleFav(id) => {
            if let Some(e) = ms.vault.data_mut().entry_mut(id) {
                e.favorite = !e.favorite;
            }
            ms.commit(svc.toasts);
        }
        Act::Copy(value, what) => ms.copy_secret(svc, &value, &what),
        Act::Reveal(id, i) => {
            if ms.items.revealed.remove(&(id, i)).is_none() {
                ms.items.revealed.insert((id, i), Instant::now());
            }
        }
        Act::Save => {
            let Some(ed) = ms.items.editor.as_mut() else {
                return;
            };
            ed.entry.title = ed.entry.title.trim().to_string();
            if ed.entry.title.is_empty() {
                ed.error = Some("Enter a title.".into());
                return;
            }
            if ed.entry.fields.iter().any(|f| f.label.trim().is_empty()) {
                ed.error = Some("Every field needs a label.".into());
                return;
            }
            let entry = ed.entry.clone();
            let id = entry.id;
            let is_new = ed.is_new;
            ms.vault.data_mut().upsert(entry);
            if ms.commit(svc.toasts) {
                svc.toasts
                    .success(if is_new { "Item added" } else { "Saved" });
                ms.items.select(id);
            }
        }
    }
}

fn list_ui(ui: &mut egui::Ui, ms: &mut MainState, cat: Category, acts: &mut Vec<Act>) {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(RADIUS)
        .inner_margin(8.0)
        .show(ui, |ui| {
            ui.set_min_height(ui.available_height());
            ui.add(
                TextEdit::singleline(&mut ms.items.search)
                    .id(Id::new(SEARCH_ID))
                    .hint_text(format!("{}  Search", icons::MAGNIFYING_GLASS))
                    .desired_width(f32::INFINITY)
                    .margin(Vec2::new(10.0, 7.0)),
            )
            .on_hover_text("Ctrl+F");
            ui.add_space(4.0);
            let q = ms.items.search.trim().to_lowercase();
            let data = ms.vault.data();
            let mut list: Vec<&Entry> = data
                .entries
                .iter()
                .filter(|e| cat.includes(e) && e.matches(&q))
                .collect();
            list.sort_by(|a, b| {
                b.favorite
                    .cmp(&a.favorite)
                    .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
            });
            egui::ScrollArea::vertical()
                .id_salt("items_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    if list.is_empty() {
                        ui.add_space(24.0);
                        ui.vertical_centered(|ui| {
                            ui.label(faint(if q.is_empty() {
                                "Nothing here yet"
                            } else {
                                "No matches"
                            }));
                        });
                    }
                    for e in list {
                        let warn = if ms.health.is_weak(e.id) {
                            Some(DANGER)
                        } else if ms.health.is_reused(e.id) {
                            Some(WARN)
                        } else {
                            None
                        };
                        let selected = ms.items.selected == Some(e.id) && ms.items.editor.is_none();
                        let resp = entry_row(ui, e, selected, warn);
                        if resp.clicked() {
                            acts.push(Act::Nav(Nav::Select(e.id)));
                        }
                        resp.context_menu(|ui| quick_copy_menu(ui, e, acts));
                    }
                });
        });
}

/// Right-click menu on a list row.
fn quick_copy_menu(ui: &mut egui::Ui, e: &Entry, acts: &mut Vec<Act>) {
    ui.set_min_width(170.0);
    let mut any = false;
    for (kind, label) in [
        (FieldKind::Username, "Copy username"),
        (FieldKind::Email, "Copy email"),
        (FieldKind::Password, "Copy password"),
        (FieldKind::Url, "Copy website"),
    ] {
        if let Some(v) = e.first_of(kind) {
            any = true;
            if ui.button(icons::with(icons::COPY, label)).clicked() {
                acts.push(Act::Copy(
                    Zeroizing::new(v.to_string()),
                    label.trim_start_matches("Copy ").to_string(),
                ));
                ui.close();
            }
        }
    }
    if any {
        ui.separator();
    }
    if ui
        .button(icons::with(icons::PENCIL_SIMPLE, "Edit"))
        .clicked()
    {
        acts.push(Act::Nav(Nav::Select(e.id)));
        acts.push(Act::Edit(e.id));
        ui.close();
    }
    if ui.button(icons::with(icons::TRASH, "Delete…")).clicked() {
        acts.push(Act::Delete(e.id));
        ui.close();
    }
}

fn entry_row(
    ui: &mut egui::Ui,
    e: &Entry,
    selected: bool,
    warn: Option<egui::Color32>,
) -> egui::Response {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 46.0), Sense::click());
    let painter = ui.painter_at(rect);
    if selected {
        painter.rect_filled(rect, 6.0, SURFACE_2);
    } else if resp.hovered() {
        painter.rect_filled(rect, 6.0, ROW_HOVER);
    }
    let tile = Rect::from_center_size(rect.left_center() + Vec2::new(22.0, 0.0), Vec2::splat(30.0));
    widgets::kind_tile(ui, tile, kind_icon(e.kind));

    let mut right = rect.right() - 10.0;
    for (show, icon, color) in [
        (e.favorite, icons::STAR, TEXT_FAINT),
        (warn.is_some(), icons::WARNING, warn.unwrap_or(WARN)),
    ] {
        if show {
            painter.text(
                egui::pos2(right, rect.center().y),
                Align2::RIGHT_CENTER,
                icon,
                FontId::proportional(13.0),
                color,
            );
            right -= 18.0;
        }
    }
    let tp = ui.painter_at(Rect::from_min_max(
        rect.min,
        egui::pos2(right - 4.0, rect.max.y),
    ));
    let x = tile.right() + 10.0;
    let sub = e.subtitle();
    let (ty, sy) = if sub.is_empty() {
        (0.0, 0.0)
    } else {
        (-8.0, 9.0)
    };
    tp.text(
        egui::pos2(x, rect.center().y + ty),
        Align2::LEFT_CENTER,
        e.display_title(),
        FontId::proportional(14.0),
        TEXT,
    );
    if !sub.is_empty() {
        tp.text(
            egui::pos2(x, rect.center().y + sy),
            Align2::LEFT_CENTER,
            sub,
            FontId::proportional(12.0),
            TEXT_FAINT,
        );
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

fn empty_detail(ui: &mut egui::Ui, vault_page_empty: bool) {
    card(ui, |ui| {
        ui.set_min_height(ui.available_height());
        ui.add_space(ui.available_height() * 0.35);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(icons::VAULT).size(32.0).color(TEXT_FAINT));
            ui.add_space(4.0);
            ui.label(dim(if vault_page_empty {
                "Add your first item with New (Ctrl+N)."
            } else {
                "Select an item to see its details."
            }));
        });
    });
}

fn header_row(
    ui: &mut egui::Ui,
    icon: &str,
    title: &str,
    subtitle: &str,
    right: impl FnOnce(&mut egui::Ui),
) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
        let p = ui.painter();
        p.rect_filled(rect, 8.0, SURFACE_2);
        p.text(
            rect.center(),
            Align2::CENTER_CENTER,
            icon,
            FontId::proportional(20.0),
            ACCENT,
        );
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.add(egui::Label::new(strong(title, 18.0)).truncate());
            ui.label(faint(subtitle));
        });
        ui.with_layout(Layout::right_to_left(Align::Center), right);
    });
}

fn detail_ui(
    ui: &mut egui::Ui,
    e: &Entry,
    revealed: &HashMap<(u64, usize), Instant>,
    health: &HealthReport,
    acts: &mut Vec<Act>,
) {
    card(ui, |ui| {
        ui.set_min_height(ui.available_height());
        header_row(
            ui,
            kind_icon(e.kind),
            e.display_title(),
            e.kind.label(),
            |ui| {
                if widgets::icon_button(ui, icons::TRASH, "Delete").clicked() {
                    acts.push(Act::Delete(e.id));
                }
                if widgets::icon_button(ui, icons::PENCIL_SIMPLE, "Edit").clicked() {
                    acts.push(Act::Edit(e.id));
                }
                let fav_tip = if e.favorite {
                    "Remove from favorites"
                } else {
                    "Add to favorites"
                };
                if widgets::toggle_icon(ui, e.favorite, icons::STAR, fav_tip).clicked() {
                    acts.push(Act::ToggleFav(e.id));
                }
            },
        );
        let weak = health.is_weak(e.id);
        let reused = health.is_reused(e.id);
        if weak || reused {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if weak {
                    widgets::pill(ui, "Weak password", DANGER);
                }
                if reused {
                    widgets::pill(ui, "Reused password", WARN);
                }
            });
        }
        ui.add_space(6.0);
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("detail_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(6.0);
                let shown: Vec<(usize, &Field)> = e
                    .fields
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| !f.value.is_empty())
                    .collect();
                if !shown.is_empty() {
                    widgets::group(ui, |ui| {
                        for (n, (i, f)) in shown.iter().enumerate() {
                            if n > 0 {
                                widgets::divider(ui, 14.0);
                            }
                            field_view(ui, e.id, *i, f, revealed.contains_key(&(e.id, *i)), acts);
                        }
                    });
                }
                if !e.notes.is_empty() {
                    ui.add_space(10.0);
                    widgets::group(ui, |ui| {
                        widgets::trailing_row(
                            ui,
                            Align::Center,
                            |ui| {
                                if widgets::icon_button(ui, icons::COPY, "Copy").clicked() {
                                    acts.push(Act::Copy(
                                        Zeroizing::new(e.notes.clone()),
                                        "Note".into(),
                                    ));
                                }
                            },
                            |ui| {
                                ui.add_space(7.0);
                                ui.label(faint(if e.kind == EntryKind::SecureNote {
                                    "Note"
                                } else {
                                    "Notes"
                                }));
                            },
                        );
                        ui.add(egui::Label::new(RichText::new(&e.notes).color(TEXT)).wrap());
                        ui.add_space(6.0);
                    });
                }
                if shown.is_empty() && e.notes.is_empty() {
                    ui.label(dim("Empty. Use Edit to add details."));
                }
                ui.add_space(14.0);
                let mut meta = format!(
                    "Created {}  ·  Updated {}",
                    format_date(e.created),
                    format_date(e.modified)
                );
                if e.primary_password().is_some() {
                    meta.push_str(&format!(
                        "  ·  Password changed {}",
                        age_description(e.password_changed, now_unix())
                    ));
                }
                ui.label(faint(meta));
            });
    });
}

fn field_view(
    ui: &mut egui::Ui,
    id: u64,
    i: usize,
    f: &Field,
    revealed: bool,
    acts: &mut Vec<Act>,
) {
    let concealed = f.kind.is_concealed() && !revealed;
    let tall = !concealed && f.value.contains('\n');
    let strength = (f.kind == FieldKind::Password).then(|| estimate_strength(&f.value));
    widgets::trailing_row_h(
        ui,
        42.0,
        if tall { Align::Min } else { Align::Center },
        |ui| {
            if widgets::icon_button(ui, icons::COPY, "Copy").clicked() {
                acts.push(Act::Copy(Zeroizing::new(f.value.clone()), f.label.clone()));
            }
            if f.kind.is_concealed() {
                let icon = if revealed {
                    icons::EYE_SLASH
                } else {
                    icons::EYE
                };
                if widgets::toggle_icon(
                    ui,
                    revealed,
                    icon,
                    if revealed { "Hide" } else { "Reveal" },
                )
                .clicked()
                {
                    acts.push(Act::Reveal(id, i));
                }
            }
        },
        |ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(faint(&f.label));
                if let Some(r) = &strength {
                    let color = strength_color(r.strength);
                    ui.label(RichText::new("·").size(12.0).color(TEXT_FAINT));
                    ui.label(RichText::new(r.strength.label()).size(12.0).color(color));
                }
            });
            let text = if concealed {
                MASK.to_string()
            } else {
                f.value.clone()
            };
            let mut rt = RichText::new(text).size(14.5).color(TEXT);
            if f.kind.is_concealed() {
                rt = rt.family(egui::FontFamily::Monospace);
            }
            ui.add(egui::Label::new(rt).wrap());
            ui.add_space(2.0);
        },
    );
}

enum FieldOp {
    Remove(usize),
    Up(usize),
    Down(usize),
    Reveal(usize),
    Generate(usize),
}

fn editor_ui(ui: &mut egui::Ui, ed: &mut Editor, gen: &GeneratorOptions, acts: &mut Vec<Act>) {
    card(ui, |ui| {
        ui.set_min_height(ui.available_height());
        let title = if ed.is_new {
            format!("New {}", ed.entry.kind.noun())
        } else {
            "Edit".to_string()
        };
        let subtitle = if ed.is_dirty() {
            "Unsaved changes"
        } else {
            ed.entry.kind.label()
        };
        header_row(ui, kind_icon(ed.entry.kind), &title, subtitle, |ui| {
            if widgets::secondary_button(ui, "Cancel")
                .on_hover_text("Esc")
                .clicked()
            {
                acts.push(Act::Nav(Nav::CloseEditor));
            }
            if widgets::primary_button(ui, "Save")
                .on_hover_text("Ctrl+S")
                .clicked()
            {
                acts.push(Act::Save);
            }
        });
        ui.add_space(6.0);
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("editor_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.label(small("Title"));
                let r = widgets::text_input(ui, &mut ed.entry.title, "");
                if ed.is_new && ed.entry.title.is_empty() && !ui.ctx().memory(|m| m.has_focus(r.id))
                {
                    r.request_focus();
                }
                ui.add_space(6.0);

                let mut ops = Vec::new();
                let n = ed.entry.fields.len();
                if n > 0 {
                    widgets::group(ui, |ui| {
                        for (i, f) in ed.entry.fields.iter_mut().enumerate() {
                            if i > 0 {
                                widgets::divider(ui, 14.0);
                            }
                            field_editor(ui, i, n, f, ed.reveal.contains_key(&i), &mut ops);
                        }
                    });
                    ui.add_space(2.0);
                }
                for op in ops {
                    match op {
                        FieldOp::Remove(i) => {
                            ed.entry.fields.remove(i);
                            ed.reveal.clear();
                        }
                        FieldOp::Up(i) if i > 0 => {
                            ed.entry.fields.swap(i, i - 1);
                            ed.reveal.clear();
                        }
                        FieldOp::Down(i) if i + 1 < ed.entry.fields.len() => {
                            ed.entry.fields.swap(i, i + 1);
                            ed.reveal.clear();
                        }
                        FieldOp::Reveal(i) => {
                            if ed.reveal.remove(&i).is_none() {
                                ed.reveal.insert(i, Instant::now());
                            }
                        }
                        FieldOp::Generate(i) => match generate_password(gen) {
                            Ok(pw) => {
                                let f = &mut ed.entry.fields[i];
                                f.value.zeroize();
                                f.value.push_str(&pw);
                                ed.reveal.insert(i, Instant::now());
                            }
                            Err(e) => ed.error = Some(e.to_string()),
                        },
                        _ => {}
                    }
                }

                let add = widgets::link_button(ui, &icons::with(icons::PLUS, "Add field"));
                egui::Popup::menu(&add).show(|ui| {
                    ui.set_min_width(170.0);
                    for k in FieldKind::ALL {
                        if ui.button(k.label()).clicked() {
                            let label = match k {
                                FieldKind::Password => "Password",
                                FieldKind::Username => "Username",
                                FieldKind::Email => "Email",
                                FieldKind::Url => "Website",
                                _ => "Field",
                            };
                            ed.entry.fields.push(Field::new(label, k));
                            ui.close();
                        }
                    }
                });
                ui.add_space(8.0);

                let is_note = ed.entry.kind == EntryKind::SecureNote;
                ui.label(small(if is_note { "Note" } else { "Notes" }));
                ui.add(
                    TextEdit::multiline(&mut ed.entry.notes)
                        .desired_rows(if is_note { 14 } else { 3 })
                        .desired_width(f32::INFINITY)
                        .margin(Vec2::new(10.0, 7.0)),
                );
                if let Some(e) = &ed.error {
                    ui.add_space(6.0);
                    widgets::error_text(ui, e);
                }
            });
    });
}

fn field_editor(
    ui: &mut egui::Ui,
    i: usize,
    n: usize,
    f: &mut Field,
    reveal: bool,
    ops: &mut Vec<FieldOp>,
) {
    ui.horizontal(|ui| {
        ui.add(
            TextEdit::singleline(&mut f.label)
                .desired_width(180.0)
                .hint_text("Label")
                .font(TextStyle::Small)
                .text_color(TEXT_DIM)
                .frame(false)
                .margin(Vec2::new(0.0, 4.0)),
        );
        // A quiet, frameless type picker: text plus caret.
        ui.scope(|ui| {
            let w = &mut ui.visuals_mut().widgets;
            w.inactive.weak_bg_fill = egui::Color32::TRANSPARENT;
            w.inactive.bg_stroke = Stroke::NONE;
            w.inactive.fg_stroke = Stroke::new(1.0, TEXT_FAINT);
            egui::ComboBox::from_id_salt(("field_kind", i))
                .width(110.0)
                .icon(widgets::combo_caret)
                .selected_text(faint(f.kind.label()))
                .show_ui(ui, |ui| {
                    for k in FieldKind::ALL {
                        ui.selectable_value(&mut f.kind, k, k.label());
                    }
                });
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if widgets::icon_button(ui, icons::X, "Remove field").clicked() {
                ops.push(FieldOp::Remove(i));
            }
            if i + 1 < n && widgets::icon_button(ui, icons::CARET_DOWN, "Move down").clicked() {
                ops.push(FieldOp::Down(i));
            }
            if i > 0 && widgets::icon_button(ui, icons::CARET_UP, "Move up").clicked() {
                ops.push(FieldOp::Up(i));
            }
        });
    });
    let concealed = f.kind.is_concealed() && !reveal;
    let kind = f.kind;
    widgets::trailing_row(
        ui,
        Align::Min,
        |ui| {
            if kind == FieldKind::Password
                && widgets::icon_button(ui, icons::DICE_FIVE, "Generate a strong password")
                    .clicked()
            {
                ops.push(FieldOp::Generate(i));
            }
            if kind.is_concealed() {
                let icon = if reveal { icons::EYE_SLASH } else { icons::EYE };
                if widgets::toggle_icon(ui, reveal, icon, if reveal { "Hide" } else { "Reveal" })
                    .clicked()
                {
                    ops.push(FieldOp::Reveal(i));
                }
            }
        },
        |ui| {
            if kind.is_multiline() {
                if concealed {
                    ui.add_space(6.0);
                    ui.label(faint("Hidden — reveal to view or edit"));
                } else {
                    ui.add(
                        TextEdit::multiline(&mut f.value)
                            .desired_rows(4)
                            .desired_width(f32::INFINITY)
                            .font(TextStyle::Monospace)
                            .margin(Vec2::new(10.0, 7.0)),
                    );
                }
            } else {
                let mut te = TextEdit::singleline(&mut f.value)
                    .password(concealed)
                    .desired_width(f32::INFINITY)
                    .margin(Vec2::new(10.0, 7.0));
                if kind.is_concealed() {
                    te = te.font(TextStyle::Monospace);
                }
                ui.add(te);
            }
        },
    );
    if f.kind == FieldKind::Password && !f.value.is_empty() {
        widgets::strength_meter(ui, &estimate_strength(&f.value));
    }
    ui.add_space(2.0);
}
