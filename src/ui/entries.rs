//! Item manager: list, detail view and editor for every entry type.
//!
//! Shortcuts: Ctrl+F search, Ctrl+N new item, Ctrl+S save, Esc close editor
//! (or clear a multiple selection), Ctrl+K quick open (from anywhere).
//! Ctrl+click, Shift+click and Ctrl+A select several items for tagging,
//! favoriting or moving to the trash together.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Align2, CursorIcon, FontId, Frame, Id, Key, Layout, Margin, Modifiers, Rect,
    RichText, Sense, Stroke, TextEdit, TextStyle, Vec2,
};
use zeroize::{Zeroize, Zeroizing};

use super::icons::{self, kind_icon};
use super::main_view::BreachReport;
use super::main_view::{MainState, Nav};
use super::theme::*;
use super::widgets::{self, card, MASK};
use super::Services;
use crate::analysis::{estimate_strength, HealthReport};
use crate::generator::generate_password;
use crate::i18n::{plural, tr};
use crate::model::{Entry, EntryKind, Field, FieldKind, SortOrder, VaultSettings};
use crate::timeutil::{age_description, expiry_description, format_date, now_unix, parse_iso8601};
use crate::totp::{format_code, Totp};
use crate::trf;

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
            Category::All => tr("All items"),
            Category::Favorites => tr("Favorites"),
            Category::Logins => tr("Logins"),
            Category::Notes => tr("Secure notes"),
            Category::Cards => tr("Cards"),
            Category::ApiKeys => tr("API keys"),
            Category::Identities => tr("Identities"),
            Category::Infrastructure => tr("Servers & databases"),
            Category::Wifi => "Wi-Fi",
            Category::Custom => tr("Other"),
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
    tag_input: String,
    /// The expiry date as typed (YYYY-MM-DD, "" = never).
    expiry_text: String,
}

impl Editor {
    fn new(entry: Entry, is_new: bool) -> Self {
        let expiry_text = if entry.expires > 0 {
            format_date(entry.expires)
        } else {
            String::new()
        };
        Editor {
            original: entry.clone(),
            entry,
            is_new,
            reveal: HashMap::new(),
            error: None,
            tag_input: String::new(),
            expiry_text,
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.entry != self.original
    }

    /// An editor holding `entry`, compared against `original` for unsaved
    /// changes (used when VaultRust fills something in for the user).
    pub fn prefilled(original: Entry, entry: Entry, is_new: bool) -> Self {
        let mut ed = Editor::new(entry, is_new);
        ed.original = original;
        ed
    }
}

#[derive(Default)]
pub struct ItemsState {
    pub selected: Option<u64>,
    pub search: String,
    pub editor: Option<Editor>,
    /// Revealed (entry, field) pairs and when they were revealed. History
    /// items use field indices from [`HISTORY_BASE`] up.
    revealed: HashMap<(u64, usize), Instant>,
    /// Items selected together (Ctrl+click, Shift+click, Ctrl+A), in the
    /// order they were picked. Two or more replace the detail view with the
    /// bulk actions.
    picked: Vec<u64>,
    /// Where a Shift+click range starts.
    anchor: Option<u64>,
    /// Tag typed into the bulk actions.
    bulk_tag: String,
}

/// Reveal-state key offset for password-history rows.
const HISTORY_BASE: usize = 10_000;

impl ItemsState {
    pub fn select(&mut self, id: u64) {
        self.selected = Some(id);
        self.editor = None;
        self.revealed.clear();
        self.picked.clear();
        self.anchor = Some(id);
    }

    pub fn new_entry(&mut self, kind: EntryKind) {
        self.selected = None;
        self.revealed.clear();
        self.picked.clear();
        self.editor = Some(Editor::new(Entry::new(kind), true));
    }

    /// The items selected together (empty unless two or more are).
    pub fn picked(&self) -> &[u64] {
        if self.picked.len() > 1 {
            &self.picked
        } else {
            &[]
        }
    }

    pub fn clear_picked(&mut self) {
        self.picked.clear();
        self.bulk_tag.clear();
    }

    /// Select `ids` together (just one of them: select it normally).
    pub fn pick_many(&mut self, ids: Vec<u64>) {
        match ids.as_slice() {
            [] => self.clear_picked(),
            [one] => self.select(*one),
            _ => {
                self.editor = None;
                self.revealed.clear();
                self.picked = ids;
            }
        }
    }

    /// Ctrl+click: add or remove one item. The item shown before joins the
    /// selection, so Ctrl+clicking a second item selects both.
    fn toggle_pick(&mut self, id: u64) {
        if self.picked.is_empty() {
            if let Some(s) = self.selected.filter(|s| *s != id) {
                self.picked.push(s);
            }
        }
        match self.picked.iter().position(|p| *p == id) {
            Some(i) => {
                self.picked.remove(i);
            }
            None => self.picked.push(id),
        }
        self.anchor = Some(id);
        let picked = std::mem::take(&mut self.picked);
        if picked.is_empty() {
            self.selected = None;
            self.editor = None;
        } else {
            self.pick_many(picked);
            self.anchor = Some(id);
        }
    }

    /// Shift+click: everything in `visible` between the anchor and `id`.
    fn pick_range(&mut self, id: u64, visible: &[u64]) {
        let from = self.anchor.or(self.selected).unwrap_or(id);
        let (Some(a), Some(b)) = (
            visible.iter().position(|x| *x == from),
            visible.iter().position(|x| *x == id),
        ) else {
            return self.select(id);
        };
        let (lo, hi) = (a.min(b), a.max(b));
        let anchor = self.anchor;
        self.pick_many(visible[lo..=hi].to_vec());
        self.anchor = anchor.or(Some(from));
    }

    fn is_picked(&self, id: u64) -> bool {
        self.picked().contains(&id)
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
    /// Value, what it is, and the entry it came from.
    Copy(Zeroizing<String>, String, u64),
    Reveal(u64, usize),
    Sort(SortOrder),
    Save,
    /// Write an attachment (entry, index) to a file the user picks.
    SaveAttachment(u64, usize),
    /// Pick a file and attach it to the item being edited.
    Attach,
    /// Look for a two-step verification QR code on screen.
    ScanQr,
    /// Ctrl+click on a list row.
    TogglePick(u64),
    /// Shift+click on a list row, with the rows in list order.
    PickRange(u64, Vec<u64>),
    PickAll(Vec<u64>),
    ClearPicked,
    Bulk(Bulk),
    /// Edit the password rules of the site the edited item is on.
    EditSiteRule(String),
}

/// A change made to every selected item at once.
enum Bulk {
    Favorite(bool),
    AddTag(String),
    RemoveTag(String),
    Trash,
}

/// Whether an entry belongs on a page showing `cat`, optionally narrowed to
/// one tag.
fn on_page(e: &Entry, cat: Category, tag: Option<&str>) -> bool {
    cat.includes(e) && tag.is_none_or(|t| e.tags.iter().any(|x| x.eq_ignore_ascii_case(t)))
}

pub fn show(
    ui: &mut egui::Ui,
    ms: &mut MainState,
    svc: &mut Services,
    cat: Category,
    tag: Option<&str>,
) {
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
    let picking = !ms.items.picked().is_empty() && ms.modal.is_none();
    let (find, new, save, escape, unpick) = ui.input_mut(|i| {
        (
            i.consume_key(Modifiers::COMMAND, Key::F),
            i.consume_key(Modifiers::COMMAND, Key::N),
            editing && i.consume_key(Modifiers::COMMAND, Key::S),
            editing && !popup_open && i.consume_key(Modifiers::NONE, Key::Escape),
            picking && !popup_open && i.consume_key(Modifiers::NONE, Key::Escape),
        )
    });
    if unpick {
        acts.push(Act::ClearPicked);
    }
    if find {
        ui.memory_mut(|m| m.request_focus(Id::new(SEARCH_ID)));
    }
    if new {
        acts.push(Act::Nav(Nav::New(cat, cat.kinds()[0])));
    }
    let title = match tag {
        Some(t) => format!("{}  {t}", icons::TAG_SIMPLE),
        None => cat.label().to_string(),
    };
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
        .filter(|e| on_page(e, cat, tag))
        .count();
    widgets::page_header_with(ui, &title, &plural(count, "{n} item", "{n} items"), |ui| {
        let kinds = cat.kinds();
        if kinds.len() == 1 {
            if widgets::primary_button(ui, &icons::with(icons::PLUS, tr("New")))
                .on_hover_text("Ctrl+N")
                .clicked()
            {
                acts.push(Act::Nav(Nav::New(cat, kinds[0])));
            }
        } else {
            let resp =
                widgets::primary_button(ui, &trf!("{}  New  {}", icons::PLUS, icons::CARET_DOWN));
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
    });

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
        .show_inside(ui, |ui| list_ui(ui, ms, cat, tag, &mut acts));

    egui::CentralPanel::default()
        .frame(Frame::new())
        .show_inside(ui, |ui| {
            let data = ms.vault.data();
            if let Some(ed) = &mut ms.items.editor {
                let suggest = Suggestions::from_vault(data);
                let scanning = ms.qr_job.is_some();
                editor_ui(ui, ed, &data.settings, &suggest, scanning, &mut acts);
            } else if !ms.items.picked.is_empty() && ms.items.picked().len() > 1 {
                let picked = ms.items.picked.clone();
                bulk_ui(ui, data, &picked, &mut ms.items.bulk_tag, &mut acts);
            } else if let Some(e) = ms.items.selected.and_then(|id| data.entry(id)) {
                let breach = ms.breach.report.as_ref();
                detail_ui(ui, e, &ms.items.revealed, &ms.health, breach, &mut acts);
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
        Act::Delete(id) => ms.trash(svc, id),
        Act::ToggleFav(id) => {
            if let Some(e) = ms.vault.data_mut().entry_mut(id) {
                e.favorite = !e.favorite;
            }
            ms.commit(svc.toasts);
        }
        Act::Copy(value, what, id) => ms.copy_from(svc, id, &value, &what),
        Act::Sort(order) => {
            ms.vault.data_mut().settings.sort = order;
            ms.schedule_settings_save();
        }
        Act::Reveal(id, i) => {
            if ms.items.revealed.remove(&(id, i)).is_none() {
                ms.items.revealed.insert((id, i), Instant::now());
            }
        }
        Act::SaveAttachment(id, i) => save_attachment(ms, svc, id, i),
        Act::Attach => attach_file(ms),
        Act::ScanQr => ms.qr_requested = true,
        Act::TogglePick(id) => ms.items.toggle_pick(id),
        Act::PickRange(id, visible) => ms.items.pick_range(id, &visible),
        Act::PickAll(ids) => ms.items.pick_many(ids),
        Act::ClearPicked => ms.items.clear_picked(),
        Act::Bulk(op) => apply_bulk(ms, svc, op),
        Act::EditSiteRule(url) => {
            let settings = &ms.vault.data().settings;
            let host = crate::autotype::url_host(&url);
            let existing = settings.site_rules.iter().find(|r| r.host == host);
            let options = existing.map_or_else(
                || settings.generator_for(Some(&url)).clone(),
                |r| r.options.clone(),
            );
            ms.modal = Some(super::modals::Modal::SiteRule(
                super::modals::SiteRuleState::new(host, options, existing.is_some()),
            ));
        }
        Act::Save => {
            let Some(ed) = ms.items.editor.as_mut() else {
                return;
            };
            ed.entry.title = ed.entry.title.trim().to_string();
            if ed.entry.title.is_empty() {
                ed.entry.title = automatic_title(&ed.entry);
            }
            if ed.entry.title.is_empty() {
                ed.error = Some(tr("Enter a title (or a website, and it's named for you).").into());
                return;
            }
            if ed.entry.fields.iter().any(|f| f.label.trim().is_empty()) {
                ed.error = Some(tr("Every field needs a label.").into());
                return;
            }
            if !ed.tag_input.trim().is_empty() {
                let pending = std::mem::take(&mut ed.tag_input);
                for t in pending.split([',', ';']) {
                    ed.entry.add_tag(t);
                }
            }
            if !ed.entry.auto_type.trim().is_empty() {
                if let Err(err) = crate::autotype::parse_sequence(&ed.entry.auto_type) {
                    ed.error = Some(trf!("Auto-type sequence: {err}", err));
                    return;
                }
            }
            match parse_expiry(&ed.expiry_text) {
                Ok(at) => ed.entry.expires = at,
                Err(()) => {
                    ed.error =
                        Some(tr("Enter the expiry date as YYYY-MM-DD, or leave it empty.").into());
                    return;
                }
            }
            if let Some(bad) = ed.entry.fields.iter().find(|f| {
                f.kind == FieldKind::Totp
                    && !f.value.trim().is_empty()
                    && Totp::parse(&f.value).is_err()
            }) {
                ed.error = Some(trf!("“{}” is not a valid one-time code secret.", bad.label));
                return;
            }
            let entry = ed.entry.clone();
            let id = entry.id;
            let is_new = ed.is_new;
            ms.vault.data_mut().upsert(entry);
            if ms.commit(svc.toasts) {
                svc.toasts.success(if is_new {
                    tr("Item added")
                } else {
                    tr("Saved")
                });
                ms.items.select(id);
            }
        }
    }
}

fn apply_bulk(ms: &mut MainState, svc: &mut Services, op: Bulk) {
    let ids = ms.items.picked().to_vec();
    if ids.is_empty() {
        return;
    }
    if let Bulk::Trash = op {
        return ms.trash_many(svc, &ids);
    }
    let now = now_unix();
    let mut changed = 0;
    for id in &ids {
        let Some(e) = ms.vault.data_mut().entry_mut(*id) else {
            continue;
        };
        let did = match &op {
            Bulk::Favorite(on) => std::mem::replace(&mut e.favorite, *on) != *on,
            Bulk::AddTag(t) => e.add_tag(t),
            Bulk::RemoveTag(t) => {
                let before = e.tags.len();
                e.tags.retain(|x| !x.eq_ignore_ascii_case(t));
                e.tags.len() != before
            }
            Bulk::Trash => false,
        };
        if did {
            e.modified = now;
            changed += 1;
        }
    }
    if changed == 0 || !ms.commit(svc.toasts) {
        return;
    }
    let msg = match &op {
        Bulk::Favorite(true) => plural(
            changed,
            tr("Added {n} item to favorites"),
            tr("Added {n} items to favorites"),
        ),
        Bulk::Favorite(false) => plural(
            changed,
            tr("Removed {n} item from favorites"),
            tr("Removed {n} items from favorites"),
        ),
        Bulk::AddTag(tag) => crate::i18n::format(
            &plural(
                changed,
                tr("Tagged {n} item “{tag}”"),
                tr("Tagged {n} items “{tag}”"),
            ),
            &[("tag", &tag.trim())],
        ),
        Bulk::RemoveTag(tag) => crate::i18n::format(
            &plural(
                changed,
                tr("Removed “{tag}” from {n} item"),
                tr("Removed “{tag}” from {n} items"),
            ),
            &[("tag", tag)],
        ),
        Bulk::Trash => String::new(),
    };
    svc.toasts.success(msg);
    if let Bulk::AddTag(_) = op {
        ms.items.bulk_tag.clear();
    }
}

/// The detail pane while several items are selected: what they are, and
/// what can be done to all of them at once.
fn bulk_ui(
    ui: &mut egui::Ui,
    data: &crate::model::VaultData,
    picked: &[u64],
    tag_input: &mut String,
    acts: &mut Vec<Act>,
) {
    let items: Vec<&Entry> = picked.iter().filter_map(|id| data.entry(*id)).collect();
    card(ui, |ui| {
        ui.set_min_height(ui.available_height());
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
            ui.painter().rect_filled(rect, 8.0, accent_bg());
            ui.painter().text(
                rect.center(),
                Align2::CENTER_CENTER,
                icons::CHECKS,
                FontId::proportional(20.0),
                accent(),
            );
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.label(strong(
                    plural(
                        items.len(),
                        tr("{n} item selected"),
                        tr("{n} items selected"),
                    ),
                    18.0,
                ));
                ui.label(faint(tr(
                    "Ctrl+click to add or remove items, Shift+click for a range",
                )));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::secondary_button(ui, tr("Clear selection"))
                    .on_hover_text("Esc")
                    .clicked()
                {
                    acts.push(Act::ClearPicked);
                }
            });
        });
        ui.add_space(6.0);
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("bulk_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(6.0);
                widgets::group(ui, |ui| {
                    ui.add_space(7.0);
                    ui.label(faint(tr("Favorites")));
                    ui.horizontal(|ui| {
                        let all_fav = items.iter().all(|e| e.favorite);
                        let none_fav = items.iter().all(|e| !e.favorite);
                        if ui
                            .add_enabled(
                                !all_fav,
                                egui::Button::new(icons::with(icons::STAR, tr("Add to favorites"))),
                            )
                            .clicked()
                        {
                            acts.push(Act::Bulk(Bulk::Favorite(true)));
                        }
                        if ui
                            .add_enabled(!none_fav, egui::Button::new(tr("Remove from favorites")))
                            .clicked()
                        {
                            acts.push(Act::Bulk(Bulk::Favorite(false)));
                        }
                    });
                    ui.add_space(6.0);
                });
                ui.add_space(10.0);
                widgets::group(ui, |ui| {
                    ui.add_space(7.0);
                    ui.label(faint(tr("Tags")));
                    ui.horizontal(|ui| {
                        let resp = ui.add(
                            TextEdit::singleline(tag_input)
                                .hint_text(hint(tr("Tag to add…")))
                                .desired_width(200.0)
                                .margin(Vec2::new(8.0, 5.0)),
                        );
                        let entered = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                        let ok = !tag_input.trim().is_empty();
                        if (ui
                            .add_enabled(
                                ok,
                                egui::Button::new(icons::with(icons::PLUS, tr("Add tag"))),
                            )
                            .clicked()
                            || entered)
                            && ok
                        {
                            acts.push(Act::Bulk(Bulk::AddTag(tag_input.trim().to_string())));
                        }
                    });
                    // Tags already on some of the selected items: one click
                    // adds them to the rest, the x removes them from all.
                    let mut tags: Vec<(String, usize)> = Vec::new();
                    for t in items.iter().flat_map(|e| e.tags.iter()) {
                        match tags.iter_mut().find(|(x, _)| x.eq_ignore_ascii_case(t)) {
                            Some((_, n)) => *n += 1,
                            None => tags.push((t.clone(), 1)),
                        }
                    }
                    tags.sort_by_key(|(t, _)| t.to_lowercase());
                    if !tags.is_empty() {
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing = Vec2::new(6.0, 6.0);
                            for (t, n) in &tags {
                                let label = if *n == items.len() {
                                    t.clone()
                                } else {
                                    format!("{t} ({n}/{})", items.len())
                                };
                                if widgets::tag_chip_removable(ui, &label) {
                                    acts.push(Act::Bulk(Bulk::RemoveTag(t.clone())));
                                }
                            }
                        });
                        ui.label(faint(tr("The × removes a tag from every selected item")));
                    }
                    ui.add_space(6.0);
                });
                ui.add_space(10.0);
                if widgets::danger_button(
                    ui,
                    &icons::with(
                        icons::TRASH,
                        &plural(
                            items.len(),
                            tr("Move {n} item to Trash"),
                            tr("Move {n} items to Trash"),
                        ),
                    ),
                )
                .clicked()
                {
                    acts.push(Act::Bulk(Bulk::Trash));
                }
                ui.add_space(14.0);
                ui.label(faint(tr("Selected")));
                ui.add_space(2.0);
                for e in &items {
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
                        widgets::entry_tile(ui, rect, e);
                        ui.add(
                            egui::Label::new(RichText::new(e.display_title()).color(text()))
                                .truncate(),
                        );
                    });
                }
            });
    });
}

fn save_attachment(ms: &mut MainState, svc: &mut Services, id: u64, i: usize) {
    let Some(a) = ms
        .vault
        .data()
        .entry(id)
        .and_then(|e| e.attachments.get(i))
        .cloned()
    else {
        return;
    };
    let Some(path) = rfd::FileDialog::new()
        .set_title(tr("Save attachment"))
        .set_file_name(a.safe_name())
        .save_file()
    else {
        return;
    };
    match std::fs::write(&path, &a.data) {
        Ok(()) => {
            ms.vault
                .data_mut()
                .log(crate::model::AuditKind::AttachmentSaved, &a.name);
            ms.commit(svc.toasts);
            svc.toasts
                .success(trf!("Saved “{}” — that copy is not encrypted", a.name));
        }
        Err(e) => svc.toasts.error(trf!("Couldn't save the file: {e}", e)),
    }
}

fn attach_file(ms: &mut MainState) {
    use crate::model::{Attachment, MAX_ATTACHMENT_BYTES, MAX_TOTAL_ATTACHMENT_BYTES};
    let Some(ed) = ms.items.editor.as_ref() else {
        return;
    };
    // Space used by everything except this item's stored attachments, which
    // the editor's copy replaces on save.
    let stored: usize = ms
        .vault
        .data()
        .entry(ed.entry.id)
        .map(|e| e.attachments.iter().map(|a| a.data.len()).sum())
        .unwrap_or(0);
    let others = ms.vault.data().attachment_bytes() - stored;
    let Some(path) = rfd::FileDialog::new()
        .set_title(tr("Attach a file"))
        .pick_file()
    else {
        return;
    };
    let Some(ed) = ms.items.editor.as_mut() else {
        return;
    };
    let mine: usize = ed.entry.attachments.iter().map(|a| a.data.len()).sum();
    let mb = |n: usize| n / (1024 * 1024);
    let len = std::fs::metadata(&path)
        .map(|m| m.len())
        .unwrap_or(u64::MAX);
    if len > MAX_ATTACHMENT_BYTES as u64 {
        ed.error = Some(trf!(
            "Files up to {} MB can be attached.",
            mb(MAX_ATTACHMENT_BYTES)
        ));
        return;
    }
    if others + mine + len as usize > MAX_TOTAL_ATTACHMENT_BYTES {
        ed.error = Some(trf!(
            "Attachments in a vault are limited to {} MB in total.",
            mb(MAX_TOTAL_ATTACHMENT_BYTES)
        ));
        return;
    }
    match std::fs::read(&path) {
        Ok(data) if data.len() <= MAX_ATTACHMENT_BYTES => {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "attachment".into());
            ed.entry.attachments.push(Attachment {
                name,
                data,
                added: now_unix(),
            });
            ed.error = None;
        }
        Ok(_) => ed.error = Some(tr("The file changed while it was being read.").into()),
        Err(e) => ed.error = Some(trf!("Couldn't read the file: {e}", e)),
    }
}

/// One attachment: icon, name and size; `trailing` adds the buttons.
fn attachment_row(
    ui: &mut egui::Ui,
    a: &crate::model::Attachment,
    trailing: impl FnOnce(&mut egui::Ui),
) {
    widgets::trailing_row(ui, Align::Center, trailing, |ui| {
        ui.horizontal_centered(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            ui.label(RichText::new(icons::PAPERCLIP).size(15.0).color(text_dim()));
            ui.add(egui::Label::new(RichText::new(&a.name).color(text())).truncate());
            ui.label(faint(widgets::file_size(a.data.len())));
        });
    });
}

fn list_ui(
    ui: &mut egui::Ui,
    ms: &mut MainState,
    cat: Category,
    tag: Option<&str>,
    acts: &mut Vec<Act>,
) {
    Frame::new()
        .fill(surface())
        .corner_radius(RADIUS)
        .inner_margin(8.0)
        .show(ui, |ui| {
            ui.set_min_height(ui.available_height());
            ui.add(
                TextEdit::singleline(&mut ms.items.search)
                    .id(Id::new(SEARCH_ID))
                    .hint_text(hint(trf!("{}  Search", icons::MAGNIFYING_GLASS)))
                    .desired_width(f32::INFINITY)
                    .margin(Vec2::new(10.0, 7.0)),
            )
            .on_hover_text("Ctrl+F");
            let q = ms.items.search.trim().to_lowercase();
            let data = ms.vault.data();
            let order = data.settings.sort;
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.label(faint(if q.is_empty() {
                    tr("Sort")
                } else {
                    tr("Best match first")
                }));
                if q.is_empty() {
                    ui.scope(|ui| {
                        let w = &mut ui.visuals_mut().widgets;
                        w.inactive.weak_bg_fill = egui::Color32::TRANSPARENT;
                        w.inactive.bg_stroke = Stroke::NONE;
                        egui::ComboBox::from_id_salt("item_sort")
                            .width(130.0)
                            .icon(widgets::combo_caret)
                            .selected_text(small(order.label()))
                            .show_ui(ui, |ui| {
                                for o in SortOrder::ALL {
                                    if ui.selectable_label(o == order, o.label()).clicked() {
                                        acts.push(Act::Sort(o));
                                    }
                                }
                            });
                    });
                }
            });
            let mut list: Vec<(i32, &Entry)> = data
                .entries
                .iter()
                .filter(|e| on_page(e, cat, tag))
                .filter_map(|e| e.search_score(&q).map(|s| (s, e)))
                .collect();
            list.sort_by(|(sa, a), (sb, b)| {
                if q.is_empty() {
                    b.favorite
                        .cmp(&a.favorite)
                        .then_with(|| order.compare(a, b))
                } else {
                    sb.cmp(sa).then_with(|| order.compare(a, b))
                }
            });
            let visible: Vec<u64> = list.iter().map(|(_, e)| e.id).collect();
            let typing = ui.memory(|m| m.focused().is_some());
            if !typing
                && ms.items.editor.is_none()
                && ms.modal.is_none()
                && visible.len() > 1
                && ui.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::A))
            {
                acts.push(Act::PickAll(visible.clone()));
            }
            egui::ScrollArea::vertical()
                .id_salt("items_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    if list.is_empty() {
                        ui.add_space(24.0);
                        ui.vertical_centered(|ui| {
                            ui.label(faint(if q.is_empty() {
                                tr("Nothing here yet")
                            } else {
                                tr("No matches")
                            }));
                        });
                    }
                    let breach = ms.breach.report.as_ref();
                    for (_, e) in list {
                        let now = now_unix();
                        let expiry = ms.health.expiry(e.id);
                        let warn = if breach.is_some_and(|b| b.is_breached(e.id))
                            || ms.health.is_weak(e.id)
                            || expiry.is_some_and(|at| at <= now)
                        {
                            Some(danger())
                        } else if ms.health.is_reused(e.id) || expiry.is_some() {
                            Some(warn())
                        } else {
                            None
                        };
                        let picked = ms.items.is_picked(e.id);
                        let selected = picked
                            || (ms.items.selected == Some(e.id)
                                && ms.items.editor.is_none()
                                && ms.items.picked().is_empty());
                        let resp = entry_row(ui, e, selected, picked, warn);
                        if resp.clicked() {
                            let m = ui.input(|i| i.modifiers);
                            // Selecting several items never discards an
                            // open editor; plain clicks go through the
                            // usual unsaved-changes check.
                            if ms.items.editor.is_none() && m.command {
                                acts.push(Act::TogglePick(e.id));
                            } else if ms.items.editor.is_none() && m.shift {
                                acts.push(Act::PickRange(e.id, visible.clone()));
                            } else {
                                acts.push(Act::Nav(Nav::Select(e.id)));
                            }
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
    for (kind, label, what) in [
        (FieldKind::Username, tr("Copy username"), tr("Username")),
        (FieldKind::Email, tr("Copy email"), tr("Email")),
        (FieldKind::Password, tr("Copy password"), tr("Password")),
        (FieldKind::Url, tr("Copy website"), tr("Website")),
    ] {
        if let Some(v) = e.first_of(kind) {
            any = true;
            if ui.button(icons::with(icons::COPY, label)).clicked() {
                acts.push(Act::Copy(
                    Zeroizing::new(v.to_string()),
                    what.to_string(),
                    e.id,
                ));
                ui.close();
            }
        }
    }
    if let Some(totp) = e.totp_secret().and_then(|s| Totp::parse(s).ok()) {
        any = true;
        if ui
            .button(icons::with(
                icons::CLOCK_COUNTDOWN,
                tr("Copy one-time code"),
            ))
            .clicked()
        {
            acts.push(Act::Copy(
                Zeroizing::new(totp.code_at(now_unix())),
                tr("One-time code").into(),
                e.id,
            ));
            ui.close();
        }
    }
    if any {
        ui.separator();
    }
    if ui
        .button(icons::with(icons::PENCIL_SIMPLE, tr("Edit")))
        .clicked()
    {
        acts.push(Act::Nav(Nav::Select(e.id)));
        acts.push(Act::Edit(e.id));
        ui.close();
    }
    if ui
        .button(icons::with(icons::TRASH, tr("Move to Trash")))
        .clicked()
    {
        acts.push(Act::Delete(e.id));
        ui.close();
    }
}

fn entry_row(
    ui: &mut egui::Ui,
    e: &Entry,
    selected: bool,
    picked: bool,
    warn: Option<egui::Color32>,
) -> egui::Response {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 46.0), Sense::click());
    let painter = ui.painter_at(rect);
    if selected {
        painter.rect_filled(rect, 6.0, surface_2());
    } else if resp.hovered() {
        painter.rect_filled(rect, 6.0, row_hover());
    }
    let tile = Rect::from_center_size(rect.left_center() + Vec2::new(22.0, 0.0), Vec2::splat(30.0));
    if picked {
        // A check mark in place of the tile, so the selection reads at a
        // glance.
        painter.rect_filled(tile, (tile.width() * 0.24).round(), accent_fill());
        painter.text(
            tile.center(),
            Align2::CENTER_CENTER,
            icons::CHECK,
            FontId::proportional(16.0),
            egui::Color32::WHITE,
        );
    } else {
        widgets::entry_tile(ui, tile, e);
    }

    let mut right = rect.right() - 10.0;
    for (show, icon, color) in [
        (e.favorite, icons::STAR, text_faint()),
        (
            warn.is_some(),
            icons::WARNING,
            warn.unwrap_or(super::theme::warn()),
        ),
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
        text(),
    );
    if !sub.is_empty() {
        tp.text(
            egui::pos2(x, rect.center().y + sy),
            Align2::LEFT_CENTER,
            sub,
            FontId::proportional(12.0),
            text_faint(),
        );
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

fn empty_detail(ui: &mut egui::Ui, vault_page_empty: bool) {
    card(ui, |ui| {
        ui.set_min_height(ui.available_height());
        ui.add_space(ui.available_height() * 0.35);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(icons::VAULT).size(32.0).color(text_faint()));
            ui.add_space(4.0);
            ui.label(dim(if vault_page_empty {
                tr("Add your first item with New (Ctrl+N).")
            } else {
                tr("Select an item to see its details.")
            }));
            if !vault_page_empty {
                ui.add_space(2.0);
                ui.label(faint(tr(
                    "Ctrl+click or Shift+click to select several and change them together.",
                )));
            }
        });
    });
}

fn header_row(
    ui: &mut egui::Ui,
    entry: &Entry,
    title: &str,
    subtitle: &str,
    right: impl FnOnce(&mut egui::Ui),
) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
        widgets::entry_tile(ui, rect, entry);
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
    breach: Option<&BreachReport>,
    acts: &mut Vec<Act>,
) {
    card(ui, |ui| {
        ui.set_min_height(ui.available_height());
        let subtitle = match e.first_of(FieldKind::Url).map(host_of) {
            Some(host) if !host.is_empty() => format!("{}  ·  {host}", e.kind.label()),
            _ => e.kind.label().to_string(),
        };
        header_row(ui, e, e.display_title(), &subtitle, |ui| {
            if widgets::icon_button(ui, icons::TRASH, tr("Move to Trash")).clicked() {
                acts.push(Act::Delete(e.id));
            }
            if widgets::icon_button(ui, icons::PENCIL_SIMPLE, tr("Edit")).clicked() {
                acts.push(Act::Edit(e.id));
            }
            let fav_tip = if e.favorite {
                tr("Remove from favorites")
            } else {
                tr("Add to favorites")
            };
            if widgets::toggle_icon(ui, e.favorite, icons::STAR, fav_tip).clicked() {
                acts.push(Act::ToggleFav(e.id));
            }
        });
        let weak = health.is_weak(e.id);
        let reused = health.is_reused(e.id);
        let breached = breach.is_some_and(|b| b.is_breached(e.id));
        let expiry = health.expiry(e.id);
        if weak || reused || breached || expiry.is_some() || !e.tags.is_empty() {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if let Some(at) = expiry {
                    let now = now_unix();
                    let color = if at <= now { danger() } else { warn() };
                    widgets::pill(ui, &expiry_description(at, now), color);
                }
                if breached {
                    widgets::pill(ui, tr("Found in a data breach"), danger());
                }
                if weak {
                    widgets::pill(ui, tr("Weak password"), danger());
                }
                if reused {
                    widgets::pill(ui, tr("Reused password"), warn());
                }
                for t in &e.tags {
                    widgets::tag_chip(ui, t);
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
                                if widgets::icon_button(ui, icons::COPY, tr("Copy")).clicked() {
                                    acts.push(Act::Copy(
                                        Zeroizing::new(e.notes.clone()),
                                        tr("Note").into(),
                                        e.id,
                                    ));
                                }
                            },
                            |ui| {
                                ui.add_space(7.0);
                                ui.label(faint(if e.kind == EntryKind::SecureNote {
                                    tr("Note")
                                } else {
                                    tr("Notes")
                                }));
                            },
                        );
                        ui.add(egui::Label::new(RichText::new(&e.notes).color(text())).wrap());
                        ui.add_space(6.0);
                    });
                }
                if !e.attachments.is_empty() {
                    ui.add_space(10.0);
                    widgets::group(ui, |ui| {
                        ui.add_space(7.0);
                        ui.label(faint(tr("Attachments")));
                        for (i, a) in e.attachments.iter().enumerate() {
                            attachment_row(ui, a, |ui| {
                                if widgets::icon_button(
                                    ui,
                                    icons::DOWNLOAD_SIMPLE,
                                    tr("Save to a file…"),
                                )
                                .clicked()
                                {
                                    acts.push(Act::SaveAttachment(e.id, i));
                                }
                            });
                        }
                        ui.add_space(4.0);
                    });
                }
                if shown.is_empty() && e.notes.is_empty() && e.attachments.is_empty() {
                    ui.label(dim(tr("Empty. Use Edit to add details.")));
                }
                if !e.history.is_empty() {
                    ui.add_space(10.0);
                    history_ui(ui, e, revealed, acts);
                }
                ui.add_space(14.0);
                let mut meta = trf!(
                    "Created {}  ·  Updated {}",
                    format_date(e.created),
                    format_date(e.modified)
                );
                if e.primary_password().is_some() {
                    meta.push_str(&trf!(
                        "  ·  Password changed {}",
                        age_description(e.password_changed, now_unix())
                    ));
                }
                if let Some(at) = e.effective_expiry() {
                    meta.push_str(&trf!("  ·  Expires {}", format_date(at)));
                }
                ui.label(faint(meta));
                if !e.auto_type.trim().is_empty() {
                    ui.label(faint(trf!(
                        "{}  Auto-type: {}",
                        icons::KEYBOARD,
                        e.auto_type.trim()
                    )));
                }
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
    if f.kind == FieldKind::Totp {
        return totp_view(ui, id, i, f, revealed, acts);
    }
    let concealed = f.kind.is_concealed() && !revealed;
    let tall = !concealed && f.value.contains('\n');
    let strength = (f.kind == FieldKind::Password).then(|| estimate_strength(&f.value));
    let top = ui.cursor().min;
    let bg = ui.painter().add(egui::Shape::Noop);
    widgets::trailing_row_h(
        ui,
        42.0,
        if tall { Align::Min } else { Align::Center },
        |ui| {
            if widgets::icon_button(ui, icons::COPY, tr("Copy")).clicked() {
                acts.push(Act::Copy(
                    Zeroizing::new(f.value.clone()),
                    f.label.clone(),
                    id,
                ));
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
                    if revealed { tr("Hide") } else { tr("Reveal") },
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
                    ui.label(RichText::new("·").size(12.0).color(text_faint()));
                    ui.label(RichText::new(r.strength.label()).size(12.0).color(color));
                }
            });
            let text = if concealed {
                MASK.to_string()
            } else {
                f.value.clone()
            };
            let mut rt = RichText::new(text).size(14.5).color(super::theme::text());
            if f.kind.is_concealed() {
                rt = rt.family(egui::FontFamily::Monospace);
            }
            ui.add(egui::Label::new(rt).wrap());
            ui.add_space(2.0);
        },
    );
    if copy_on_click(ui, top, bg, &f.label, id, i) {
        acts.push(Act::Copy(
            Zeroizing::new(f.value.clone()),
            f.label.clone(),
            id,
        ));
    }
}

/// Make the row drawn since `top` copy its value when clicked anywhere left
/// of its buttons, with a hover highlight painted into the reserved `bg`
/// slot (behind the row's content).
fn copy_on_click(
    ui: &mut egui::Ui,
    top: egui::Pos2,
    bg: egui::layers::ShapeIdx,
    label: &str,
    id: u64,
    i: usize,
) -> bool {
    let row = Rect::from_min_max(
        top,
        egui::pos2(ui.max_rect().right(), ui.min_rect().bottom()),
    );
    // Leave the trailing icon buttons (copy / reveal) their own clicks.
    let target = row.with_max_x(row.right() - 2.0 * widgets::ICON_BUTTON - 16.0);
    let resp = ui
        .interact(target, Id::new(("copy_row", id, i)), Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand)
        .on_hover_text(trf!("Click to copy {}", label.to_lowercase()));
    if resp.hovered() {
        ui.painter().set(
            bg,
            egui::epaint::RectShape::filled(
                row.expand2(Vec2::new(8.0, 1.0)),
                RADIUS_SM,
                row_hover(),
            ),
        );
    }
    resp.clicked()
}

/// "https://www.example.com/login" -> "example.com".
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    host.trim_start_matches("www.").to_string()
}

/// A one-time-code field: the live code with a countdown. The secret itself
/// is only shown when revealed.
fn totp_view(ui: &mut egui::Ui, id: u64, i: usize, f: &Field, revealed: bool, acts: &mut Vec<Act>) {
    let parsed = Totp::parse(&f.value);
    let now = now_unix();
    widgets::trailing_row_h(
        ui,
        42.0,
        Align::Center,
        |ui| {
            if let Ok(t) = &parsed {
                if widgets::icon_button(ui, icons::COPY, tr("Copy code")).clicked() {
                    acts.push(Act::Copy(
                        Zeroizing::new(t.code_at(now)),
                        tr("One-time code").into(),
                        id,
                    ));
                }
            }
            let icon = if revealed {
                icons::EYE_SLASH
            } else {
                icons::EYE
            };
            let tip = if revealed {
                tr("Hide secret")
            } else {
                tr("Show secret")
            };
            if widgets::toggle_icon(ui, revealed, icon, tip).clicked() {
                acts.push(Act::Reveal(id, i));
            }
        },
        |ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.add_space(2.0);
            ui.label(faint(&f.label));
            match &parsed {
                Ok(t) => {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format_code(&t.code_at(now)))
                                .size(17.0)
                                .family(egui::FontFamily::Monospace)
                                .color(text()),
                        );
                        widgets::countdown(ui, t.remaining_at(now), t.period);
                    });
                }
                Err(e) => {
                    ui.label(RichText::new(e.to_string()).color(danger()).size(13.0));
                }
            }
            if revealed {
                ui.add(egui::Label::new(faint(&f.value)).wrap());
            }
            ui.add_space(2.0);
        },
    );
}

/// Replaced passwords, newest first, each concealed until revealed.
fn history_ui(
    ui: &mut egui::Ui,
    e: &Entry,
    revealed: &HashMap<(u64, usize), Instant>,
    acts: &mut Vec<Act>,
) {
    egui::CollapsingHeader::new(small(trf!(
        "{}  Password history ({})",
        icons::CLOCK_COUNTER_CLOCKWISE,
        e.history.len()
    )))
    .id_salt(("history", e.id))
    .show(ui, |ui| {
        widgets::group(ui, |ui| {
            let now = now_unix();
            for (n, (i, h)) in e.history.iter().enumerate().rev().enumerate() {
                if n > 0 {
                    widgets::divider(ui, 14.0);
                }
                let key = HISTORY_BASE + i;
                let shown = revealed.contains_key(&(e.id, key));
                widgets::trailing_row_h(
                    ui,
                    40.0,
                    Align::Center,
                    |ui| {
                        if widgets::icon_button(ui, icons::COPY, tr("Copy")).clicked() {
                            acts.push(Act::Copy(
                                Zeroizing::new(h.value.clone()),
                                tr("Old password").into(),
                                e.id,
                            ));
                        }
                        let icon = if shown { icons::EYE_SLASH } else { icons::EYE };
                        let tip = if shown { tr("Hide") } else { tr("Reveal") };
                        if widgets::toggle_icon(ui, shown, icon, tip).clicked() {
                            acts.push(Act::Reveal(e.id, key));
                        }
                    },
                    |ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.label(faint(trf!(
                            "{} · replaced {}",
                            h.label,
                            age_description(h.replaced, now)
                        )));
                        let text = if shown {
                            h.value.clone()
                        } else {
                            MASK.to_string()
                        };
                        ui.label(
                            RichText::new(text)
                                .family(egui::FontFamily::Monospace)
                                .color(text_dim()),
                        );
                    },
                );
            }
        });
    });
}

enum FieldOp {
    Remove(usize),
    Up(usize),
    Down(usize),
    Reveal(usize),
    Generate(usize),
    ScanQr,
    EditRule(String),
}

/// The website of the item being edited, for its password rules.
struct RuleHint {
    url: String,
    host: String,
    /// The rule that applies (its host may be a parent domain).
    rule: Option<(String, crate::generator::GeneratorOptions)>,
}

/// "16 characters · A–Z a–z 0–9" (what generated passwords will be like).
pub fn rule_summary(g: &crate::generator::GeneratorOptions) -> String {
    let mut sets: Vec<&str> = Vec::new();
    if g.custom_only {
        sets.push(tr("only the extra characters"));
    } else {
        for (on, label) in [
            (g.uppercase, "A–Z"),
            (g.lowercase, "a–z"),
            (g.digits, "0–9"),
            (g.symbols, "!#$%&*"),
        ] {
            if on {
                sets.push(label);
            }
        }
    }
    let mut out = plural(g.length as usize, "{n} character", "{n} characters");
    if !sets.is_empty() {
        out.push_str(" · ");
        out.push_str(&sets.join(" "));
    }
    if !g.custom_only && !g.custom_chars.trim().is_empty() {
        out.push_str(&format!(" +{}", g.custom_chars.trim()));
    }
    out
}

/// The item's tile, which opens a menu of icons and colours to give it.
fn icon_picker(ui: &mut egui::Ui, e: &mut Entry) {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(34.0), Sense::click());
    widgets::entry_tile(ui, rect, e);
    if resp.hovered() {
        ui.painter().rect_stroke(
            rect,
            8.0,
            Stroke::new(1.5_f32, accent()),
            egui::StrokeKind::Outside,
        );
    }
    let resp = resp
        .on_hover_text(tr("Change icon and colour"))
        .on_hover_cursor(CursorIcon::PointingHand);
    egui::Popup::menu(&resp)
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .show(|ui| {
            ui.set_width(316.0);
            ui.label(small(tr("Icon")));
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::splat(4.0);
                let letter = e
                    .title
                    .chars()
                    .find(|c| c.is_alphanumeric())
                    .map_or_else(|| "Aa".to_string(), |c| c.to_uppercase().to_string());
                if swatch(ui, &letter, e.icon.is_empty(), None)
                    .on_hover_text(tr("First letter of the title"))
                    .clicked()
                {
                    e.icon.clear();
                }
                for (key, glyph) in icons::ITEM_ICONS {
                    if swatch(ui, glyph, e.icon == *key, None).clicked() {
                        e.icon = key.to_string();
                    }
                }
            });
            ui.add_space(8.0);
            ui.label(small(tr("Colour")));
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::splat(4.0);
                if swatch(ui, icons::GLOBE, e.color == 0, None)
                    .on_hover_text(tr("Automatic: the same for every item on a website"))
                    .clicked()
                {
                    e.color = 0;
                }
                for (i, c) in widgets::TILE_COLORS.iter().enumerate() {
                    let n = (i + 1) as u8;
                    if swatch(ui, "", e.color == n, Some(*c)).clicked() {
                        e.color = n;
                    }
                }
            });
        });
}

/// One choice in the icon menu: a glyph, or a colour (`fill`).
fn swatch(ui: &mut egui::Ui, glyph: &str, on: bool, fill: Option<egui::Color32>) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::click());
    let p = ui.painter();
    match fill {
        Some(c) => {
            p.rect_filled(rect.shrink(3.0), 6.0, c);
        }
        None if on => {
            p.rect_filled(rect, 6.0, accent_bg());
        }
        None if resp.hovered() => {
            p.rect_filled(rect, 6.0, row_hover());
        }
        None => {}
    }
    if on {
        p.rect_stroke(
            rect,
            6.0,
            Stroke::new(1.5_f32, accent()),
            egui::StrokeKind::Inside,
        );
    }
    if !glyph.is_empty() {
        p.text(
            rect.center(),
            Align2::CENTER_CENTER,
            glyph,
            FontId::proportional(15.0),
            if on { accent() } else { text_dim() },
        );
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// Usernames and email addresses used most often in the vault, offered as
/// one-click fills for empty fields.
struct Suggestions {
    usernames: Vec<String>,
    emails: Vec<String>,
}

impl Suggestions {
    const MAX: usize = 3;

    fn from_vault(data: &crate::model::VaultData) -> Self {
        let top = |kind: FieldKind| {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for e in &data.entries {
                if let Some(v) = e.first_of(kind) {
                    *counts.entry(v.trim()).or_default() += 1;
                }
            }
            let mut v: Vec<(&str, usize)> =
                counts.into_iter().filter(|(k, _)| !k.is_empty()).collect();
            v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            v.into_iter()
                .take(Self::MAX)
                .map(|(k, _)| k.to_string())
                .collect()
        };
        Suggestions {
            usernames: top(FieldKind::Username),
            emails: top(FieldKind::Email),
        }
    }

    fn for_kind(&self, kind: FieldKind) -> &[String] {
        match kind {
            FieldKind::Username => &self.usernames,
            FieldKind::Email => &self.emails,
            _ => &[],
        }
    }
}

/// A title for an item saved without one: the site's name from its website
/// ("accounts.google.com" -> "Google") or from its two-step code.
fn automatic_title(e: &Entry) -> String {
    let from_site = e
        .first_of(FieldKind::Url)
        .map(crate::autotype::url_host)
        .map(|h| crate::autotype::site_name(&h).to_string())
        .unwrap_or_default();
    let name = if from_site.is_empty() {
        e.totp_secret()
            .map(|t| crate::totp::otpauth_labels(t).0)
            .unwrap_or_default()
    } else {
        from_site
    };
    let mut c = name.chars();
    match c.next() {
        Some(first) => first.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

fn editor_ui(
    ui: &mut egui::Ui,
    ed: &mut Editor,
    settings: &VaultSettings,
    suggest: &Suggestions,
    scanning: bool,
    acts: &mut Vec<Act>,
) {
    card(ui, |ui| {
        ui.set_min_height(ui.available_height());
        let title = if ed.is_new {
            trf!("New {}", ed.entry.kind.noun())
        } else {
            tr("Edit").to_string()
        };
        let subtitle = if ed.is_dirty() {
            tr("Unsaved changes")
        } else {
            ed.entry.kind.label()
        };
        header_row(ui, &ed.entry, &title, subtitle, |ui| {
            if widgets::secondary_button(ui, tr("Cancel"))
                .on_hover_text("Esc")
                .clicked()
            {
                acts.push(Act::Nav(Nav::CloseEditor));
            }
            if widgets::primary_button(ui, tr("Save"))
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
                ui.label(small(tr("Title")));
                let r = ui
                    .horizontal(|ui| {
                        icon_picker(ui, &mut ed.entry);
                        widgets::text_input(
                            ui,
                            &mut ed.entry.title,
                            tr("Leave empty to name it after the website"),
                        )
                    })
                    .inner;
                if ed.is_new && ed.entry.title.is_empty() && !ui.ctx().memory(|m| m.has_focus(r.id))
                {
                    r.request_focus();
                }
                ui.add_space(6.0);

                // Password rules belong to the item's website.
                let url = ed.entry.first_of(FieldKind::Url).map(str::to_string);
                let rule = url.as_deref().and_then(|u| {
                    let host = crate::autotype::url_host(u);
                    (!host.is_empty()).then(|| RuleHint {
                        url: u.to_string(),
                        host,
                        rule: settings.site_rule(u).map(|r| (r.host.clone(), r.options.clone())),
                    })
                });
                let gen = settings.generator_for(url.as_deref()).clone();

                let mut ops = Vec::new();
                let n = ed.entry.fields.len();
                if n > 0 {
                    widgets::group(ui, |ui| {
                        for (i, f) in ed.entry.fields.iter_mut().enumerate() {
                            if i > 0 {
                                widgets::divider(ui, 14.0);
                            }
                            let reveal = ed.reveal.contains_key(&i);
                            let s = suggest.for_kind(f.kind);
                            let r = rule.as_ref().filter(|_| f.kind == FieldKind::Password);
                            field_editor(ui, i, n, f, reveal, s, scanning, r, &mut ops);
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
                        FieldOp::ScanQr => acts.push(Act::ScanQr),
                        FieldOp::EditRule(url) => acts.push(Act::EditSiteRule(url)),
                        FieldOp::Generate(i) => match generate_password(&gen) {
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

                let has_code = ed.entry.fields.iter().any(|f| f.kind == FieldKind::Totp);
                let mut add = None;
                ui.horizontal(|ui| {
                    add = Some(widgets::link_button(ui, &icons::with(icons::PLUS, tr("Add field"))));
                    if !has_code {
                        if scanning {
                            ui.add(egui::Spinner::new().size(14.0));
                            ui.label(faint(tr("Looking for a QR code…")));
                        } else if widgets::link_button(
                            ui,
                            &icons::with(icons::QR_CODE, tr("Scan two-step QR code")),
                        )
                        .on_hover_text(
                            tr("Shows the site's 2FA setup QR code on screen? VaultRust reads it — no typing"),
                        )
                        .clicked()
                        {
                            acts.push(Act::ScanQr);
                        }
                    }
                });
                let add = add.expect("set above");
                egui::Popup::menu(&add).show(|ui| {
                    ui.set_min_width(170.0);
                    for k in FieldKind::ALL {
                        if ui.button(k.label()).clicked() {
                            let label = match k {
                                FieldKind::Password => tr("Password"),
                                FieldKind::Username => tr("Username"),
                                FieldKind::Email => tr("Email"),
                                FieldKind::Url => tr("Website"),
                                FieldKind::Totp => tr("One-time code"),
                                _ => tr("Field"),
                            };
                            ed.entry.fields.push(Field::new(label, k));
                            ui.close();
                        }
                    }
                });
                ui.add_space(8.0);

                ui.label(small(tr("Attachments")));
                let mut remove = None;
                for (i, a) in ed.entry.attachments.iter().enumerate() {
                    attachment_row(ui, a, |ui| {
                        if widgets::icon_button(ui, icons::X, tr("Remove")).clicked() {
                            remove = Some(i);
                        }
                    });
                }
                if let Some(i) = remove {
                    ed.entry.attachments.remove(i);
                }
                if widgets::link_button(ui, &icons::with(icons::PAPERCLIP, tr("Attach file…")))
                    .on_hover_text(tr("Stored encrypted inside the vault, up to 10 MB per file"))
                    .clicked()
                {
                    acts.push(Act::Attach);
                }
                ui.add_space(8.0);

                ui.label(small(tr("Tags")));
                tags_editor(ui, ed);
                ui.add_space(8.0);

                more_options(ui, ed);
                ui.add_space(8.0);

                let is_note = ed.entry.kind == EntryKind::SecureNote;
                ui.label(small(if is_note { tr("Note") } else { tr("Notes") }));
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

#[allow(clippy::too_many_arguments)]
fn field_editor(
    ui: &mut egui::Ui,
    i: usize,
    n: usize,
    f: &mut Field,
    reveal: bool,
    suggest: &[String],
    scanning: bool,
    rule: Option<&RuleHint>,
    ops: &mut Vec<FieldOp>,
) {
    // The type is only worth showing when the label doesn't already say it.
    let kind_hint = (!f.label.eq_ignore_ascii_case(f.kind.label())).then(|| f.kind.label());
    widgets::trailing_row_h(
        ui,
        26.0,
        Align::Center,
        |ui| {
            // Type, order and removal live in one menu instead of four
            // controls on every field.
            let more = widgets::icon_button(ui, icons::DOTS_THREE, tr("Field options"));
            egui::Popup::menu(&more).show(|ui| {
                ui.set_min_width(190.0);
                ui.menu_button(icons::with(icons::TEXT_AA, tr("Type")), |ui| {
                    for k in FieldKind::ALL {
                        if ui.selectable_label(f.kind == k, k.label()).clicked() {
                            f.kind = k;
                            ui.close();
                        }
                    }
                });
                ui.separator();
                if ui
                    .add_enabled(
                        i > 0,
                        egui::Button::new(icons::with(icons::ARROW_UP, tr("Move up"))),
                    )
                    .clicked()
                {
                    ops.push(FieldOp::Up(i));
                    ui.close();
                }
                if ui
                    .add_enabled(
                        i + 1 < n,
                        egui::Button::new(icons::with(icons::ARROW_DOWN, tr("Move down"))),
                    )
                    .clicked()
                {
                    ops.push(FieldOp::Down(i));
                    ui.close();
                }
                ui.separator();
                if ui
                    .button(
                        RichText::new(icons::with(icons::TRASH, tr("Remove field")))
                            .color(danger()),
                    )
                    .clicked()
                {
                    ops.push(FieldOp::Remove(i));
                    ui.close();
                }
            });
            if let Some(k) = kind_hint {
                ui.label(faint(k));
            }
        },
        |ui| {
            ui.add(
                TextEdit::singleline(&mut f.label)
                    .desired_width(ui.available_width().min(260.0))
                    .hint_text(hint(tr("Label")))
                    .font(TextStyle::Small)
                    .text_color(text_dim())
                    .frame(false)
                    .margin(Vec2::new(0.0, 4.0)),
            );
        },
    );
    let concealed = f.kind.is_concealed() && !reveal;
    let kind = f.kind;
    widgets::trailing_row(
        ui,
        Align::Min,
        |ui| {
            if kind == FieldKind::Password
                && widgets::icon_button(ui, icons::DICE_FIVE, tr("Generate a strong password"))
                    .clicked()
            {
                ops.push(FieldOp::Generate(i));
            }
            if kind == FieldKind::Totp {
                if scanning {
                    ui.add_sized(
                        [widgets::ICON_BUTTON, widgets::ICON_BUTTON],
                        egui::Spinner::new(),
                    );
                } else if widgets::icon_button(ui, icons::QR_CODE, tr("Scan the QR code on screen"))
                    .clicked()
                {
                    ops.push(FieldOp::ScanQr);
                }
            }
            if kind.is_concealed() {
                let icon = if reveal { icons::EYE_SLASH } else { icons::EYE };
                if widgets::toggle_icon(
                    ui,
                    reveal,
                    icon,
                    if reveal { tr("Hide") } else { tr("Reveal") },
                )
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
                    ui.label(faint(tr("Hidden — reveal to view or edit")));
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
    if let Some(r) = rule {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            let link = match &r.rule {
                Some((host, g)) => {
                    ui.label(
                        RichText::new(format!(
                            "{}  {host}: {}",
                            icons::SLIDERS_HORIZONTAL,
                            rule_summary(g)
                        ))
                        .size(12.0)
                        .color(text_dim()),
                    );
                    tr("Change")
                }
                None => {
                    ui.label(
                        RichText::new(icons::SLIDERS_HORIZONTAL)
                            .size(12.0)
                            .color(text_faint()),
                    );
                    tr("Set password rules for this site")
                }
            };
            if ui
                .add(egui::Button::new(RichText::new(link).size(12.0).color(accent())).frame(false))
                .on_hover_text(trf!(
                    "Length and characters the generator uses for {} and its subdomains",
                    r.host
                ))
                .on_hover_cursor(CursorIcon::PointingHand)
                .clicked()
            {
                ops.push(FieldOp::EditRule(r.url.clone()));
            }
        });
    }
    if f.value.is_empty() && !suggest.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            for s in suggest {
                if ui
                    .add(
                        egui::Button::new(RichText::new(s).size(12.5).color(text_dim()))
                            .fill(surface_2())
                            .corner_radius(10.0)
                            .min_size(Vec2::new(0.0, 22.0)),
                    )
                    .on_hover_text(tr("Use this"))
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                {
                    f.value = s.clone();
                }
            }
        });
    }
    if f.kind == FieldKind::Totp {
        let hint = if f.value.trim().is_empty() {
            RichText::new(tr(
                "Scan the QR code on screen, or paste the site's setup key",
            ))
            .size(12.0)
            .color(text_faint())
        } else {
            match Totp::parse(&f.value) {
                Ok(t) => RichText::new(trf!(
                    "Valid · current code {}",
                    format_code(&t.code_at(now_unix()))
                ))
                .size(12.0)
                .color(accent()),
                Err(e) => RichText::new(e.to_string()).size(12.0).color(danger()),
            }
        };
        ui.label(hint);
    }
    ui.add_space(2.0);
}

/// "" -> no expiry; "YYYY-MM-DD" -> the end of that day (UTC).
fn parse_expiry(text: &str) -> Result<i64, ()> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(0);
    }
    parse_iso8601(t).map(|at| at + 86_399).ok_or(())
}

/// Expiry date and custom auto-type sequence, folded away by default.
fn more_options(ui: &mut egui::Ui, ed: &mut Editor) {
    let open_by_default = !ed.expiry_text.is_empty() || !ed.entry.auto_type.is_empty();
    egui::CollapsingHeader::new(small(tr("Expiry and auto-type")))
        .id_salt(("more_options", ed.entry.id))
        .default_open(open_by_default)
        .show(ui, |ui| {
            ui.label(small(tr("Expires or needs changing on")));
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(&mut ed.expiry_text)
                        .hint_text(hint("YYYY-MM-DD"))
                        .desired_width(130.0)
                        .margin(Vec2::new(10.0, 6.0)),
                );
                let now = now_unix();
                for (label, days) in [
                    (tr("30 days"), 30),
                    (tr("90 days"), 90),
                    (tr("1 year"), 365),
                ] {
                    if widgets::secondary_button(ui, label).clicked() {
                        ed.expiry_text = format_date(now + days * 86_400);
                    }
                }
                if !ed.expiry_text.is_empty() && widgets::link_button(ui, tr("Never")).clicked() {
                    ed.expiry_text.clear();
                }
            });
            let hint = match parse_expiry(&ed.expiry_text) {
                Err(()) => RichText::new(tr("Use the format YYYY-MM-DD"))
                    .size(12.0)
                    .color(danger()),
                Ok(0) => RichText::new(tr("Shown under Needs attention two weeks before the date"))
                    .size(12.0)
                    .color(text_faint()),
                Ok(at) => RichText::new(expiry_description(at, now_unix()))
                    .size(12.0)
                    .color(text_dim()),
            };
            ui.label(hint);
            ui.add_space(8.0);

            ui.label(small(tr("Auto-type sequence")));
            ui.add(
                TextEdit::singleline(&mut ed.entry.auto_type)
                    .hint_text(super::theme::hint(crate::autotype::DEFAULT_SEQUENCE))
                    .font(TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .margin(Vec2::new(10.0, 7.0)),
            );
            let hint = if ed.entry.auto_type.trim().is_empty() {
                RichText::new(tr(
                    "Default: username, Tab, password, Enter. Placeholders: {USERNAME} {PASSWORD} \
                     {TOTP} {TAB} {ENTER} {DELAY 1000} {FIELD:label}",
                ))
                .size(12.0)
                .color(text_faint())
            } else {
                match crate::autotype::parse_sequence(&ed.entry.auto_type) {
                    Ok(_) => RichText::new(tr("Valid sequence"))
                        .size(12.0)
                        .color(accent()),
                    Err(e) => RichText::new(e).size(12.0).color(danger()),
                }
            };
            ui.add(egui::Label::new(hint).wrap());
        });
}

/// Tag chips with remove buttons, plus an input that adds a tag on Enter or
/// comma.
fn tags_editor(ui: &mut egui::Ui, ed: &mut Editor) {
    let mut remove = None;
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = Vec2::new(6.0, 6.0);
        for (i, t) in ed.entry.tags.iter().enumerate() {
            if widgets::tag_chip_removable(ui, t) {
                remove = Some(i);
            }
        }
        let resp = ui.add(
            TextEdit::singleline(&mut ed.tag_input)
                .hint_text(hint(tr("Add tag…")))
                .desired_width(140.0)
                .margin(Vec2::new(8.0, 4.0)),
        );
        let entered = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
        if entered || ed.tag_input.contains(',') {
            let pending = std::mem::take(&mut ed.tag_input);
            for t in pending.split([',', ';']) {
                ed.entry.add_tag(t);
            }
            if entered {
                resp.request_focus();
            }
        }
    });
    if let Some(i) = remove {
        ed.entry.tags.remove(i);
    }
}
