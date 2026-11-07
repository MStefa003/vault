//! Update checks, the "new version" notification, installing it, and the
//! "What's new" window (the changelog built into the program).

use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Align2, Color32, FontId, Frame, Id, Label, Margin, Order, RichText, Sense, Shadow,
    Stroke, Vec2,
};

use super::icons;
use super::jobs::{Job, Poll};
use super::theme::*;
use super::widgets;
use crate::i18n::tr;
use crate::prefs::AppPrefs;
use crate::timeutil::now_unix;
use crate::trf;
use crate::update::{self, Changes, Release, UpdateError, Version};

/// Automatic checks happen at most this often.
const CHECK_INTERVAL_SECS: i64 = 12 * 3600;
/// After an automatic check failed (offline), try again this much later.
const RETRY_AFTER: Duration = Duration::from_secs(3600);
/// Width of the notification's content.
const CARD_WIDTH: f32 = 340.0;
/// Points of the release notes shown in the notification.
const HIGHLIGHTS: usize = 3;

/// What the "What's new" window shows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Notes {
    /// The changes in each version up to this one.
    Changelog,
    /// The new release's notes, then the changelog.
    Release,
}

#[derive(Default)]
pub struct Updates {
    check: Option<Job<Result<Option<Release>, UpdateError>>>,
    install: Option<Job<Result<(), UpdateError>>>,
    /// A newer, not yet installed release.
    pub available: Option<Release>,
    /// Result of the last check, for Settings.
    pub status: Option<String>,
    /// The notification was closed with "Later" (until the next start).
    dismissed: bool,
    /// The new program is in place; restart into it.
    pub installed: bool,
    started: bool,
    /// When the last automatic check failed.
    failed_at: Option<Instant>,
    /// This version has just been installed: say what's new once.
    updated_to: Option<Changes>,
    notes: Option<Notes>,
    /// When the current notification first appeared (for its entrance).
    shown_at: Option<Instant>,
}

impl Updates {
    pub fn is_busy(&self) -> bool {
        self.check.is_some() || self.install.is_some()
    }

    pub fn is_installing(&self) -> bool {
        self.install.is_some()
    }

    /// Ask GitHub for a newer release in the background.
    pub fn check_now(&mut self, ctx: &egui::Context) {
        if self.check.is_none() && self.install.is_none() {
            self.status = None;
            self.check = Some(Job::spawn(ctx, update::check));
        }
    }

    pub fn install_now(&mut self, ctx: &egui::Context) {
        let Some(release) = self.available.clone() else {
            return;
        };
        if self.install.is_some() {
            return;
        }
        self.notes = None;
        self.install = Some(Job::spawn(ctx, move || {
            let exe = std::env::current_exe().map_err(|e| UpdateError::Install(e.to_string()))?;
            let bytes = update::download(&release)?;
            update::install(&exe, &bytes)?;
            crate::os_protect::record_installed_version(&release.version.to_string());
            Ok(())
        }));
    }

    /// Open the "What's new" window.
    pub fn open_changelog(&mut self) {
        self.notes = Some(Notes::Changelog);
    }

    /// Open the "What's new" window on the available update's notes.
    #[cfg(test)]
    pub fn open_release_notes(&mut self) {
        self.notes = Some(Notes::Release);
    }

    /// Show the notification VaultRust shows after it was updated.
    #[cfg(test)]
    pub fn pretend_updated(&mut self) {
        self.updated_to = update::parse_changelog(update::CHANGELOG)
            .into_iter()
            .next();
    }

    /// Remember the version that runs now; if it is newer than the last one
    /// that ran here, say what's new in it.
    fn note_version(&mut self, prefs: &mut AppPrefs) {
        let current = update::current_version();
        let seen = Version::parse(&prefs.seen_version);
        if seen.is_some_and(|v| v < current) {
            let version = current.to_string();
            self.updated_to = Some(
                update::parse_changelog(update::CHANGELOG)
                    .into_iter()
                    .find(|c| c.version == version)
                    .unwrap_or(Changes {
                        version,
                        date: String::new(),
                        items: Vec::new(),
                    }),
            );
        }
        if seen.is_none_or(|v| v < current) {
            prefs.seen_version = current.to_string();
            prefs.save();
        }
    }

    /// Call every frame. Checks for a new version when one is due (and an
    /// hour after a failed check) and collects finished work; returns an
    /// error message to show, if any.
    pub fn tick(&mut self, ctx: &egui::Context, prefs: &mut AppPrefs) -> Option<String> {
        if !self.started {
            self.started = true;
            if let Ok(exe) = std::env::current_exe() {
                update::clean_up(&exe);
            }
            self.note_version(prefs);
        }
        let due = now_unix() - prefs.last_update_check >= CHECK_INTERVAL_SECS;
        let may_retry = self.failed_at.is_none_or(|t| t.elapsed() >= RETRY_AFTER);
        if prefs.check_updates
            && due
            && may_retry
            && self.available.is_none()
            && !self.is_busy()
            && !cfg!(test)
        {
            self.check_now(ctx);
        }
        let mut message = None;
        if let Some(job) = &self.check {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(r) => {
                    self.check = None;
                    if r.is_ok() {
                        prefs.last_update_check = now_unix();
                        prefs.save();
                        self.failed_at = None;
                    } else {
                        self.failed_at = Some(Instant::now());
                    }
                    match r {
                        Ok(Some(rel)) => {
                            self.status = Some(trf!("Version {} is available", rel.version));
                            self.available = Some(rel);
                            self.dismissed = false;
                            self.shown_at = None;
                        }
                        Ok(None) => {
                            self.status = Some(trf!(
                                "VaultRust {} is the latest version",
                                update::current_version()
                            ))
                        }
                        Err(e) => self.status = Some(e.to_string()),
                    }
                }
                Poll::Failed => {
                    self.check = None;
                    self.failed_at = Some(Instant::now());
                }
            }
        }
        if let Some(job) = &self.install {
            match job.poll() {
                Poll::Pending => {}
                Poll::Done(Ok(())) => {
                    self.install = None;
                    self.installed = true;
                }
                Poll::Done(Err(e)) => {
                    self.install = None;
                    message = Some(e.to_string());
                }
                Poll::Failed => {
                    self.install = None;
                    message = Some(tr("The update stopped unexpectedly").into());
                }
            }
        }
        message
    }

    /// The notification in the bottom-right corner (a new version is
    /// available, or was just installed) and the "What's new" window.
    /// Returns whether the user chose to install the update, and the height
    /// the notification takes up (toasts go above it).
    pub fn show(&mut self, ctx: &egui::Context) -> (bool, f32) {
        let mut install = false;
        if self.notes.is_some() {
            install |= self.notes_window(ctx);
        }
        let height = if self.available.is_some() && (!self.dismissed || self.is_installing()) {
            let (go, h) = self.available_card(ctx);
            install |= go;
            h
        } else if self.updated_to.is_some() {
            self.updated_card(ctx)
        } else {
            self.shown_at = None;
            0.0
        };
        (install, height)
    }

    fn available_card(&mut self, ctx: &egui::Context) -> (bool, f32) {
        let Some(rel) = &self.available else {
            return (false, 0.0);
        };
        let items = update::note_items(&rel.notes);
        let title = tr("Update available");
        let (new, current) = (rel.version, update::current_version());
        let subtitle = trf!("VaultRust {new} · you have {current}", new, current);
        let installing = self.install.is_some();
        let mut install = false;
        let mut later = false;
        let mut notes = false;
        let shown_at = *self.shown_at.get_or_insert_with(Instant::now);
        let height = notification(
            ctx,
            "update_available",
            shown_at,
            icons::ARROW_CIRCLE_UP,
            title,
            &subtitle,
            &items,
            !installing,
            |ui| {
                if installing {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(16.0));
                        ui.label(dim(tr("Downloading and checking the signature…")));
                    });
                    return false;
                }
                let mut close = false;
                ui.horizontal(|ui| {
                    if widgets::primary_button(ui, tr("Update and restart"))
                        .on_hover_text(tr("Your vault is locked and saved first"))
                        .clicked()
                    {
                        install = true;
                    }
                    if widgets::secondary_button(ui, tr("What's new")).clicked() {
                        notes = true;
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        if widgets::link_button(ui, tr("Later")).clicked() {
                            close = true;
                        }
                    });
                });
                close
            },
            &mut later,
        );
        if later {
            self.dismissed = true;
        }
        if notes {
            self.notes = Some(Notes::Release);
        }
        (install, height)
    }

    fn updated_card(&mut self, ctx: &egui::Context) -> f32 {
        let Some(changes) = &self.updated_to else {
            return 0.0;
        };
        let title = trf!("Updated to VaultRust {}", changes.version);
        let mut all = false;
        let mut close = false;
        let shown_at = *self.shown_at.get_or_insert_with(Instant::now);
        let height = notification(
            ctx,
            "update_installed",
            shown_at,
            icons::SPARKLE,
            &title,
            tr("Here's what's new in this version"),
            &changes.items,
            true,
            |ui| {
                let mut done = false;
                ui.horizontal(|ui| {
                    if widgets::primary_button(ui, tr("Got it")).clicked() {
                        done = true;
                    }
                    if widgets::secondary_button(ui, tr("See all changes")).clicked() {
                        all = true;
                    }
                });
                done
            },
            &mut close,
        );
        if all {
            self.notes = Some(Notes::Changelog);
            close = true;
        }
        if close {
            self.updated_to = None;
            self.shown_at = None;
        }
        height
    }

    /// The "What's new" window. Returns true when the user chose to
    /// install the available update from it.
    fn notes_window(&mut self, ctx: &egui::Context) -> bool {
        let Some(view) = self.notes else {
            return false;
        };
        let release = self.available.as_ref().filter(|_| view == Notes::Release);
        let current = update::current_version().to_string();
        let log: Vec<Changes> = update::parse_changelog(update::CHANGELOG)
            .into_iter()
            .filter(|c| Version::parse(&c.version).is_some())
            .collect();
        let mut install = false;
        let mut close = false;
        let resp = egui::Modal::new(Id::new("modal_whats_new")).show(ctx, |ui| {
            ui.set_width(540.0);
            ui.horizontal(|ui| {
                badge(ui, icons::SPARKLE, 32.0);
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.label(strong(tr("What's new"), 17.0));
                    ui.label(faint(trf!("You have VaultRust {}", current)));
                });
            });
            ui.add_space(10.0);
            egui::ScrollArea::vertical()
                .max_height((ctx.content_rect().height() - 260.0).clamp(180.0, 460.0))
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if let Some(rel) = release {
                        version_block(
                            ui,
                            &rel.version.to_string(),
                            "",
                            Some((tr("New"), accent())),
                            &update::note_items(&rel.notes),
                        );
                    }
                    for c in &log {
                        let tag = (c.version == current).then(|| (tr("Installed"), text_dim()));
                        version_block(ui, &c.version, &c.date, tag, &c.items);
                    }
                    if log.is_empty() && release.is_none() {
                        ui.label(dim(tr("No changes are listed for this version")));
                    }
                });
            if crate::i18n::language() != crate::i18n::Language::English {
                ui.add_space(4.0);
                ui.label(faint(tr("The list of changes is in English")));
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if self.available.is_some() && self.install.is_none() {
                    if widgets::primary_button(ui, tr("Update and restart")).clicked() {
                        install = true;
                    }
                    if widgets::secondary_button(ui, tr("Close")).clicked() {
                        close = true;
                    }
                } else if widgets::primary_button(ui, tr("Close")).clicked() {
                    close = true;
                }
            });
        });
        if close || install || resp.should_close() {
            self.notes = None;
        }
        install
    }
}

/// A round tinted badge with an icon.
fn badge(ui: &mut egui::Ui, glyph: &str, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let p = ui.painter();
    p.circle_filled(rect.center(), size / 2.0, accent_bg());
    p.text(
        rect.center(),
        Align2::CENTER_CENTER,
        glyph,
        FontId::proportional(size * 0.56),
        accent(),
    );
}

/// "•  text" with the text wrapping under itself.
fn bullet(ui: &mut egui::Ui, text: &str) {
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.label(RichText::new("•").color(accent()).strong());
        ui.add(Label::new(dim(text)).wrap());
    });
}

/// One version in the "What's new" window.
fn version_block(
    ui: &mut egui::Ui,
    version: &str,
    date: &str,
    tag: Option<(&str, Color32)>,
    items: &[String],
) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(strong(version, 15.0));
        if !date.is_empty() {
            ui.label(faint(date));
        }
        if let Some((text, color)) = tag {
            widgets::pill(ui, text, color);
        }
    });
    ui.add_space(2.0);
    for item in items {
        bullet(ui, item);
    }
    ui.add_space(8.0);
    widgets::divider(ui, 0.0);
}

/// Shorten `s` to about `max` characters at a word boundary.
fn shorten(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    // One more, so a word ending right at `max` is kept.
    let cut: String = s.chars().take(max + 1).collect();
    let cut = cut.rsplit_once(' ').map_or(cut.as_str(), |(a, _)| a);
    format!("{}…", cut.trim_end_matches([',', '.', ';', ':']))
}

/// A notification card in the bottom-right corner: icon, title, subtitle,
/// the first few `items` and the row of buttons `actions` adds (which
/// returns true to close it). `closed` is set when it was closed by
/// either. Returns the height it takes up.
#[allow(clippy::too_many_arguments)]
fn notification(
    ctx: &egui::Context,
    id: &str,
    shown_at: Instant,
    glyph: &str,
    title: &str,
    subtitle: &str,
    items: &[String],
    closable: bool,
    actions: impl FnOnce(&mut egui::Ui) -> bool,
    closed: &mut bool,
) -> f32 {
    // Slide up and fade in over a quarter of a second.
    let t = if cfg!(test) {
        1.0
    } else {
        (shown_at.elapsed().as_secs_f32() / 0.25).min(1.0)
    };
    let ease = 1.0 - (1.0 - t).powi(3);
    if t < 1.0 {
        ctx.request_repaint();
    }
    let shadow = Color32::from_black_alpha(if is_dark() { 120 } else { 45 });
    let area = egui::Area::new(Id::new(id))
        .order(Order::Middle)
        .anchor(Align2::RIGHT_BOTTOM, [-16.0, -16.0 + (1.0 - ease) * 24.0])
        .show(ctx, |ui| {
            ui.set_opacity(ease);
            Frame::new()
                .fill(surface())
                .stroke(Stroke::new(1.0_f32, border()))
                .corner_radius(12.0)
                .inner_margin(Margin::same(16))
                .shadow(Shadow {
                    offset: [0, 8],
                    blur: 28,
                    spread: 0,
                    color: shadow,
                })
                .show(ui, |ui| {
                    ui.set_width(CARD_WIDTH);
                    ui.horizontal(|ui| {
                        badge(ui, glyph, 38.0);
                        ui.add_space(4.0);
                        ui.vertical(|ui| {
                            ui.set_width(CARD_WIDTH - 38.0 - 44.0);
                            ui.add(Label::new(strong(title, 15.0)).wrap());
                            ui.add(Label::new(faint(subtitle)).wrap());
                        });
                        if closable {
                            ui.with_layout(egui::Layout::right_to_left(Align::Min), |ui| {
                                if widgets::icon_button(ui, icons::X, tr("Close")).clicked() {
                                    *closed = true;
                                }
                            });
                        }
                    });
                    if !items.is_empty() {
                        ui.add_space(10.0);
                        for item in items.iter().take(HIGHLIGHTS) {
                            bullet(ui, &shorten(item, 130));
                        }
                        if items.len() > HIGHLIGHTS {
                            let more = items.len() - HIGHLIGHTS;
                            ui.label(faint(trf!("and {more} more", more)));
                        }
                    }
                    ui.add_space(14.0);
                    if actions(ui) {
                        *closed = true;
                    }
                });
        });
    area.response.rect.height() + 8.0
}

/// The "Updates" and "What's new" rows in Settings.
pub fn settings_row(ui: &mut egui::Ui, updates: &mut Updates, prefs: &mut AppPrefs) {
    let mut auto = prefs.check_updates;
    widgets::switch_row(
        ui,
        &mut auto,
        tr("Check for updates automatically"),
        &trf!(
            "Twice a day, VaultRust asks GitHub ({}) for a newer, signed release and lets you know. No vault data is sent",
            update::REPO
        ),
    );
    if auto != prefs.check_updates {
        prefs.check_updates = auto;
        prefs.save();
    }
    widgets::divider(ui, 16.0);
    let desc = updates
        .status
        .clone()
        .unwrap_or_else(|| trf!("You have version {}", update::current_version()));
    let mut check = false;
    let mut install = false;
    widgets::setting_row(ui, tr("Updates"), &desc, 200.0, |ui| {
        if updates.is_busy() {
            ui.add(egui::Spinner::new());
        } else if updates.available.is_some() {
            install = widgets::primary_button(ui, tr("Update and restart")).clicked();
        } else {
            check = widgets::secondary_button(ui, tr("Check now")).clicked();
        }
    });
    if check {
        updates.check_now(ui.ctx());
    }
    if install {
        updates.install_now(ui.ctx());
    }
    widgets::divider(ui, 16.0);
    let mut open = false;
    widgets::setting_row(
        ui,
        tr("What's new"),
        tr("The changes in each version of VaultRust"),
        160.0,
        |ui| open = widgets::secondary_button(ui, tr("Show changes")).clicked(),
    );
    if open {
        updates.open_changelog();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_points_are_shortened_at_a_word() {
        assert_eq!(shorten("short", 10), "short");
        assert_eq!(shorten("one two three four", 12), "one two…");
        assert_eq!(shorten("one, two, three", 9), "one, two…");
    }

    #[test]
    fn whats_new_is_shown_once_after_an_update() {
        let mut prefs = AppPrefs::in_memory();
        let mut u = Updates::default();
        u.note_version(&mut prefs);
        assert!(u.updated_to.is_none(), "not on the first start");
        assert_eq!(prefs.seen_version, update::current_version().to_string());

        prefs.seen_version = "0.0.1".into();
        let mut u = Updates::default();
        u.note_version(&mut prefs);
        let changes = u.updated_to.expect("after an update");
        assert_eq!(changes.version, update::current_version().to_string());
        let mut again = Updates::default();
        again.note_version(&mut prefs);
        assert!(again.updated_to.is_none());

        // An older version started after a newer one says nothing.
        prefs.seen_version = "99.0.0".into();
        let mut u = Updates::default();
        u.note_version(&mut prefs);
        assert!(u.updated_to.is_none());
        assert_eq!(prefs.seen_version, "99.0.0");
    }
}
