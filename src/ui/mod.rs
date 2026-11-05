//! egui / eframe desktop front end.

mod create;
mod dashboard;
mod entries;
mod generator_page;
mod icons;
mod jobs;
mod main_view;
mod modals;
mod security_page;
mod settings_page;
#[cfg(test)]
mod tests;
mod theme;
mod toast;
mod unlock;
mod welcome;
mod widgets;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::clipboard::ClipboardGuard;
use crate::recent::RecentVaults;
use crate::vault::UnlockedVault;

pub use toast::Toasts;

/// Launch the desktop application.
pub fn run() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("VaultRust")
            .with_app_id("VaultRust")
            .with_inner_size([1200.0, 780.0])
            .with_min_inner_size([900.0, 600.0])
            .with_icon(theme::app_icon()),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "VaultRust",
        options,
        Box::new(|cc| Ok(Box::new(VaultRustApp::new(&cc.egui_ctx)))),
    )
}

/// Shared services handed to every screen.
pub struct Services<'a> {
    pub clipboard: &'a mut ClipboardGuard,
    pub toasts: &'a mut Toasts,
    pub recent: &'a mut RecentVaults,
}

/// Requests from a screen to switch to another screen.
pub enum Transition {
    Welcome,
    Create,
    Unlock(PathBuf),
    Open(Box<UnlockedVault>),
    Lock,
    /// Lock without saving pending changes, so the file is re-read from disk
    /// (used after the user chooses to discard a conflicting change).
    Reload,
}

enum Screen {
    Welcome(welcome::WelcomeState),
    Create(Box<create::CreateState>),
    Unlock(Box<unlock::UnlockState>),
    Main(Box<main_view::MainState>),
}

pub struct VaultRustApp {
    screen: Screen,
    recent: RecentVaults,
    clipboard: ClipboardGuard,
    toasts: Toasts,
    styled: bool,
    /// Screen-capture exclusion currently applied to the window.
    capture_hidden: Option<bool>,
}

impl VaultRustApp {
    fn new(_ctx: &egui::Context) -> Self {
        let recent = RecentVaults::load();
        let screen = match recent.paths.first() {
            Some(p) if p.exists() => Screen::Unlock(Box::new(unlock::UnlockState::new(p.clone()))),
            _ => Screen::Welcome(welcome::WelcomeState),
        };
        Self::with_screen(screen, recent)
    }

    fn with_screen(screen: Screen, recent: RecentVaults) -> Self {
        VaultRustApp {
            screen,
            recent,
            clipboard: ClipboardGuard::new(),
            toasts: Toasts::default(),
            styled: false,
            capture_hidden: None,
        }
    }

    /// Whether the window should currently be hidden from screen capture:
    /// only while a vault is unlocked and the vault's setting asks for it.
    fn wants_capture_hidden(&self) -> bool {
        matches!(&self.screen, Screen::Main(m) if m.vault.data().settings.hide_from_capture)
    }

    /// One UI frame. Separate from `eframe::App::update` so it can be driven
    /// headlessly in tests.
    fn frame(&mut self, ctx: &egui::Context) {
        if !self.styled {
            // Fonts installed with `set_fonts` only become usable on the next
            // frame, so skip drawing this one.
            theme::apply(ctx);
            self.styled = true;
            ctx.request_repaint();
            return;
        }
        self.clipboard.tick(Instant::now());
        let mut svc = Services {
            clipboard: &mut self.clipboard,
            toasts: &mut self.toasts,
            recent: &mut self.recent,
        };
        let transition = match &mut self.screen {
            Screen::Welcome(s) => welcome::show(ctx, s, &mut svc),
            Screen::Create(s) => create::show(ctx, s, &mut svc),
            Screen::Unlock(s) => unlock::show(ctx, s, &mut svc),
            Screen::Main(m) => m.show(ctx, &mut svc),
        };
        if let Some(t) = transition {
            self.apply(ctx, t);
        }
        self.toasts.show(ctx);

        // Defence in depth: the app never opens URLs / launches a browser.
        ctx.output_mut(|o| {
            o.commands
                .retain(|c| !matches!(c, egui::OutputCommand::OpenUrl(_)))
        });
        // Keep timers (auto-lock, clipboard clearing) ticking while idle.
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    fn apply(&mut self, ctx: &egui::Context, t: Transition) {
        match t {
            Transition::Welcome => self.screen = Screen::Welcome(welcome::WelcomeState),
            Transition::Create => self.screen = Screen::Create(Box::default()),
            Transition::Unlock(p) => {
                self.screen = Screen::Unlock(Box::new(unlock::UnlockState::new(p)));
            }
            Transition::Open(v) => {
                self.recent.push(v.path());
                self.forget_ui_state(ctx);
                self.screen = Screen::Main(Box::new(main_view::MainState::new(*v)));
            }
            Transition::Lock => {
                let path = match &mut self.screen {
                    Screen::Main(m) => {
                        m.flush(&mut self.toasts);
                        Some(m.vault.path().to_path_buf())
                    }
                    _ => None,
                };
                // Dropping MainState zeroizes the vault key and contents.
                self.screen = match path {
                    Some(p) => Screen::Unlock(Box::new(unlock::UnlockState::new(p))),
                    None => Screen::Welcome(welcome::WelcomeState),
                };
                self.clipboard.clear_now();
                self.forget_ui_state(ctx);
                self.toasts.info("Vault locked");
            }
            Transition::Reload => {
                let path = match &self.screen {
                    Screen::Main(m) => Some(m.vault.path().to_path_buf()),
                    _ => None,
                };
                self.screen = match path {
                    Some(p) => Screen::Unlock(Box::new(unlock::UnlockState::new(p))),
                    None => Screen::Welcome(welcome::WelcomeState),
                };
                self.clipboard.clear_now();
                self.forget_ui_state(ctx);
                self.toasts.info("Unlock again to load the current file");
            }
        }
    }

    /// Drop egui's per-widget memory (text edit undo history etc.), which
    /// may hold copies of text typed while the vault was open.
    fn forget_ui_state(&self, ctx: &egui::Context) {
        ctx.memory_mut(|m| m.data.clear());
    }
}

impl eframe::App for VaultRustApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.frame(ctx);
        let want = self.wants_capture_hidden();
        if self.capture_hidden != Some(want) {
            use raw_window_handle::HasWindowHandle;
            if let Ok(h) = frame.window_handle() {
                crate::os_protect::set_capture_excluded(h.as_raw(), want);
            }
            // Recorded even if the OS refused, to avoid retrying every frame.
            self.capture_hidden = Some(want);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Screen::Main(m) = &mut self.screen {
            m.flush(&mut self.toasts);
        }
        self.clipboard.clear_now();
        // Replace the screen so the vault is dropped (and zeroized) now.
        self.screen = Screen::Welcome(welcome::WelcomeState);
    }
}
