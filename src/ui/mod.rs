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
#[cfg(all(test, windows))]
mod tests;
mod theme;
mod toast;
mod trash_page;
mod unlock;
mod updates;
mod welcome;
mod widgets;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::clipboard::ClipboardGuard;
use crate::os_protect::{ForeignWindow, HotkeyEvent, HotkeyStatus};
use crate::prefs::AppPrefs;
use crate::recent::RecentVaults;
use crate::vault::UnlockedVault;

pub use toast::Toasts;

/// Launch the desktop application.
pub fn run() -> eframe::Result<()> {
    crate::os_protect::harden_process();
    // Started by Windows at sign-in: begin minimized (or hidden in the
    // notification area, below) rather than in the user's face.
    let startup = std::env::args().any(|a| a == crate::os_protect::STARTUP_ARG);
    // One VaultRust per user session. Starting it again brings the running
    // copy forward (except when Windows starts it at sign-in). After an
    // update the old copy is still closing, so wait for it.
    let after_update = std::env::args().any(|a| a == UPDATED_ARG);
    let wait = if after_update {
        Duration::from_secs(20)
    } else {
        Duration::ZERO
    };
    let _instance = match crate::os_protect::single_instance(wait) {
        crate::os_protect::Instance::First(guard) => guard,
        crate::os_protect::Instance::AlreadyRunning => {
            if !startup {
                crate::os_protect::activate_running_instance();
            }
            return Ok(());
        }
    };
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
        Box::new(|cc| {
            let mut app = VaultRustApp::new(&cc.egui_ctx);
            app.prefs = AppPrefs::load();
            let window = app.window.clone();
            app.minimize_on_start = startup;

            // Global shortcuts (quick open, auto-type): each press is passed
            // to the UI thread. The window may be hidden in the notification
            // area, where it gets no frames, so it is shown from here.
            let (tx, rx) = mpsc::channel();
            {
                let (tx, ctx, w) = (tx.clone(), cc.egui_ctx.clone(), window.clone());
                crate::os_protect::listen_for_activation(move || {
                    crate::os_protect::show_window(w.load(Ordering::Relaxed));
                    let _ = tx.send(HotkeyEvent::Activate);
                    ctx.request_repaint();
                });
            }
            let ctx = cc.egui_ctx.clone();
            let w = window.clone();
            app.hotkey_status = crate::os_protect::register_hotkeys(move |event| {
                crate::os_protect::show_window(w.load(Ordering::Relaxed));
                let _ = tx.send(event);
                ctx.request_repaint();
            });
            app.hotkeys = Some(rx);

            match tray::create(&cc.egui_ctx, window, app.unlocked.clone()) {
                Some((icon, rx)) => {
                    app.tray = Some(icon);
                    app.tray_events = Some(rx);
                    app.hide_on_start = startup && app.prefs.close_to_tray;
                }
                None => app.toasts.error("Couldn't add the notification-area icon"),
            }
            Ok(Box::new(app))
        }),
    )
}

/// Passed to the new program when it is started after an update.
const UPDATED_ARG: &str = "--updated";

/// The notification-area (system tray) icon and its menu.
mod tray {
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::Arc;

    use eframe::egui;
    use tray_icon::menu::{
        Icon as MenuIcon, IconMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem,
    };
    use tray_icon::{
        Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };

    use super::icons;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Action {
        Open,
        QuickOpen,
        Lock,
        Settings,
        Quit,
    }

    /// The icon plus the menu items that change with the vault's state.
    pub struct Tray {
        icon: TrayIcon,
        status: MenuItem,
        lock: IconMenuItem,
        shown: Option<Option<String>>,
    }

    impl Tray {
        /// Show which vault is unlocked (`None` = locked) in the menu's
        /// heading and the tooltip; "Lock now" is only enabled when unlocked.
        pub fn set_state(&mut self, unlocked: Option<&str>) {
            let state = unlocked.map(str::to_string);
            if self.shown.as_ref() == Some(&state) {
                return;
            }
            let text = match &state {
                Some(name) => format!("{name} — unlocked"),
                None => "Locked".to_string(),
            };
            self.status.set_text(format!("VaultRust  ·  {text}"));
            self.lock.set_enabled(state.is_some());
            let _ = self.icon.set_tooltip(Some(format!("VaultRust — {text}")));
            self.shown = Some(state);
        }
    }

    /// A Phosphor glyph rendered as a menu icon, sized for the display scale
    /// and coloured for a light or dark menu.
    fn glyph(g: &str, dark: bool) -> Option<MenuIcon> {
        use ab_glyph::{Font, FontRef, PxScale};
        let px = (16 * crate::os_protect::system_scale_percent() / 100).clamp(16, 48);
        let font = FontRef::try_from_slice(egui_phosphor::Variant::Regular.font_bytes()).ok()?;
        let id = font.glyph_id(g.chars().next()?);
        let outline = font.outline_glyph(id.with_scale(PxScale::from(px as f32)))?;
        let b = outline.px_bounds();
        let ox = ((px as f32 - b.width()) / 2.0).round() as i32;
        let oy = ((px as f32 - b.height()) / 2.0).round() as i32;
        let rgb: [u8; 3] = if dark {
            [0xd8, 0xd8, 0xd8]
        } else {
            [0x40, 0x40, 0x40]
        };
        let mut rgba = vec![0u8; (px * px * 4) as usize];
        outline.draw(|x, y, c| {
            let (x, y) = (x as i32 + ox, y as i32 + oy);
            if (0..px as i32).contains(&x) && (0..px as i32).contains(&y) {
                let i = ((y as u32 * px + x as u32) * 4) as usize;
                rgba[i..i + 3].copy_from_slice(&rgb);
                rgba[i + 3] = (c.clamp(0.0, 1.0) * 255.0) as u8;
            }
        });
        MenuIcon::from_rgba(rgba, px, px).ok()
    }

    /// Build the icon. Menu and click handlers run on the UI thread while
    /// winit dispatches messages, even when the main window is hidden, so
    /// they show the window themselves before handing the action over.
    pub fn create(
        ctx: &egui::Context,
        window: Arc<AtomicIsize>,
        unlocked: Arc<AtomicBool>,
    ) -> Option<(Tray, Receiver<Action>)> {
        crate::os_protect::follow_system_menu_theme();
        let dark = crate::os_protect::system_prefers_dark();
        let item =
            |text: String, icon: &str| IconMenuItem::new(text, true, glyph(icon, dark), None);

        let status = MenuItem::new("VaultRust  ·  Locked", false, None);
        let open = item("Open VaultRust".into(), icons::APP_WINDOW);
        let quick = item(
            format!("Quick open	{}", crate::os_protect::QUICK_OPEN_HOTKEY),
            icons::MAGNIFYING_GLASS,
        );
        let lock = item("Lock now".into(), icons::LOCK);
        lock.set_enabled(false);
        let settings = item("Settings".into(), icons::GEAR_SIX);
        let quit = item("Quit".into(), icons::POWER);
        let menu = Menu::new();
        menu.append_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &open,
            &quick,
            &lock,
            &PredefinedMenuItem::separator(),
            &settings,
            &quit,
        ])
        .ok()?;
        let ids = [
            (open.id().clone(), Action::Open),
            (quick.id().clone(), Action::QuickOpen),
            (lock.id().clone(), Action::Lock),
            (settings.id().clone(), Action::Settings),
            (quit.id().clone(), Action::Quit),
        ];
        let icon = super::theme::app_icon();
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip("VaultRust — Locked")
            .with_icon(Icon::from_rgba(icon.rgba, icon.width, icon.height).ok()?)
            .build()
            .ok()?;

        let (tx, rx) = mpsc::channel();
        let dispatch = {
            let ctx = ctx.clone();
            move |action: Action| {
                let handle = window.load(Ordering::Relaxed);
                match action {
                    // Hidden in the tray means locked: nothing to save, and
                    // the clipboard was cleared when it locked.
                    Action::Quit if !unlocked.load(Ordering::Relaxed) => std::process::exit(0),
                    Action::Lock => {}
                    _ => crate::os_protect::show_window(handle),
                }
                let _ = tx.send(action);
                ctx.request_repaint();
            }
        };
        let on_menu = dispatch.clone();
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
            if let Some((_, action)) = ids.iter().find(|(id, _)| *id == e.id) {
                on_menu(*action);
            }
        }));
        TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = e
            {
                dispatch(Action::Open);
            }
        }));
        Some((
            Tray {
                icon: tray,
                status,
                lock,
                shown: None,
            },
            rx,
        ))
    }
}

/// Shared services handed to every screen.
pub struct Services<'a> {
    pub clipboard: &'a mut ClipboardGuard,
    pub toasts: &'a mut Toasts,
    pub recent: &'a mut RecentVaults,
    /// App-level preferences (theme, close button).
    pub prefs: &'a mut AppPrefs,
    /// Which global hotkeys are registered.
    pub hotkeys: HotkeyStatus,
    /// The notification-area icon exists.
    pub tray: bool,
    pub updates: &'a mut updates::Updates,
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
    prefs: AppPrefs,
    clipboard: ClipboardGuard,
    toasts: Toasts,
    styled: bool,
    /// The theme currently applied (`Some(true)` = dark).
    dark_applied: Option<bool>,
    /// Screen-capture exclusion currently applied to the window.
    capture_hidden: Option<bool>,
    /// Presses of the global hotkeys.
    hotkeys: Option<Receiver<HotkeyEvent>>,
    hotkey_status: HotkeyStatus,
    /// Auto-type requested while the vault was locked: the picker opens once
    /// it is unlocked (if that happens within a couple of minutes).
    pending_auto_type: Option<(ForeignWindow, Instant)>,
    tray: Option<tray::Tray>,
    tray_events: Option<Receiver<tray::Action>>,
    /// The main window's HWND, for showing it from the tray and hotkeys.
    window: Arc<AtomicIsize>,
    updates: updates::Updates,
    /// Hide into the notification area on the first frame (started at
    /// sign-in with "keep running in the notification area" on).
    hide_on_start: bool,
    /// Minimise on the first frame (started at sign-in).
    minimize_on_start: bool,
    /// A vault is unlocked (read by the tray's Quit handler).
    unlocked: Arc<AtomicBool>,
    /// The user chose Quit: let the close go through.
    quitting: bool,
    /// Vaults opened with their master password (or created) since the app
    /// started. Windows Hello is only offered for these.
    password_unlocked: HashSet<PathBuf>,
}

/// How long an auto-type request survives a pending unlock.
const PENDING_AUTO_TYPE: Duration = Duration::from_secs(120);

fn path_key(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
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
            prefs: AppPrefs::in_memory(),
            clipboard: ClipboardGuard::new(),
            toasts: Toasts::default(),
            styled: false,
            dark_applied: None,
            capture_hidden: None,
            hotkeys: None,
            hotkey_status: HotkeyStatus::default(),
            pending_auto_type: None,
            tray: None,
            tray_events: None,
            window: Arc::new(AtomicIsize::new(0)),
            hide_on_start: false,
            updates: updates::Updates::default(),
            minimize_on_start: false,
            unlocked: Arc::new(AtomicBool::new(false)),
            quitting: false,
            password_unlocked: HashSet::new(),
        }
    }

    /// The unlock screen for `path`, offering Windows Hello if the master
    /// password was already used for this vault since the app started.
    fn unlock_screen(&self, path: PathBuf) -> Screen {
        let hello = self.password_unlocked.contains(&path_key(&path));
        Screen::Unlock(Box::new(unlock::UnlockState::new(path).allow_hello(hello)))
    }

    /// Bring the window forward after a global hotkey press and show quick
    /// open or the auto-type picker (or the password field, if the vault is
    /// locked).
    fn handle_hotkey(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.hotkeys else { return };
        let events: Vec<HotkeyEvent> = rx.try_iter().collect();
        for event in events {
            if let HotkeyEvent::AutoType(None) = event {
                // Pressed while VaultRust itself was in front: nothing to
                // type into.
                self.toasts.info(format!(
                    "Click into a login form in another app, then press {}",
                    crate::os_protect::AUTO_TYPE_HOTKEY
                ));
                continue;
            }
            Self::bring_forward(ctx);
            match (event, &mut self.screen) {
                (HotkeyEvent::QuickOpen, Screen::Main(m)) => m.open_quick_open(true),
                (HotkeyEvent::AutoType(Some(w)), Screen::Main(m)) => m.open_auto_type(w),
                (HotkeyEvent::AutoType(Some(w)), Screen::Unlock(u)) => {
                    self.pending_auto_type = Some((w, Instant::now()));
                    u.focus();
                }
                (_, Screen::Unlock(u)) => u.focus(),
                _ => {}
            }
        }
    }

    fn bring_forward(ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn handle_tray(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.tray_events else { return };
        let actions: Vec<tray::Action> = rx.try_iter().collect();
        for action in actions {
            match action {
                tray::Action::Open => Self::bring_forward(ctx),
                tray::Action::QuickOpen => {
                    Self::bring_forward(ctx);
                    match &mut self.screen {
                        Screen::Main(m) => m.open_quick_open(true),
                        Screen::Unlock(u) => u.focus(),
                        _ => {}
                    }
                }
                tray::Action::Lock => {
                    if matches!(self.screen, Screen::Main(_)) {
                        self.apply(ctx, Transition::Lock);
                    }
                }
                tray::Action::Settings => {
                    Self::bring_forward(ctx);
                    if let Screen::Main(m) = &mut self.screen {
                        m.request(main_view::Nav::Page(main_view::Page::Settings));
                    }
                }
                tray::Action::Quit => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    /// The close button: with the tray icon (and the preference on), lock
    /// and hide instead of quitting. Locking first matters: a hidden window
    /// may get no frames, so the inactivity timer could not lock it later.
    fn handle_close(&mut self, ctx: &egui::Context) {
        if !ctx.input(|i| i.viewport().close_requested()) || self.quitting {
            return;
        }
        if self.tray.is_none() || !self.prefs.close_to_tray {
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        if matches!(self.screen, Screen::Main(_)) {
            self.apply(ctx, Transition::Lock);
        }
        // Through winit, not ShowWindow directly: hiding behind its back
        // left it painting into a window it believed was visible.
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
    }

    /// Follow the theme preference (and, for "System", Windows' setting).
    fn sync_theme(&mut self, ctx: &egui::Context) {
        let system_dark = ctx.system_theme().map(|t| t == egui::Theme::Dark);
        let dark = self.prefs.theme.is_dark(system_dark);
        if self.dark_applied != Some(dark) {
            theme::apply(ctx, dark);
            self.dark_applied = Some(dark);
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
            theme::install(ctx);
            self.sync_theme(ctx);
            self.styled = true;
            ctx.request_repaint();
            return;
        }
        self.sync_theme(ctx);
        self.clipboard.tick(Instant::now());
        self.handle_hotkey(ctx);
        self.handle_tray(ctx);
        self.handle_close(ctx);
        if let Some(t) = &mut self.tray {
            match &self.screen {
                Screen::Main(m) => t.set_state(Some(&m.vault.data().name)),
                _ => t.set_state(None),
            }
        }
        let minimize = std::mem::take(&mut self.minimize_on_start);
        if std::mem::take(&mut self.hide_on_start) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        } else if minimize {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
        if let Some(err) = self.updates.tick(ctx, &mut self.prefs) {
            self.toasts.error(err);
        }
        if self.updates.banner(ctx) {
            self.updates.install_now(ctx);
        }
        if std::mem::take(&mut self.updates.installed) {
            self.restart_after_update(ctx);
            return;
        }
        let mut svc = Services {
            clipboard: &mut self.clipboard,
            toasts: &mut self.toasts,
            recent: &mut self.recent,
            prefs: &mut self.prefs,
            hotkeys: self.hotkey_status,
            tray: self.tray.is_some(),
            updates: &mut self.updates,
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
        self.unlocked
            .store(matches!(self.screen, Screen::Main(_)), Ordering::Relaxed);
        self.toasts.show(ctx);

        // Defence in depth: the app never opens URLs / launches a browser.
        ctx.output_mut(|o| {
            o.commands
                .retain(|c| !matches!(c, egui::OutputCommand::OpenUrl(_)))
        });
        // Keep timers (auto-lock, clipboard clearing) ticking while idle.
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    /// The new program is in place: lock (which saves) and start it.
    fn restart_after_update(&mut self, ctx: &egui::Context) {
        if matches!(self.screen, Screen::Main(_)) {
            self.apply(ctx, Transition::Lock);
        }
        let started = std::env::current_exe()
            .and_then(|exe| std::process::Command::new(exe).arg(UPDATED_ARG).spawn());
        match started {
            Ok(_) => {
                self.quitting = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Err(e) => self.toasts.error(format!(
                "Updated — start VaultRust again to use the new version ({e})"
            )),
        }
    }

    fn apply(&mut self, ctx: &egui::Context, t: Transition) {
        match t {
            Transition::Welcome => self.screen = Screen::Welcome(welcome::WelcomeState),
            Transition::Create => self.screen = Screen::Create(Box::default()),
            Transition::Unlock(p) => self.screen = self.unlock_screen(p),
            Transition::Open(v) => {
                self.recent.push(v.path());
                self.password_unlocked.insert(path_key(v.path()));
                self.forget_ui_state(ctx);
                let mut main = main_view::MainState::new(*v);
                if let Some((w, at)) = self.pending_auto_type.take() {
                    if at.elapsed() < PENDING_AUTO_TYPE {
                        main.open_auto_type(w);
                    }
                }
                self.screen = Screen::Main(Box::new(main));
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
                    Some(p) => self.unlock_screen(p),
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
                    Some(p) => self.unlock_screen(p),
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
        use raw_window_handle::HasWindowHandle;
        if self.window.load(Ordering::Relaxed) == 0 {
            if let Ok(h) = frame.window_handle() {
                if let raw_window_handle::RawWindowHandle::Win32(w) = h.as_raw() {
                    self.window.store(w.hwnd.get(), Ordering::Relaxed);
                }
            }
        }
        self.frame(ctx);
        let want = self.wants_capture_hidden();
        if self.capture_hidden != Some(want) {
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
