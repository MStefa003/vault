//! Operating-system integration and protection.
//!
//! This is the only module that contains `unsafe` code: a handful of Win32
//! calls, each documented where it is made.
//!
//! * `SetWindowDisplayAffinity` asks Windows to exclude the window from
//!   screenshots, screen recording and screen sharing (Windows 10 2004+ shows
//!   nothing in captures; older versions show a black rectangle).
//! * `OpenInputDesktop` tells whether the interactive session is locked
//!   (Win+L, the sign-in screen after sleep, switching user), so the vault
//!   can lock with it.
//! * `WerSetFlags` / `SetErrorMode` keep the process heap — where decrypted
//!   entries live — out of Windows Error Reporting crash reports.
//! * `RegisterHotKey` plus a message loop on a dedicated thread implement the
//!   global quick-open shortcut.
//! * `RegGetValueW` / `RegSetKeyValueW` / `RegDeleteKeyValueW` manage the
//!   per-user `Run` value that starts VaultRust when the user signs in.
//! * `BitBlt` / `GetDIBits` take one in-memory screenshot when the user asks
//!   to scan a two-step verification QR code (wiped right after decoding).
//! * WinHTTP fetches update information and signed releases from GitHub
//!   over HTTPS (see `update.rs`); Windows' own TLS and certificate store
//!   are used, so no networking library is bundled.
//! * uxtheme's `SetPreferredAppMode` (by ordinal) lets popup menus — the
//!   notification-area menu — follow Windows' dark mode.
//!
//! Like any OS-level measure these are best effort (e.g. a camera pointed at
//! the screen, an administrator-configured full crash dump, or malware with
//! kernel access is not affected).

#![allow(unsafe_code)]

/// Returns true if the requested state was applied.
#[cfg(all(windows, feature = "gui"))]
pub fn set_capture_excluded(handle: raw_window_handle::RawWindowHandle, exclude: bool) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR, WDA_NONE,
    };
    let raw_window_handle::RawWindowHandle::Win32(h) = handle else {
        return false;
    };
    let hwnd = h.hwnd.get() as *mut core::ffi::c_void;
    // SAFETY: `hwnd` is the live top-level window handle provided by winit
    // for this process's own window; the call only changes a display flag.
    unsafe {
        if !exclude {
            return SetWindowDisplayAffinity(hwnd, WDA_NONE) != 0;
        }
        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) != 0
            || SetWindowDisplayAffinity(hwnd, WDA_MONITOR) != 0
    }
}

#[cfg(all(not(windows), feature = "gui"))]
pub fn set_capture_excluded(_handle: raw_window_handle::RawWindowHandle, _exclude: bool) -> bool {
    false
}

/// Whether the interactive Windows session is currently locked.
///
/// When the session is locked (or the secure desktop is showing, e.g. a UAC
/// prompt), a normal process cannot open the input desktop for switching.
/// Erring towards "locked" is deliberate: the worst case is an extra unlock.
#[cfg(windows)]
pub fn is_session_locked() -> bool {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, OpenInputDesktop, DESKTOP_SWITCHDESKTOP,
    };
    // SAFETY: OpenInputDesktop has no preconditions; a non-null handle is
    // owned by us and closed immediately.
    unsafe {
        let desk = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);
        if desk.is_null() {
            return true;
        }
        CloseDesktop(desk);
        false
    }
}

#[cfg(not(windows))]
pub fn is_session_locked() -> bool {
    false
}

/// Process-wide hardening applied once at start-up: crash reports must not
/// include heap memory, and no "program stopped working" dialog is shown.
#[cfg(windows)]
pub fn harden_process() {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    };
    use windows_sys::Win32::System::ErrorReporting::{
        WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP,
    };
    // SAFETY: both calls only set flags for the current process.
    unsafe {
        let _ = WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
        let previous = SetErrorMode(0);
        SetErrorMode(previous | SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }
}

#[cfg(not(windows))]
pub fn harden_process() {}

/// The Windows Hello prompt opened by a desktop app often appears behind
/// it. For a few seconds, look for the prompt's window and bring it forward.
#[cfg(windows)]
pub fn focus_hello_prompt_soon() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
    let _ = std::thread::Builder::new()
        .name("vaultrust-hello-focus".into())
        .spawn(|| {
            let class: Vec<u16> = "Credential Dialog Xaml Host\0".encode_utf16().collect();
            for _ in 0..50 {
                // SAFETY: `class` is a NUL-terminated UTF-16 string; a null
                // title matches any window of that class.
                let h = unsafe { FindWindowW(class.as_ptr(), std::ptr::null()) };
                if !h.is_null() {
                    // SAFETY: `h` was just returned by FindWindowW.
                    unsafe { SetForegroundWindow(h) };
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
}

#[cfg(not(windows))]
pub fn focus_hello_prompt_soon() {}

/// Show a window of this process (from any thread) and bring it forward:
/// used to wake VaultRust from the notification area.
#[cfg(windows)]
pub fn show_window(handle: isize) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IsIconic, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
    };
    if handle == 0 {
        return;
    }
    let hwnd = handle as windows_sys::Win32::Foundation::HWND;
    // SAFETY: ShowWindow / IsIconic / SetForegroundWindow accept any handle;
    // this is our own top-level window.
    unsafe {
        ShowWindow(
            hwnd,
            if IsIconic(hwnd) != 0 {
                SW_RESTORE
            } else {
                SW_SHOW
            },
        );
        SetForegroundWindow(hwnd);
    }
}

#[cfg(not(windows))]
pub fn show_window(_handle: isize) {}

/// Shortcut shown in the UI for the global quick-open hotkey.
pub const QUICK_OPEN_HOTKEY: &str = "Ctrl+Shift+Space";
/// Shortcut shown in the UI for the global auto-type hotkey. Not Ctrl+Alt+…:
/// on many keyboard layouts that is AltGr, and grabbing it system-wide would
/// break typing characters such as ą or €.
pub const AUTO_TYPE_HOTKEY: &str = "Ctrl+Shift+L";

/// A window of another application, captured when the auto-type hotkey was
/// pressed.
#[derive(Clone, Debug)]
pub struct ForeignWindow {
    /// The HWND, stored as an integer so the value can cross threads.
    #[cfg_attr(not(windows), allow(dead_code))]
    handle: isize,
    pub title: String,
}

/// A press of one of the global hotkeys.
pub enum HotkeyEvent {
    QuickOpen,
    /// The window that was in front when the hotkey was pressed, or `None`
    /// if it was VaultRust itself (or there was none).
    AutoType(Option<ForeignWindow>),
}

/// Which global hotkeys could be registered (another application may own
/// the same shortcut).
#[derive(Debug, Clone, Copy, Default)]
pub struct HotkeyStatus {
    pub quick_open: bool,
    pub auto_type: bool,
}

/// The foreground window, unless it belongs to this process.
#[cfg(windows)]
pub fn foreground_window() -> Option<ForeignWindow> {
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
    };
    // SAFETY: plain queries on a window handle Windows just gave us; the
    // title buffer is a stack array whose length is passed along.
    unsafe {
        let h = GetForegroundWindow();
        if h.is_null() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(h, &mut pid);
        if pid == GetCurrentProcessId() {
            return None;
        }
        let mut buf = [0u16; 512];
        let n = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32);
        let title = String::from_utf16_lossy(&buf[..n.max(0) as usize]);
        Some(ForeignWindow {
            handle: h as isize,
            title,
        })
    }
}

#[cfg(not(windows))]
pub fn foreground_window() -> Option<ForeignWindow> {
    None
}

/// Register the global hotkeys (quick open and auto-type) on a dedicated
/// thread. `on_event` runs on that thread for every press. For auto-type the
/// foreground window is captured right there, before VaultRust comes
/// forward, so it is the window the user was looking at.
#[cfg(windows)]
pub fn register_hotkeys(on_event: impl Fn(HotkeyEvent) + Send + 'static) -> HotkeyStatus {
    use std::sync::mpsc;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        RegisterHotKey, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, VK_L, VK_SPACE,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY};

    const QUICK_OPEN: i32 = 1;
    const AUTO_TYPE: i32 = 2;
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("vaultrust-hotkeys".into())
        .spawn(move || {
            let mods = MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT;
            // SAFETY: a null HWND binds each hotkey to this thread's message
            // queue, which the loop below services for the thread's lifetime.
            let status = unsafe {
                HotkeyStatus {
                    quick_open: RegisterHotKey(
                        std::ptr::null_mut(),
                        QUICK_OPEN,
                        mods,
                        u32::from(VK_SPACE),
                    ) != 0,
                    auto_type: RegisterHotKey(
                        std::ptr::null_mut(),
                        AUTO_TYPE,
                        mods,
                        u32::from(VK_L),
                    ) != 0,
                }
            };
            let _ = tx.send(status);
            if !status.quick_open && !status.auto_type {
                return;
            }
            // SAFETY: MSG is plain data; GetMessageW fills it in.
            let mut msg: MSG = unsafe { std::mem::zeroed() };
            // SAFETY: valid pointer to `msg`; a null HWND reads this thread's
            // queue. Returns 0 on WM_QUIT and -1 on error, ending the loop.
            while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
                if msg.message != WM_HOTKEY {
                    continue;
                }
                match msg.wParam as i32 {
                    QUICK_OPEN => on_event(HotkeyEvent::QuickOpen),
                    AUTO_TYPE => on_event(HotkeyEvent::AutoType(foreground_window())),
                    _ => {}
                }
            }
        });
    if spawned.is_err() {
        return HotkeyStatus::default();
    }
    rx.recv().unwrap_or_default()
}

#[cfg(not(windows))]
pub fn register_hotkeys(_on_event: impl Fn(HotkeyEvent) + Send + 'static) -> HotkeyStatus {
    HotkeyStatus::default()
}

/// One step of an auto-type sequence. Text is wiped on drop.
pub enum TypeStep {
    Text(zeroize::Zeroizing<String>),
    Tab,
    Enter,
    /// Pause, e.g. while a site loads its password page (milliseconds).
    Delay(u32),
}

/// Never prints typed text: it is usually a password.
impl std::fmt::Debug for TypeStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeStep::Text(t) => write!(f, "Text({} chars)", t.chars().count()),
            TypeStep::Tab => f.write_str("Tab"),
            TypeStep::Enter => f.write_str("Enter"),
            TypeStep::Delay(ms) => write!(f, "Delay({ms})"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AutoTypeError {
    #[error("the window to type into has closed")]
    WindowGone,
    #[error("couldn't switch to the window to type into")]
    Focus,
    #[error("another window took focus, so typing stopped")]
    FocusLost,
    #[error("release Ctrl, Shift and Alt so typing can start")]
    KeysHeld,
    #[error("Windows blocked the typing (the target app may be running as administrator)")]
    Blocked,
    #[error("auto-type is only available on Windows")]
    Unsupported,
}

/// Bring `target` to the front and type `steps` into it.
///
/// Characters are sent as Unicode key events, so they arrive correctly
/// whatever the keyboard layout. Before every key the foreground window is
/// checked: if anything else took focus, typing stops at once rather than
/// sending the rest of a password to the wrong place.
#[cfg(windows)]
pub fn auto_type(target: &ForeignWindow, steps: &[TypeStep]) -> Result<(), AutoTypeError> {
    use std::thread::sleep;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VK_CONTROL, VK_LWIN, VK_MENU, VK_RETURN, VK_RWIN, VK_SHIFT, VK_TAB,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, IsWindow, SetForegroundWindow,
    };

    let hwnd = target.handle as windows_sys::Win32::Foundation::HWND;
    // SAFETY: IsWindow / SetForegroundWindow / GetForegroundWindow accept
    // any handle value; a stale one is simply reported as not a window.
    unsafe {
        if IsWindow(hwnd) == 0 {
            return Err(AutoTypeError::WindowGone);
        }
        SetForegroundWindow(hwnd);
    }
    let focused = || unsafe { GetForegroundWindow() } == hwnd;
    let started = Instant::now();
    while !focused() {
        if started.elapsed() > Duration::from_millis(1500) {
            return Err(AutoTypeError::Focus);
        }
        sleep(Duration::from_millis(20));
    }
    // Wait for the user to let go of the keys they pressed to confirm (a
    // held Shift would turn Tab into Shift+Tab).
    let held = || {
        [VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN]
            .iter()
            // SAFETY: GetAsyncKeyState only reads key state.
            .any(|&vk| unsafe { GetAsyncKeyState(i32::from(vk)) } < 0)
    };
    let started = Instant::now();
    while held() {
        if started.elapsed() > Duration::from_secs(3) {
            return Err(AutoTypeError::KeysHeld);
        }
        sleep(Duration::from_millis(20));
    }
    // Let the window finish activating before the first key.
    sleep(Duration::from_millis(80));

    for step in steps {
        match step {
            TypeStep::Text(text) => {
                for unit in text.encode_utf16() {
                    if !focused() {
                        return Err(AutoTypeError::FocusLost);
                    }
                    send_key(0, unit)?;
                    sleep(Duration::from_millis(4));
                }
            }
            TypeStep::Delay(ms) => sleep(Duration::from_millis(u64::from(*ms))),
            TypeStep::Tab | TypeStep::Enter => {
                if !focused() {
                    return Err(AutoTypeError::FocusLost);
                }
                let vk = if matches!(step, TypeStep::Tab) {
                    VK_TAB
                } else {
                    VK_RETURN
                };
                send_key(vk, 0)?;
            }
        }
        sleep(Duration::from_millis(40));
    }
    Ok(())
}

/// Press and release one key: a virtual key (`vk`), or with `vk == 0` the
/// UTF-16 code unit `unit` as a Unicode character.
#[cfg(windows)]
fn send_key(vk: u16, unit: u16) -> Result<(), AutoTypeError> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    };
    let key = |up: bool| {
        let mut flags = if vk == 0 { KEYEVENTF_UNICODE } else { 0 };
        if up {
            flags |= KEYEVENTF_KEYUP;
        }
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: unit,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    };
    let mut inputs = [key(false), key(true)];
    // SAFETY: `inputs` is a valid array of two INPUT structures and the size
    // passed is that of one INPUT, as SendInput requires.
    let sent = unsafe {
        SendInput(
            inputs.len() as u32,
            inputs.as_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        )
    };
    // The structures held a character of a secret; overwrite them.
    // SAFETY: writing zeroed plain-data structures over our own array.
    unsafe { std::ptr::write_volatile(&mut inputs, std::mem::zeroed()) };
    if sent == 2 {
        Ok(())
    } else {
        Err(AutoTypeError::Blocked)
    }
}

#[cfg(not(windows))]
pub fn auto_type(_target: &ForeignWindow, _steps: &[TypeStep]) -> Result<(), AutoTypeError> {
    Err(AutoTypeError::Unsupported)
}

impl ForeignWindow {
    /// A stand-in target for tests of the auto-type UI.
    #[cfg(test)]
    pub fn for_tests(title: &str) -> Self {
        ForeignWindow {
            handle: 0,
            title: title.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_lock_query_does_not_crash() {
        // The result depends on the machine running the tests; only check
        // that the call is safe to make.
        let _ = super::is_session_locked();
    }
}

/// Command-line flag passed when Windows starts VaultRust at sign-in.
pub const STARTUP_ARG: &str = "--startup";

/// Whether VaultRust starts when the user signs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Autostart {
    Off,
    /// Starts this copy of VaultRust.
    On,
    /// Starts a different copy (the program was moved, or another build).
    OtherCopy(String),
}

#[cfg(windows)]
mod run_key {
    pub const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    pub const VALUE: &str = "VaultRust";

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The command this executable should be started with.
    pub fn command() -> Option<String> {
        let exe = std::env::current_exe().ok()?;
        Some(format!("\"{}\" {}", exe.display(), super::STARTUP_ARG))
    }
}

#[cfg(windows)]
pub fn autostart_status() -> Autostart {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ};
    let (subkey, value) = (
        run_key::wide(run_key::SUBKEY),
        run_key::wide(run_key::VALUE),
    );
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: all pointers are valid for the stated sizes; `size` is in bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if rc != 0 {
        return Autostart::Off;
    }
    let len = (size as usize / 2).min(buf.len());
    let stored = String::from_utf16_lossy(&buf[..len])
        .trim_end_matches('\0')
        .to_string();
    match run_key::command() {
        Some(cmd) if cmd.eq_ignore_ascii_case(&stored) => Autostart::On,
        _ => Autostart::OtherCopy(stored),
    }
}

/// Turn starting at sign-in on (for this executable) or off.
#[cfg(windows)]
pub fn set_autostart(on: bool) -> Result<(), String> {
    use windows_sys::Win32::System::Registry::{
        RegDeleteKeyValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ,
    };
    let (subkey, value) = (
        run_key::wide(run_key::SUBKEY),
        run_key::wide(run_key::VALUE),
    );
    let rc = if on {
        let cmd = run_key::command().ok_or("couldn't find the program's location")?;
        let data = run_key::wide(&cmd);
        // SAFETY: `data` is a NUL-terminated UTF-16 string of the given byte
        // length; the key and value names are NUL-terminated.
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                value.as_ptr(),
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        }
    } else {
        // SAFETY: NUL-terminated names; deleting a missing value is harmless.
        let rc = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, subkey.as_ptr(), value.as_ptr()) };
        // ERROR_FILE_NOT_FOUND: already off.
        if rc == 2 {
            0
        } else {
            rc
        }
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("Windows refused the change (error {rc})"))
    }
}

#[cfg(not(windows))]
pub fn autostart_status() -> Autostart {
    Autostart::Off
}

#[cfg(not(windows))]
pub fn set_autostart(_on: bool) -> Result<(), String> {
    Err("only available on Windows".into())
}

/// Whether Windows apps are set to the dark theme.
#[cfg(windows)]
pub fn system_prefers_dark() -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
    let subkey = run_key::wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
    let value = run_key::wide("AppsUseLightTheme");
    let mut light: u32 = 1;
    let mut size = 4u32;
    // SAFETY: `light` is a valid 4-byte buffer and `size` says so.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut light as *mut u32).cast(),
            &mut size,
        )
    };
    rc == 0 && light == 0
}

/// Let this process's popup menus follow Windows' light / dark setting.
/// `SetPreferredAppMode` is exported from uxtheme.dll by ordinal only (135,
/// with `FlushMenuThemes` at 136) on Windows 10 1903 and later; on anything
/// else this does nothing and menus stay light.
#[cfg(windows)]
pub fn follow_system_menu_theme() {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    let name = run_key::wide("uxtheme.dll");
    // SAFETY: loading a system DLL by name; the ordinals are looked up and
    // only called if present, with the signatures Windows has used since
    // 1903 (`fn(i32) -> i32` and `fn()`).
    unsafe {
        let lib = LoadLibraryW(name.as_ptr());
        if lib.is_null() {
            return;
        }
        let set_mode = GetProcAddress(lib, 135 as *const u8);
        let flush = GetProcAddress(lib, 136 as *const u8);
        if let (Some(set_mode), Some(flush)) = (set_mode, flush) {
            let set_mode: unsafe extern "system" fn(i32) -> i32 = std::mem::transmute(set_mode);
            let flush: unsafe extern "system" fn() = std::mem::transmute(flush);
            // 1 = AllowDark: follow the system setting.
            set_mode(1);
            flush();
        }
    }
}

/// Display scale in percent (100 at 96 DPI).
#[cfg(windows)]
pub fn system_scale_percent() -> u32 {
    // SAFETY: no arguments; returns the system DPI.
    let dpi = unsafe { windows_sys::Win32::UI::HiDpi::GetDpiForSystem() };
    if dpi == 0 {
        100
    } else {
        dpi * 100 / 96
    }
}

#[cfg(not(windows))]
pub fn system_prefers_dark() -> bool {
    false
}

#[cfg(not(windows))]
pub fn follow_system_menu_theme() {}

#[cfg(not(windows))]
pub fn system_scale_percent() -> u32 {
    100
}

#[cfg(all(test, windows))]
mod autostart_tests {
    /// Writes the real per-user Run value (and removes it again).
    #[test]
    #[ignore = "changes the user's registry"]
    fn autostart_roundtrip() {
        use super::{autostart_status, set_autostart, Autostart};
        assert_eq!(autostart_status(), Autostart::Off);
        set_autostart(true).unwrap();
        assert_eq!(autostart_status(), Autostart::On);
        set_autostart(false).unwrap();
        assert_eq!(autostart_status(), Autostart::Off);
        set_autostart(false).unwrap();
        assert!(super::system_scale_percent() >= 100);
    }
}

/// A greyscale screenshot of every monitor (the whole virtual screen), one
/// byte per pixel, rows top to bottom. Windows marked "exclude from capture"
/// (VaultRust itself while protected) are not in it.
#[cfg(windows)]
pub fn capture_screen_gray() -> Option<(Vec<u8>, usize, usize)> {
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
        SRCCOPY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };
    use zeroize::Zeroize;
    // SAFETY: standard GDI screen copy. Every handle is checked, the
    // selected object is restored and everything created is released before
    // returning; the pixel buffer is exactly w*h*4 bytes, as described by the
    // 32-bit top-down BITMAPINFO passed to GetDIBits.
    unsafe {
        let x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if w <= 0 || h <= 0 || w > 32_768 || h > 32_768 {
            return None;
        }
        let screen = GetDC(std::ptr::null_mut());
        if screen.is_null() {
            return None;
        }
        let mem = CreateCompatibleDC(screen);
        let bmp = CreateCompatibleBitmap(screen, w, h);
        let mut pixels = vec![0u8; w as usize * h as usize * 4];
        let mut lines = 0;
        if !mem.is_null() && !bmp.is_null() {
            let old = SelectObject(mem, bmp);
            if BitBlt(mem, 0, 0, w, h, screen, x, y, SRCCOPY) != 0 {
                let mut info: BITMAPINFO = std::mem::zeroed();
                info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
                info.bmiHeader.biWidth = w;
                info.bmiHeader.biHeight = -h;
                info.bmiHeader.biPlanes = 1;
                info.bmiHeader.biBitCount = 32;
                info.bmiHeader.biCompression = BI_RGB;
                lines = GetDIBits(
                    mem,
                    bmp,
                    0,
                    h as u32,
                    pixels.as_mut_ptr().cast(),
                    &mut info,
                    DIB_RGB_COLORS,
                );
            }
            SelectObject(mem, old);
        }
        if !bmp.is_null() {
            DeleteObject(bmp);
        }
        if !mem.is_null() {
            DeleteDC(mem);
        }
        ReleaseDC(std::ptr::null_mut(), screen);
        if lines != h {
            pixels.zeroize();
            return None;
        }
        // BGRA -> luma.
        let gray = pixels
            .as_chunks::<4>()
            .0
            .iter()
            .map(|p| ((p[2] as u32 * 299 + p[1] as u32 * 587 + p[0] as u32 * 114) / 1000) as u8)
            .collect();
        pixels.zeroize();
        Some((gray, w as usize, h as usize))
    }
}

#[cfg(not(windows))]
pub fn capture_screen_gray() -> Option<(Vec<u8>, usize, usize)> {
    None
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    #[error("only https:// addresses are allowed")]
    NotHttps,
    #[error("no connection ({0})")]
    Connect(u32),
    #[error("the server answered {0}")]
    Status(u32),
    #[error("the download is larger than expected")]
    TooLarge,
    #[error("not available on this system")]
    Unsupported,
}

/// GET an `https://` URL, following redirects (never to plain http), and
/// return the body, refusing more than `max_bytes`. Blocking: call from a
/// worker thread.
#[cfg(windows)]
pub fn http_get(url: &str, max_bytes: usize) -> Result<Vec<u8>, HttpError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpAddRequestHeaders, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen,
        WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
        WinHttpSendRequest, WinHttpSetOption, WinHttpSetTimeouts,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_ADDREQ_FLAG_ADD, WINHTTP_FLAG_SECURE,
        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,
        WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
    };

    let rest = url.strip_prefix("https://").ok_or(HttpError::NotHttps)?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if host.is_empty() || host.contains(['@', ':']) {
        return Err(HttpError::NotHttps);
    }
    let w = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let agent = w(&format!(
        "VaultRust/{} (update check)",
        env!("CARGO_PKG_VERSION")
    ));
    let (host_w, path_w, verb) = (w(host), w(path), w("GET"));
    let headers = w("Accept: application/vnd.github+json, application/octet-stream");

    struct Handle(*mut core::ffi::c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: a handle returned by WinHttpOpen/Connect/OpenRequest,
                // closed exactly once.
                unsafe { WinHttpCloseHandle(self.0) };
            }
        }
    }
    let last = || unsafe { GetLastError() };

    // SAFETY: every string is NUL-terminated UTF-16 that outlives the call;
    // handles are checked for null before use and closed by `Handle` in
    // reverse order of creation; reads go into a buffer of the stated size.
    unsafe {
        let session = Handle(WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        ));
        if session.0.is_null() {
            return Err(HttpError::Connect(last()));
        }
        let protocols: u32 =
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        if WinHttpSetOption(
            session.0,
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            (&protocols as *const u32).cast(),
            4,
        ) == 0
        {
            // Older Windows without TLS 1.3 support: TLS 1.2 only.
            let tls12: u32 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
            WinHttpSetOption(
                session.0,
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                (&tls12 as *const u32).cast(),
                4,
            );
        }
        WinHttpSetTimeouts(session.0, 10_000, 10_000, 15_000, 30_000);
        let conn = Handle(WinHttpConnect(session.0, host_w.as_ptr(), 443, 0));
        if conn.0.is_null() {
            return Err(HttpError::Connect(last()));
        }
        let req = Handle(WinHttpOpenRequest(
            conn.0,
            verb.as_ptr(),
            path_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ));
        if req.0.is_null() {
            return Err(HttpError::Connect(last()));
        }
        WinHttpAddRequestHeaders(req.0, headers.as_ptr(), u32::MAX, WINHTTP_ADDREQ_FLAG_ADD);
        if WinHttpSendRequest(req.0, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) == 0
            || WinHttpReceiveResponse(req.0, std::ptr::null_mut()) == 0
        {
            return Err(HttpError::Connect(last()));
        }
        let mut status: u32 = 0;
        let mut len = 4u32;
        if WinHttpQueryHeaders(
            req.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            std::ptr::null(),
            (&mut status as *mut u32).cast(),
            &mut len,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(HttpError::Connect(last()));
        }
        if status != 200 {
            return Err(HttpError::Status(status));
        }
        let mut body = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let mut read = 0u32;
            if WinHttpReadData(
                req.0,
                chunk.as_mut_ptr().cast(),
                chunk.len() as u32,
                &mut read,
            ) == 0
            {
                return Err(HttpError::Connect(last()));
            }
            if read == 0 {
                break;
            }
            if body.len() + read as usize > max_bytes {
                return Err(HttpError::TooLarge);
            }
            body.extend_from_slice(&chunk[..read as usize]);
        }
        Ok(body)
    }
}

#[cfg(not(windows))]
pub fn http_get(_url: &str, _max_bytes: usize) -> Result<Vec<u8>, HttpError> {
    Err(HttpError::Unsupported)
}
