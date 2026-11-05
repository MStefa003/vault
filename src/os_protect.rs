//! Operating-system window protection.
//!
//! This is the only module that contains `unsafe` code: a single call to the
//! Win32 `SetWindowDisplayAffinity` API, which asks Windows to exclude the
//! window from screenshots, screen recording and screen sharing. Windows 10
//! 2004+ shows nothing in captures; older versions show a black rectangle.
//! Like any OS-level measure this is best effort (e.g. a camera pointed at the
//! screen, or malware with kernel access, is not affected).

#![allow(unsafe_code)]

use raw_window_handle::RawWindowHandle;

/// Returns true if the requested state was applied.
#[cfg(windows)]
pub fn set_capture_excluded(handle: RawWindowHandle, exclude: bool) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR, WDA_NONE,
    };
    let RawWindowHandle::Win32(h) = handle else {
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

#[cfg(not(windows))]
pub fn set_capture_excluded(_handle: RawWindowHandle, _exclude: bool) -> bool {
    false
}
