//! Clipboard copy with automatic clearing.
//!
//! On Windows, copied secrets are tagged so they are excluded from Clipboard
//! History (Win+V) and from Cloud Clipboard sync. Clearing is best effort:
//! another application may read the clipboard before it is cleared, and
//! clipboard managers that ignore the exclusion flags may keep a copy.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

pub struct ClipboardGuard {
    /// What we placed on the clipboard, so we only clear our own content.
    owned: Option<Zeroizing<String>>,
    clear_at: Option<Instant>,
}

impl Default for ClipboardGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ClipboardGuard {
    pub fn new() -> Self {
        ClipboardGuard {
            owned: None,
            clear_at: None,
        }
    }

    /// Copy `text` and schedule it to be cleared after `clear_after`.
    pub fn copy_secret(&mut self, text: &str, clear_after: Duration) -> Result<(), String> {
        let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
        set_excluded(&mut cb, text).map_err(|e| e.to_string())?;
        self.owned = Some(Zeroizing::new(text.to_string()));
        self.clear_at = Some(Instant::now() + clear_after);
        Ok(())
    }

    /// Seconds until the clipboard is cleared, if a clear is pending.
    pub fn pending_clear(&self, now: Instant) -> Option<Duration> {
        self.clear_at.map(|t| t.saturating_duration_since(now))
    }

    /// Call periodically; clears the clipboard once the deadline passes.
    pub fn tick(&mut self, now: Instant) {
        if self.clear_at.is_some_and(|t| now >= t) {
            self.clear_now();
        }
    }

    /// Clear the clipboard if it still holds what we copied.
    pub fn clear_now(&mut self) {
        if let Some(owned) = self.owned.take() {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                let still_ours = cb
                    .get_text()
                    .map(|t| Zeroizing::new(t).as_str() == owned.as_str())
                    .unwrap_or(false);
                if still_ours {
                    let _ = cb.clear();
                    // Some applications treat an empty clipboard oddly; make
                    // sure the secret is gone even if `clear` was a no-op.
                    let _ = set_excluded(&mut cb, "");
                }
            }
        }
        self.clear_at = None;
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        self.clear_now();
    }
}

#[cfg(windows)]
fn set_excluded(cb: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    use arboard::SetExtWindows;
    cb.set()
        .exclude_from_history()
        .exclude_from_cloud()
        .exclude_from_monitoring()
        .text(text)
}

#[cfg(not(windows))]
fn set_excluded(cb: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    cb.set_text(text)
}
