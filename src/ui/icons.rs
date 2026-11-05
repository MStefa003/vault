//! Icon mapping (Phosphor icon font, bundled — never downloaded).

pub use egui_phosphor::regular::*;

use crate::model::EntryKind;

pub fn kind_icon(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Login => KEY,
        EntryKind::Email => ENVELOPE_SIMPLE,
        EntryKind::SecureNote => NOTE,
        EntryKind::CreditCard => CREDIT_CARD,
        EntryKind::Identity => IDENTIFICATION_CARD,
        EntryKind::ApiKey => CODE,
        EntryKind::Server => HARD_DRIVES,
        EntryKind::Database => DATABASE,
        EntryKind::Wifi => WIFI_HIGH,
        EntryKind::Custom => PUZZLE_PIECE,
    }
}

/// "icon  text" for buttons and menu items.
pub fn with(icon: &str, text: &str) -> String {
    format!("{icon}  {text}")
}
