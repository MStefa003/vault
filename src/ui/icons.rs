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

/// Icons an item can be given instead of its first letter, with the key
/// stored in the vault ([`crate::model::Entry::icon`]). Keys must never
/// change; new icons are appended.
pub const ITEM_ICONS: &[(&str, &str)] = &[
    ("key", KEY),
    ("lock", LOCK),
    ("shield", SHIELD),
    ("user", USER),
    ("users", USERS),
    ("envelope", ENVELOPE_SIMPLE),
    ("chat", CHAT_CIRCLE),
    ("globe", GLOBE),
    ("cloud", CLOUD),
    ("bank", BANK),
    ("wallet", WALLET),
    ("coins", COINS),
    ("card", CREDIT_CARD),
    ("cart", SHOPPING_CART),
    ("store", STOREFRONT),
    ("briefcase", BRIEFCASE),
    ("buildings", BUILDINGS),
    ("house", HOUSE),
    ("school", GRADUATION_CAP),
    ("book", BOOK_OPEN),
    ("health", FIRST_AID_KIT),
    ("heart", HEART),
    ("game", GAME_CONTROLLER),
    ("music", MUSIC_NOTES),
    ("film", FILM_STRIP),
    ("tv", TELEVISION),
    ("camera", CAMERA),
    ("phone", DEVICE_MOBILE),
    ("desktop", DESKTOP),
    ("code", CODE),
    ("terminal", TERMINAL_WINDOW),
    ("server", HARD_DRIVES),
    ("database", DATABASE),
    ("wifi", WIFI_HIGH),
    ("plane", AIRPLANE),
    ("car", CAR),
    ("train", TRAIN),
    ("ticket", TICKET),
    ("food", FORK_KNIFE),
    ("pet", PAW_PRINT),
];

/// The glyph for an item icon key ("" or unknown = none).
pub fn item_icon(key: &str) -> Option<&'static str> {
    ITEM_ICONS.iter().find(|(k, _)| *k == key).map(|(_, g)| *g)
}
