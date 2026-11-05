//! Headless UI tests driven by `egui_kittest`.
//!
//! These run the real screens without a window. They never touch the real
//! `%APPDATA%` (the recent-vault list is in memory) or the clipboard.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use secrecy::SecretString;

use super::entries::Category;
use super::main_view::{MainState, Page};
use super::modals::{Modal, RestoreState};
use super::{unlock, welcome, Screen, VaultRustApp};
use crate::crypto::KdfParams;
use crate::import_export::import_csv;
use crate::model::{Entry, EntryKind};
use crate::recent::RecentVaults;
use crate::session::AutoLock;
use crate::vault::UnlockedVault;

const PW: &str = "ui test master password";

fn fast() -> KdfParams {
    KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).unwrap()
}

fn sample_vault(path: &Path) -> UnlockedVault {
    let mut v =
        UnlockedVault::create(path, &SecretString::from(PW), fast(), "UI Test", false).unwrap();
    let mut items = Vec::new();
    for kind in EntryKind::ALL {
        let mut e = Entry::new(kind);
        e.title = format!("Sample {}", kind.label());
        for f in &mut e.fields {
            f.value = format!("{} value", f.label);
        }
        e.notes = "Some notes".into();
        items.push(e);
    }
    let mut weak = Entry::new(EntryKind::Login);
    weak.title = "Weak one".into();
    weak.fields[3].value = "password1".into();
    items.push(weak.clone());
    let mut reused = Entry::new(EntryKind::Login);
    reused.title = "Reused one".into();
    reused.fields[3].value = "password1".into();
    items.push(reused);
    for e in items {
        v.data_mut().upsert(e);
    }
    v.save().unwrap();
    v
}

fn unlocked_app(path: &Path) -> VaultRustApp {
    let v = sample_vault(path);
    VaultRustApp::with_screen(
        Screen::Main(Box::new(MainState::new(v))),
        RecentVaults::in_memory(),
    )
}

fn harness(app: VaultRustApp) -> Harness<'static, VaultRustApp> {
    Harness::builder()
        .with_size([1200.0, 780.0])
        .build_state(|ctx, app: &mut VaultRustApp| app.frame(ctx), app)
}

fn main_state<'a>(h: &'a mut Harness<'_, VaultRustApp>) -> &'a mut MainState {
    match &mut h.state_mut().screen {
        Screen::Main(m) => m,
        _ => panic!("expected the vault to be unlocked"),
    }
}

fn is_locked(h: &Harness<'_, VaultRustApp>) -> bool {
    matches!(h.state().screen, Screen::Unlock(_))
}

fn all_pages() -> Vec<Page> {
    let mut pages = vec![
        Page::Dashboard,
        Page::Generator,
        Page::Security,
        Page::Settings,
    ];
    pages.extend(Category::ALL.into_iter().map(Page::Items));
    pages
}

#[test]
fn every_page_editor_and_modal_renders() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    h.step();

    for page in all_pages() {
        main_state(&mut h).page = page;
        h.step();
        h.step();
    }

    let first = main_state(&mut h).vault.data().entries[0].id;
    main_state(&mut h).open_entry(first);
    h.step();

    for kind in EntryKind::ALL {
        main_state(&mut h).items.new_entry(kind);
        h.step();
    }
    main_state(&mut h).items.editor = None;

    let csv = import_csv(b"name,url,username,password\nA,https://a.example,u,p\n").unwrap();
    let modals = vec![
        Modal::DeleteEntry(first),
        Modal::ExportWarning {
            understood: false,
            typed: String::new(),
        },
        Modal::Restore(Box::new(RestoreState::new(path.clone()))),
        Modal::ConfirmBackupOverwrite(PathBuf::from("backup.vault")),
        Modal::ImportPreview {
            source: PathBuf::from("export.csv"),
            result: csv,
        },
    ];
    for m in modals {
        main_state(&mut h).modal = Some(m);
        h.step();
        h.step();
        main_state(&mut h).modal = None;
    }
    assert!(!is_locked(&h));
}

#[test]
fn inactivity_timeout_locks_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = harness(unlocked_app(&dir.path().join("ui.vault")));
    h.step();
    assert!(!is_locked(&h));
    // Pretend the last input happened just over the configured 5 minutes ago.
    let long_ago = Instant::now()
        .checked_sub(Duration::from_secs(5 * 60 + 1))
        .unwrap();
    main_state(&mut h).autolock = AutoLock::new(Duration::from_secs(5 * 60), long_ago);
    h.step();
    assert!(
        is_locked(&h),
        "vault should lock once the inactivity timeout expires"
    );
}

#[test]
fn lock_button_and_shortcut_lock_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    h.step();
    h.get_by_label_contains("Lock vault").click();
    h.step();
    h.step();
    assert!(is_locked(&h));

    let mut h = harness(VaultRustApp::with_screen(
        Screen::Main(Box::new(MainState::new(
            UnlockedVault::open(&path, &SecretString::from(PW)).unwrap(),
        ))),
        RecentVaults::in_memory(),
    ));
    h.step();
    h.key_press_modifiers(eframe::egui::Modifiers::COMMAND, eframe::egui::Key::L);
    h.step();
    h.step();
    assert!(is_locked(&h));
}

#[test]
fn unlock_screen_unlocks_with_correct_password_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    drop(sample_vault(&path));
    let app = VaultRustApp::with_screen(
        Screen::Unlock(Box::new(unlock::UnlockState::new(path.clone()))),
        RecentVaults::in_memory(),
    );
    let mut h = harness(app);
    h.step();

    let try_password = |h: &mut Harness<'_, VaultRustApp>, pw: &str| {
        h.get_by_role(eframe::egui::accesskit::Role::PasswordInput)
            .type_text(pw);
        h.step();
        h.get_by(|n| {
            n.role() == eframe::egui::accesskit::Role::Button
                && n.label().is_some_and(|l| l.contains("Unlock"))
        })
        .click();
        for _ in 0..200 {
            h.step();
            std::thread::sleep(Duration::from_millis(10));
            if !matches!(&h.state().screen, Screen::Unlock(s) if s.is_busy()) {
                break;
            }
        }
    };

    try_password(&mut h, "definitely the wrong password");
    assert!(is_locked(&h), "wrong password must not unlock");

    try_password(&mut h, PW);
    assert!(
        matches!(h.state().screen, Screen::Main(_)),
        "correct password should unlock"
    );
}

#[test]
fn creating_an_item_through_the_editor_persists_it_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    h.step();
    {
        let ms = main_state(&mut h);
        ms.page = Page::Items(Category::Logins);
        ms.items.new_entry(EntryKind::Login);
        let ed = ms.items.editor.as_mut().unwrap();
        ed.entry.title = "Created in UI".into();
        ed.entry.fields[3].value = "UI-created-secret-value-42".into();
    }
    h.step();
    h.get_by_label("Save").click();
    h.step();
    h.step();
    assert!(
        main_state(&mut h).items.editor.is_none(),
        "editor should close after saving"
    );

    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes
        .windows(26)
        .any(|w| w == b"UI-created-secret-value-42"));
    let reopened = UnlockedVault::open(&path, &SecretString::from(PW)).unwrap();
    assert!(reopened
        .data()
        .entries
        .iter()
        .any(|e| e.title == "Created in UI"
            && e.primary_password() == Some("UI-created-secret-value-42")));
}

#[test]
fn welcome_screen_renders() {
    let mut h = harness(VaultRustApp::with_screen(
        Screen::Welcome(welcome::WelcomeState),
        RecentVaults::in_memory(),
    ));
    h.step();
    h.get_by_label_contains("Create a new vault").click();
    h.step();
    assert!(matches!(h.state().screen, Screen::Create(_)));
    h.step();
}

/// Renders every screen to PNG files for visual review:
///
/// ```text
/// set VAULTRUST_SCREENSHOT_DIR=C:\some\dir
/// cargo test --lib render_screenshots -- --ignored
/// ```
#[test]
#[ignore = "visual review helper; needs a GPU or WARP adapter"]
fn render_screenshots() {
    let out = PathBuf::from(
        std::env::var("VAULTRUST_SCREENSHOT_DIR").expect("set VAULTRUST_SCREENSHOT_DIR"),
    );
    std::fs::create_dir_all(&out).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Screenshots.vault");

    let shoot = |h: &mut Harness<'_, VaultRustApp>, name: &str| {
        for _ in 0..3 {
            h.step();
        }
        h.render()
            .unwrap()
            .save(out.join(format!("{name}.png")))
            .unwrap();
    };

    let mut h = harness(VaultRustApp::with_screen(
        Screen::Welcome(welcome::WelcomeState),
        RecentVaults::in_memory(),
    ));
    shoot(&mut h, "01-welcome");
    h.state_mut().screen = Screen::Create(Box::default());
    shoot(&mut h, "02-create");

    drop(sample_vault(&path));
    h.state_mut().screen = Screen::Unlock(Box::new(unlock::UnlockState::new(path.clone())));
    shoot(&mut h, "03-unlock");

    // Home with an empty vault.
    let empty_path = dir.path().join("Empty.vault");
    let empty = UnlockedVault::create(
        &empty_path,
        &SecretString::from(PW),
        fast(),
        "Personal",
        false,
    )
    .unwrap();
    h.state_mut().screen = Screen::Main(Box::new(MainState::new(empty)));
    shoot(&mut h, "03b-home-empty");

    let mut v = UnlockedVault::open(&path, &SecretString::from(PW)).unwrap();
    for e in v.data_mut().entries.iter_mut().take(4) {
        e.favorite = true;
    }
    v.data_mut().last_backup = crate::timeutil::now_unix() - 3 * 86_400;
    v.save().unwrap();
    h.state_mut().screen = Screen::Main(Box::new(MainState::new(v)));
    main_state(&mut h).home_query = "sample".into();
    shoot(&mut h, "04b-home-search");
    main_state(&mut h).home_query.clear();
    let pages = [
        ("04-dashboard", Page::Dashboard),
        ("05-logins", Page::Items(Category::Logins)),
        ("06-notes", Page::Items(Category::Notes)),
        ("07-cards", Page::Items(Category::Cards)),
        ("08-api-keys", Page::Items(Category::ApiKeys)),
        ("09-generator", Page::Generator),
        ("10-security", Page::Security),
        ("11-settings", Page::Settings),
    ];
    for (name, page) in pages {
        let ms = main_state(&mut h);
        ms.page = page;
        if let Page::Items(c) = page {
            let id = ms
                .vault
                .data()
                .entries
                .iter()
                .find(|e| c.includes(e))
                .map(|e| e.id);
            if let Some(id) = id {
                ms.items.select(id);
            }
        }
        shoot(&mut h, name);
    }
    main_state(&mut h).items.new_entry(EntryKind::Login);
    main_state(&mut h).page = Page::Items(Category::Logins);
    shoot(&mut h, "12-editor");
    main_state(&mut h).modal = Some(Modal::ExportWarning {
        understood: false,
        typed: String::new(),
    });
    shoot(&mut h, "13-export-warning");
}

#[test]
fn unsaved_edits_are_not_discarded_without_asking() {
    use super::main_view::Nav;
    let dir = tempfile::tempdir().unwrap();
    let mut h = harness(unlocked_app(&dir.path().join("ui.vault")));
    h.step();
    let ms = main_state(&mut h);
    ms.page = Page::Items(Category::Logins);
    ms.items.new_entry(EntryKind::Login);

    // Clean editor: navigation just closes it.
    ms.request(Nav::Page(Page::Generator));
    assert!(ms.modal.is_none());
    assert!(ms.items.editor.is_none());
    assert_eq!(ms.page, Page::Generator);

    // Dirty editor: navigation asks first and changes nothing yet.
    ms.page = Page::Items(Category::Logins);
    ms.items.new_entry(EntryKind::Login);
    ms.items.editor.as_mut().unwrap().entry.title = "typed something".into();
    ms.request(Nav::Page(Page::Settings));
    assert!(matches!(ms.modal, Some(Modal::DiscardEdits(_))));
    assert!(ms.items.editor.is_some());
    assert_eq!(ms.page, Page::Items(Category::Logins));
}
