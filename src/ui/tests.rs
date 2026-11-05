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
use super::modals::{
    AutoTypeState, KdbxImportState, Modal, QuickOpenState, ReauthAction, ReauthState, RestoreState,
};
use super::{unlock, welcome, Screen, VaultRustApp};
use crate::crypto::KdfParams;
use crate::import_export::import_csv;
use crate::model::{Entry, EntryKind, Field, FieldKind};
use crate::os_protect::ForeignWindow;
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
    let mut tagged = Entry::new(EntryKind::Login);
    tagged.title = "Tagged with OTP".into();
    tagged.add_tag("Work");
    tagged.favorite = true;
    tagged.fields.push(Field::with_value(
        "2FA",
        FieldKind::Totp,
        "JBSWY3DPEHPK3PXP",
    ));
    items.push(tagged);
    for e in items {
        v.data_mut().upsert(e);
    }
    // Give one item a password history and put one in the trash.
    let mut changed = v.data().entries[0].clone();
    changed.fields[3].value = "a newer password".into();
    v.data_mut().upsert(changed);
    let gone = v.data().entries[1].id;
    v.data_mut().trash_entry(gone);
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
        Page::Trash,
        Page::Tag("Work".into()),
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
    // An item with tags and a one-time code.
    let otp = main_state(&mut h)
        .vault
        .data()
        .entries
        .iter()
        .find(|e| e.totp_secret().is_some())
        .unwrap()
        .id;
    main_state(&mut h).open_entry(otp);
    h.step();

    for kind in EntryKind::ALL {
        main_state(&mut h).items.new_entry(kind);
        h.step();
    }
    main_state(&mut h).items.editor = None;

    let csv = import_csv(b"name,url,username,password\nA,https://a.example,u,p\n").unwrap();
    let trashed = main_state(&mut h).vault.data().trash[0].entry.id;
    let modals = vec![
        Modal::PurgeEntry(trashed),
        Modal::EmptyTrash,
        Modal::QuickOpen(QuickOpenState::new(false)),
        Modal::AutoType(AutoTypeState::new(ForeignWindow::for_tests("Some window"))),
        Modal::Reauth(Box::new(ReauthState::new(ReauthAction::Export))),
        Modal::KdbxImport(Box::new(KdbxImportState::new(
            PathBuf::from("db.kdbx"),
            zeroize::Zeroizing::new(vec![1, 2, 3]),
        ))),
        Modal::ExportWarning {
            understood: false,
            typed: String::new(),
        },
        Modal::Restore(Box::new(RestoreState::new(path.clone()))),
        Modal::ConfirmBackupOverwrite(PathBuf::from("backup.vault")),
        Modal::ImportPreview {
            source: PathBuf::from("export.csv"),
            result: csv,
            update_changed: true,
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

const GH_URI: &str = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

fn with_toasts<R>(
    h: &mut Harness<'_, VaultRustApp>,
    f: impl FnOnce(&mut MainState, &mut super::Services) -> R,
) -> R {
    let mut clipboard = crate::clipboard::ClipboardGuard::new();
    let mut toasts = super::toast::Toasts::default();
    let mut recent = RecentVaults::in_memory();
    let mut prefs = crate::prefs::AppPrefs::in_memory();
    let mut svc = super::Services {
        clipboard: &mut clipboard,
        toasts: &mut toasts,
        recent: &mut recent,
        prefs: &mut prefs,
        hotkeys: Default::default(),
        tray: false,
        updates: &mut Default::default(),
    };
    f(main_state(h), &mut svc)
}

#[test]
fn scanned_code_goes_to_the_matching_login() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    let mut gh = Entry::new(EntryKind::Login);
    gh.title = "GitHub (work)".into();
    gh.fields[0].value = "https://github.com/login".into();
    gh.fields[1].value = "octocat".into();
    gh.fields[3].value = "pw".into();
    let id = gh.id;
    main_state(&mut h).vault.data_mut().upsert(gh);
    with_toasts(&mut h, |ms, svc| ms.use_otpauth(GH_URI, svc));
    h.step();
    let ms = main_state(&mut h);
    let ed = ms.items.editor.as_ref().expect("editor opened");
    assert_eq!(ed.entry.id, id, "the existing login, not a new one");
    assert_eq!(ed.entry.totp_secret(), Some(GH_URI));
    assert!(ed.is_dirty() && !ed.is_new);
    // Nothing is saved until Save.
    assert!(ms.vault.data().entry(id).unwrap().totp_secret().is_none());
}

#[test]
fn scanned_code_without_a_match_starts_a_named_login() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    with_toasts(&mut h, |ms, svc| ms.use_otpauth(GH_URI, svc));
    h.step();
    h.get_by_label("Save").click();
    h.step();
    h.step();
    let ms = main_state(&mut h);
    let e = ms
        .vault
        .data()
        .entries
        .iter()
        .find(|e| e.totp_secret() == Some(GH_URI))
        .expect("saved");
    assert_eq!(e.title, "GitHub");
    assert_eq!(e.first_of(FieldKind::Username), Some("octocat"));
}

#[test]
fn scanned_code_fills_the_open_editor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    main_state(&mut h).items.new_entry(EntryKind::Login);
    main_state(&mut h).page = Page::Items(Category::Logins);
    h.step();
    with_toasts(&mut h, |ms, svc| ms.use_otpauth(GH_URI, svc));
    let ed = main_state(&mut h).items.editor.as_ref().unwrap();
    assert_eq!(ed.entry.totp_secret(), Some(GH_URI));
    assert_eq!(ed.entry.title, "GitHub");
}

#[test]
fn untitled_login_is_named_after_its_website() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    main_state(&mut h).items.new_entry(EntryKind::Login);
    main_state(&mut h).page = Page::Items(Category::Logins);
    main_state(&mut h)
        .items
        .editor
        .as_mut()
        .unwrap()
        .entry
        .fields[0]
        .value = "https://accounts.google.com/signin".into();
    h.step();
    h.get_by_label("Save").click();
    h.step();
    h.step();
    let ms = main_state(&mut h);
    assert!(ms.items.editor.is_none(), "saved without typing a title");
    assert!(ms.vault.data().entries.iter().any(|e| e.title == "Google"));
}

#[test]
fn username_suggestions_fill_empty_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    main_state(&mut h).items.new_entry(EntryKind::Login);
    main_state(&mut h).page = Page::Items(Category::Logins);
    h.step();
    h.get_by_label("Username value").click();
    h.step();
    let ed = main_state(&mut h).items.editor.as_ref().unwrap();
    assert_eq!(
        ed.entry.first_of(FieldKind::Username),
        Some("Username value")
    );
}

#[test]
fn undo_in_the_toast_restores_a_deleted_item() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    h.step();
    let id = main_state(&mut h).vault.data().entries[0].id;
    main_state(&mut h).open_entry(id);
    h.step();
    h.get_by_label(super::icons::TRASH).click();
    h.step();
    h.step();
    assert!(main_state(&mut h).vault.data().entry(id).is_none());
    h.get_by_label("Undo").click();
    h.step();
    h.step();
    let ms = main_state(&mut h);
    assert!(ms.vault.data().entry(id).is_some(), "restored by Undo");
    assert!(ms.vault.data().trash.iter().all(|t| t.entry.id != id));
}

#[test]
fn ctrl_z_restores_a_deleted_item() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    h.step();
    let id = main_state(&mut h).vault.data().entries[0].id;
    main_state(&mut h).open_entry(id);
    h.step();
    h.get_by_label(super::icons::TRASH).click();
    h.step();
    h.step();
    h.key_press_modifiers(eframe::egui::Modifiers::COMMAND, eframe::egui::Key::Z);
    h.step();
    h.step();
    assert!(main_state(&mut h).vault.data().entry(id).is_some());
}

#[test]
fn attachments_are_listed_and_saved_with_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    let mut e = Entry::new(EntryKind::SecureNote);
    e.title = "Recovery".into();
    e.attachments.push(crate::model::Attachment {
        name: "codes.txt".into(),
        data: b"1111 2222".to_vec(),
        added: 1,
    });
    let id = e.id;
    main_state(&mut h).vault.data_mut().upsert(e);
    assert!(main_state(&mut h).commit(&mut super::toast::Toasts::default()));
    main_state(&mut h).open_entry(id);
    h.step();
    h.get_by_label("codes.txt");
    h.get_by_label("9 bytes");
    // Editing keeps the attachment, and removing it is a change to save.
    h.get_by_label(super::icons::PENCIL_SIMPLE).click();
    h.step();
    {
        let ed = main_state(&mut h)
            .items
            .editor
            .as_mut()
            .expect("editor open");
        assert_eq!(ed.entry.attachments.len(), 1);
        ed.entry.attachments.clear();
    }
    h.step();
    h.get_by_label("Save").click();
    h.step();
    h.step();
    assert!(main_state(&mut h)
        .vault
        .data()
        .entry(id)
        .unwrap()
        .attachments
        .is_empty());

    let reopened = UnlockedVault::open(&path, &SecretString::from(PW)).unwrap();
    assert!(reopened.data().entry(id).unwrap().attachments.is_empty());
}

#[test]
fn deleting_moves_to_trash_and_restore_brings_it_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    h.step();
    main_state(&mut h).vault.data_mut().empty_trash();
    let id = main_state(&mut h).vault.data().entries[0].id;
    let title = main_state(&mut h).vault.data().entries[0].title.clone();
    main_state(&mut h).open_entry(id);
    h.step();
    h.get_by_label(super::icons::TRASH).click();
    h.step();
    h.step();
    {
        let ms = main_state(&mut h);
        assert!(ms.vault.data().entry(id).is_none());
        assert!(ms.vault.data().trash.iter().any(|t| t.entry.id == id));
    }
    // Persisted: the trashed item is still in the file, just not live.
    let reopened = UnlockedVault::open(&path, &SecretString::from(PW)).unwrap();
    assert!(reopened.data().trash.iter().any(|t| t.entry.title == title));

    main_state(&mut h).page = Page::Trash;
    h.step();
    h.get_by_label_contains("Restore").click();
    h.step();
    h.step();
    let ms = main_state(&mut h);
    assert!(ms.vault.data().entry(id).is_some(), "restored");
}

#[test]
fn ctrl_k_opens_quick_open_and_escape_closes_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = harness(unlocked_app(&dir.path().join("ui.vault")));
    h.step();
    h.key_press_modifiers(eframe::egui::Modifiers::COMMAND, eframe::egui::Key::K);
    h.step();
    h.step();
    assert!(matches!(
        main_state(&mut h).modal,
        Some(Modal::QuickOpen(_))
    ));
    h.key_press(eframe::egui::Key::Escape);
    h.step();
    h.step();
    assert!(main_state(&mut h).modal.is_none());
}

#[test]
fn export_requires_the_master_password() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = harness(unlocked_app(&dir.path().join("ui.vault")));
    h.step();
    main_state(&mut h).modal = Some(Modal::Reauth(Box::new(ReauthState::new(
        ReauthAction::Export,
    ))));
    h.step();

    let attempt = |h: &mut Harness<'_, VaultRustApp>, pw: &str| {
        h.get_by_role(eframe::egui::accesskit::Role::PasswordInput)
            .type_text(pw);
        h.step();
        h.get_by_label("Continue").click();
        for _ in 0..200 {
            h.step();
            std::thread::sleep(Duration::from_millis(10));
            let busy = main_state(h).modal.as_ref().is_some_and(Modal::is_busy);
            if !busy {
                break;
            }
        }
    };
    attempt(&mut h, "not the master password");
    assert!(matches!(main_state(&mut h).modal, Some(Modal::Reauth(_))));
    attempt(&mut h, PW);
    assert!(matches!(
        main_state(&mut h).modal,
        Some(Modal::ExportWarning { .. })
    ));
}

#[test]
fn auto_type_picks_the_matching_item_and_types_the_right_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = harness(unlocked_app(&dir.path().join("ui.vault")));
    let mut gh = Entry::new(EntryKind::Login);
    gh.title = "GitHub".into();
    gh.fields[0].value = "https://github.com/login".into();
    gh.fields[1].value = "octocat".into();
    gh.fields[3].value = "gh-pass-123".into();
    let gh_id = gh.id;
    main_state(&mut h).vault.data_mut().upsert(gh);
    h.step();

    let window = || ForeignWindow::for_tests("Sign in to GitHub · GitHub — Mozilla Firefox");
    main_state(&mut h).open_auto_type(window());
    h.step();
    h.step();
    h.key_press(eframe::egui::Key::Enter);
    h.step();
    h.step();
    {
        let ms = main_state(&mut h);
        assert!(ms.modal.is_none(), "picker closes after typing starts");
        assert_eq!(
            ms.auto_typed.as_deref(),
            Some(
                &[
                    "octocat".to_string(),
                    "{TAB}".into(),
                    "gh-pass-123".into(),
                    "{ENTER}".into()
                ][..]
            )
        );
        assert!(ms.vault.data().entry(gh_id).unwrap().last_used > 0);
    }

    // Shift+Enter types only the password.
    main_state(&mut h).open_auto_type(window());
    h.step();
    h.key_press_modifiers(eframe::egui::Modifiers::SHIFT, eframe::egui::Key::Enter);
    h.step();
    h.step();
    assert_eq!(
        main_state(&mut h).auto_typed.as_deref(),
        Some(&["gh-pass-123".to_string(), "{ENTER}".into()][..])
    );

    // Esc cancels without typing anything.
    main_state(&mut h).auto_typed = None;
    main_state(&mut h).open_auto_type(window());
    h.step();
    h.key_press(eframe::egui::Key::Escape);
    h.step();
    h.step();
    assert!(main_state(&mut h).modal.is_none());
    assert!(main_state(&mut h).auto_typed.is_none());
}

#[test]
fn import_skips_identical_items_and_updates_changed_passwords() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.vault");
    let mut h = harness(unlocked_app(&path));
    let mut gh = Entry::new(EntryKind::Login);
    gh.title = "GitHub".into();
    gh.fields[0].value = "https://github.com".into();
    gh.fields[1].value = "octocat".into();
    gh.fields[3].value = "old-pass".into();
    let gh_id = gh.id;
    let mut mail = Entry::new(EntryKind::Login);
    mail.title = "Mail".into();
    mail.fields[0].value = "https://mail.example".into();
    mail.fields[1].value = "me".into();
    mail.fields[3].value = "same-pass".into();
    main_state(&mut h).vault.data_mut().upsert(gh);
    main_state(&mut h).vault.data_mut().upsert(mail);
    let before = main_state(&mut h).vault.data().entries.len();
    h.step();

    let csv = import_csv(
        b"name,url,username,password\n\
          GitHub,https://www.github.com/,octocat,new-pass\n\
          Mail,https://mail.example,me,same-pass\n\
          Brand new,https://new.example,x,y\n",
    )
    .unwrap();
    main_state(&mut h).modal = Some(Modal::ImportPreview {
        source: PathBuf::from("export.csv"),
        result: csv,
        update_changed: true,
    });
    h.step();
    h.step();
    h.get_by_label("Import").click();
    h.step();
    h.step();

    let ms = main_state(&mut h);
    assert!(ms.modal.is_none());
    let data = ms.vault.data();
    assert_eq!(data.entries.len(), before + 1, "only the new item is added");
    let gh = data.entry(gh_id).unwrap();
    assert_eq!(gh.primary_password(), Some("new-pass"));
    assert!(gh.history.iter().any(|h| h.value == "old-pass"));
    assert_eq!(data.entries.iter().filter(|e| e.title == "Mail").count(), 1);
    assert!(data
        .audit
        .iter()
        .any(|a| a.kind == crate::model::AuditKind::Imported
            && a.detail.starts_with("1 added, 1 updated")));
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
    // A few realistic items so the home page shows varied tiles.
    let now = crate::timeutil::now_unix();
    for (n, (title, url, user, pass)) in [
        (
            "GitHub",
            "https://github.com",
            "octocat",
            "c8!Rq2#vLp9@Zm4w",
        ),
        (
            "Google",
            "https://accounts.google.com",
            "me@gmail.com",
            "Tr0ub4dor&3",
        ),
        (
            "Netflix",
            "https://netflix.com",
            "me@gmail.com",
            "x7$Kq!9pLm2#Wz8r",
        ),
        (
            "AWS console",
            "https://aws.amazon.com",
            "admin",
            "g3@Hn8!Qw5^Rt1zP",
        ),
        (
            "Bank",
            "https://bank.example",
            "4410221",
            "h2#Vb9!Lr6$Kx4mT",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut e = Entry::new(EntryKind::Login);
        e.title = title.into();
        e.fields[0].value = url.into();
        e.fields[1].value = user.into();
        e.fields[3].value = pass.into();
        e.favorite = n < 4;
        e.last_used = now - (n as i64 + 1) * 5_400;
        v.data_mut().upsert(e);
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
        ("14-trash", Page::Trash),
        ("15-tag", Page::Tag("Work".into())),
    ];
    for (name, page) in pages {
        let ms = main_state(&mut h);
        ms.page = page.clone();
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
    // A maximised full-HD window.
    main_state(&mut h).page = Page::Dashboard;
    h.set_size(eframe::egui::vec2(1920.0, 1040.0));
    shoot(&mut h, "04c-dashboard-maximised");
    h.set_size(eframe::egui::vec2(1200.0, 780.0));
    main_state(&mut h).items.new_entry(EntryKind::Login);
    main_state(&mut h).page = Page::Items(Category::Logins);
    shoot(&mut h, "12-editor");
    main_state(&mut h).modal = Some(Modal::ExportWarning {
        understood: false,
        typed: String::new(),
    });
    shoot(&mut h, "13-export-warning");
    main_state(&mut h).items.editor = None;
    let otp = main_state(&mut h)
        .vault
        .data()
        .entries
        .iter()
        .find(|e| e.totp_secret().is_some())
        .unwrap()
        .id;
    main_state(&mut h).open_entry(otp);
    main_state(&mut h).modal = None;
    shoot(&mut h, "16-item-with-otp");

    // Attachments, then the Undo toast after deleting.
    let mut note = Entry::new(EntryKind::SecureNote);
    note.title = "Recovery codes".into();
    note.notes = "GitHub and Google backup codes are attached.".into();
    for (name, len) in [
        ("github-recovery-codes.txt", 412),
        ("passport-scan.pdf", 1_830_000),
    ] {
        note.attachments.push(crate::model::Attachment {
            name: name.into(),
            data: vec![0; len],
            added: 1,
        });
    }
    let note_id = note.id;
    main_state(&mut h).vault.data_mut().upsert(note);
    main_state(&mut h).open_entry(note_id);
    shoot(&mut h, "25-attachments");
    h.get_by_label(super::icons::TRASH).click();
    shoot(&mut h, "26-undo-toast");
    main_state(&mut h).items.new_entry(EntryKind::Login);
    main_state(&mut h).page = Page::Items(Category::Logins);
    shoot(&mut h, "27-new-login");
    main_state(&mut h).items.editor = None;
    main_state(&mut h).page = Page::Dashboard;
    let json = br#"{"tag_name":"v0.2.0","body":"- Scan 2FA QR codes","assets":[
        {"name":"VaultRust.exe","browser_download_url":"https://github.com/x/VaultRust.exe"},
        {"name":"VaultRust.exe.sig","browser_download_url":"https://github.com/x/VaultRust.exe.sig"}]}"#;
    h.state_mut().updates.available =
        crate::update::parse_latest(json, crate::update::Version(0, 1, 0)).unwrap();
    shoot(&mut h, "28-update-banner");
    h.get_by_label("Update and restart");
    h.state_mut().updates.available = None;
    main_state(&mut h).page = Page::Dashboard;
    main_state(&mut h).modal = Some(Modal::QuickOpen(QuickOpenState::new(false)));
    shoot(&mut h, "17-quick-open");
    main_state(&mut h).open_auto_type(ForeignWindow::for_tests(
        "Tagged with OTP - Sign in - Google Chrome",
    ));
    shoot(&mut h, "18-auto-type");

    // The same screens in the light theme.
    h.state_mut().prefs.theme = crate::prefs::ThemePref::Light;
    main_state(&mut h).modal = None;
    for (name, page) in [
        ("20-light-dashboard", Page::Dashboard),
        ("21-light-logins", Page::Items(Category::Logins)),
        ("22-light-security", Page::Security),
        ("23-light-settings", Page::Settings),
    ] {
        main_state(&mut h).page = page;
        shoot(&mut h, name);
    }
    h.state_mut().screen = Screen::Unlock(Box::new(unlock::UnlockState::new(path.clone())));
    shoot(&mut h, "24-light-unlock");
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
