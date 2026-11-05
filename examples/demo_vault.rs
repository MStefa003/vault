//! Create a demo vault filled with fictional sample data, for trying out the UI.
//!
//! ```text
//! cargo run --example demo_vault -- <path.vault> <master password>
//! ```
//!
//! Refuses to overwrite an existing file.

use std::path::PathBuf;

use secrecy::SecretString;
use vaultrust::crypto::KdfParams;
use vaultrust::model::{Entry, EntryKind};
use vaultrust::timeutil::now_unix;
use vaultrust::UnlockedVault;

fn entry(kind: EntryKind, title: &str, values: &[&str], notes: &str) -> Entry {
    let mut e = Entry::new(kind);
    e.title = title.into();
    for (f, v) in e.fields.iter_mut().zip(values) {
        f.value = (*v).into();
    }
    e.notes = notes.into();
    e
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(password)) = (args.next(), args.next()) else {
        eprintln!("usage: demo_vault <path.vault> <master password>");
        std::process::exit(2);
    };
    let path = PathBuf::from(path);
    let password = SecretString::from(password);
    let mut v = UnlockedVault::create(&path, &password, KdfParams::STANDARD, "Demo Vault", false)
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });

    let old = now_unix() - 500 * 86_400;
    let mut items = vec![
        entry(
            EntryKind::Login,
            "GitHub",
            &[
                "https://github.com",
                "octo-demo",
                "demo@example.com",
                "q7#Vt9!pLm2$Xc4Rz8",
            ],
            "",
        ),
        entry(
            EntryKind::Login,
            "Example Bank",
            &["https://bank.example", "jdoe", "", "Summer2024!"],
            "Security questions in the note below.",
        ),
        entry(
            EntryKind::Login,
            "Forum",
            &["https://forum.example", "jdoe", "", "Summer2024!"],
            "",
        ),
        entry(
            EntryKind::Email,
            "Personal mail",
            &[
                "jane.doe@example.com",
                "Correct-Horse-Battery-Staple-7",
                "imap.example.com",
                "",
            ],
            "",
        ),
        entry(
            EntryKind::SecureNote,
            "Recovery codes",
            &[],
            "GitHub recovery codes\n1a2b-3c4d\n5e6f-7a8b\n9c0d-1e2f",
        ),
        entry(
            EntryKind::CreditCard,
            "Everyday Visa",
            &[
                "Jane Doe",
                "4111 1111 1111 1111",
                "08/29",
                "123",
                "4321",
                "Example Bank",
            ],
            "",
        ),
        entry(
            EntryKind::Identity,
            "Jane Doe",
            &[
                "Jane Doe",
                "jane.doe@example.com",
                "+30 210 000 0000",
                "1 Example Street\nAthens",
                "1990-01-01",
                "AB1234567",
                "",
            ],
            "",
        ),
        entry(
            EntryKind::ApiKey,
            "Stripe (test)",
            &[
                "Stripe",
                "sk_test_51DemoKeyNotReal",
                "",
                "https://api.stripe.com",
                "2027-01-01",
            ],
            "",
        ),
        entry(
            EntryKind::Server,
            "Build server",
            &["10.0.0.12", "22", "deploy", "T4n!q9#wLr8@Vb2", ""],
            "",
        ),
        entry(
            EntryKind::Database,
            "Analytics DB",
            &[
                "PostgreSQL",
                "db.internal",
                "5432",
                "analytics",
                "reporter",
                "password123",
                "",
            ],
            "",
        ),
        entry(
            EntryKind::Wifi,
            "Home Wi-Fi",
            &["DemoNet-5G", "garden-lamp-river-91", "WPA3"],
            "",
        ),
    ];
    items[0].favorite = true;
    items[3].favorite = true;
    items[2].password_changed = old;
    for e in items {
        v.data_mut().upsert(e);
    }
    v.save().expect("save");
    println!("Created {}", path.display());
}
