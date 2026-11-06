// Release builds are GUI-only (no console window).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() {
    // Never print panic payloads: they could contain fragments of user data.
    // Only the source location is reported, and nothing is written to disk.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".into());
        eprintln!("VaultRust stopped because of an internal error at {location}.");
    }));

    // Started by a browser for the VaultRust extension: relay its messages
    // to the running app, no window.
    let args: Vec<String> = std::env::args().collect();
    if vaultrust::browser::is_host_invocation(&args) {
        vaultrust::os_protect::harden_process();
        vaultrust::browser::run_host();
        return;
    }

    if let Err(e) = vaultrust::ui::run() {
        eprintln!("VaultRust could not start: {e}");
        std::process::exit(1);
    }
}
