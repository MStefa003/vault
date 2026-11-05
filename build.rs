//! Embeds the icon and version information in the Windows program, so
//! Explorer, the taskbar and Settings → Apps show VaultRust's padlock.

fn main() {
    println!("cargo:rerun-if-changed=assets/vaultrust.ico");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    if !windows || std::env::var_os("CARGO_FEATURE_GUI").is_none() {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/vaultrust.ico")
        .set("ProductName", "VaultRust")
        .set("FileDescription", "VaultRust password manager")
        .set("CompanyName", "Marios Stefanidis")
        .set("LegalCopyright", "MIT licence");
    if let Err(e) = res.compile() {
        // A missing resource compiler only costs the icon, not the build.
        println!("cargo:warning=couldn't embed the program icon: {e}");
    }
}
