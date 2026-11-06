; VaultRust installer (Inno Setup 6).
;   iscc /DAppVersion=1.2.3 installer\vaultrust.iss
; expects release\VaultRust.exe and writes release\VaultRust-Setup-1.2.3.exe.
;
; Installs for the current user only (no administrator prompt) into
; %LOCALAPPDATA%\Programs\VaultRust, which also lets VaultRust's built-in
; updater replace its own program file. Vault files are never touched.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
; Never change AppId: it identifies the installation for upgrades and the
; updater (src/os_protect.rs, INSTALL_KEY).
AppId={{8F3C2A51-6D2B-4E7A-9C1E-5B0D7A4F2E10}
AppName=VaultRust
AppVersion={#AppVersion}
AppVerName=VaultRust {#AppVersion}
AppPublisher=Marios Stefanidis
AppPublisherURL=https://github.com/MStefa003/vault
AppSupportURL=https://github.com/MStefa003/vault/issues
AppUpdatesURL=https://github.com/MStefa003/vault/releases
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\VaultRust
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
OutputDir=..\release
OutputBaseFilename=VaultRust-Setup-{#AppVersion}
SetupIconFile=..\assets\vaultrust.ico
UninstallDisplayIcon={app}\VaultRust.exe
UninstallDisplayName=VaultRust
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
; Close a running VaultRust when upgrading. "force" because a copy hidden in
; the notification area treats a close request as "hide"; the vault is saved
; after every change, so ending it loses nothing.
CloseApplications=force
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\release\VaultRust.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\VaultRust"; Filename: "{app}\VaultRust.exe"
Name: "{autodesktop}\VaultRust"; Filename: "{app}\VaultRust.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\VaultRust.exe"; Description: "{cm:LaunchProgram,VaultRust}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Left behind by an interrupted self-update.
Type: files; Name: "{app}\VaultRust.old.exe"
Type: files; Name: "{app}\VaultRust.new.exe"
; The browser extension's files and helper registration (Settings → Browser
; extension); the browsers' own copies are removed in the browsers.
Type: filesandordirs; Name: "{localappdata}\VaultRust\Browser extension"
Type: files; Name: "{localappdata}\VaultRust\com.vaultrust.browser.json"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  // "Start with Windows" and the browser extension's helper (both set from
  // VaultRust's settings) would otherwise point at a deleted program.
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 'VaultRust');
    // The browser extension's helper registration (src/browser.rs,
    // BROWSER_KEYS).
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'Software\Google\Chrome\NativeMessagingHosts\com.vaultrust.browser');
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'Software\Microsoft\Edge\NativeMessagingHosts\com.vaultrust.browser');
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.vaultrust.browser');
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'Software\Chromium\NativeMessagingHosts\com.vaultrust.browser');
  end;
end;
