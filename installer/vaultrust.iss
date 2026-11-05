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
; Close a running VaultRust (it locks and saves first) when upgrading.
CloseApplications=yes
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

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  // "Start with Windows" (set from VaultRust's settings) would otherwise
  // point at a deleted program.
  if CurUninstallStep = usPostUninstall then
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 'VaultRust');
end;
