; Inno Setup script for the pysentinel-siem Windows installer.
; Built by .github/workflows/release.yml:
;   iscc /DAppVersion=1.1.0 /DSourceDir=release_dist\<zip folder> packaging\installer.iss
;
; Per-user install into %LOCALAPPDATA%\Programs (same idea as VS Code's user
; installer): no admin prompt to install, and the app can keep writing
; config.yaml / siem.db next to the exe like the portable zip does. The app
; itself still asks for admin when it starts, because reading the Security
; log needs it.

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist"
#endif

#define AppName "pysentinel-siem"
#define AppExe "pysentinel-siem.exe"

[Setup]
; never change AppId -- Windows uses it to match upgrades and the uninstaller
AppId={{79F4D6C1-89CF-4ABA-9A8F-CA41BF61D90D}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Abhi Katragadda
AppPublisherURL=https://github.com/rackvzz/pysentinel-siem
AppSupportURL=https://github.com/rackvzz/pysentinel-siem/issues
AppUpdatesURL=https://github.com/rackvzz/pysentinel-siem/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile={#SourceDir}\LICENSE
SetupIconFile=pysentinel-siem.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
OutputDir=..\release_dist
OutputBaseFilename={#AppName}-v{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README-FIRST.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "{#SourceDir}\PRIVACY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\sysmonconfig-export.xml"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; the Start Menu shortcut is what makes it show up in Windows search
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Comment: "Lightweight SIEM for this PC"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; shellexec so Windows can show the UAC prompt the exe's manifest asks for
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallDelete]
; local data the app creates at runtime: settings, the event database, logs.
; Removed on uninstall so collected usernames/IPs/command lines don't linger.
Type: files; Name: "{app}\config.yaml"
Type: files; Name: "{app}\user_settings.yaml"
Type: files; Name: "{app}\secrets.yaml"
Type: files; Name: "{app}\siem.db"
Type: files; Name: "{app}\siem.db-wal"
Type: files; Name: "{app}\siem.db-shm"
Type: files; Name: "{app}\pysentinel-siem.log*"
Type: dirifempty; Name: "{app}"
