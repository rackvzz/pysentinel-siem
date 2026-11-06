; Inno Setup script for the pysentinel-siem Windows installer.
; Built by .github/workflows/release.yml:
;   iscc /DAppVersion=1.2.0 /DSourceDir=<docs folder> /DOnedirDir=<pyinstaller onedir> packaging\installer.iss
;
; Machine-wide install into Program Files. The app always runs as admin, so
; its files must sit somewhere normal programs can't modify -- a per-user
; folder would let non-admin malware swap the exe and get admin the next
; time it's launched. Data (config, database, logs) lives separately in
; %ProgramData%\pysentinel-siem, locked to Administrators by the app itself
; (siem/paths.py).

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist"
#endif
#ifndef OnedirDir
  #define OnedirDir "..\dist\pysentinel-siem"
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
AppCopyright=Copyright (c) 2026 Abhi Katragadda
AppPublisherURL=https://github.com/rackvzz/pysentinel-siem
AppSupportURL=https://github.com/rackvzz/pysentinel-siem/issues
AppUpdatesURL=https://github.com/rackvzz/pysentinel-siem/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
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
; onedir build: the exe plus its _internal folder, so nothing gets unpacked
; into the user's Temp folder at launch
Source: "{#OnedirDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
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

[UninstallRun]
; firewall blocks the app added stay in Windows until removed -- clean them up
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; \
  Parameters: "-NoProfile -NonInteractive -Command ""Get-NetFirewallRule -DisplayName 'pysentinel-siem-block-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"""; \
  Flags: runhidden; RunOnceId: "RemoveFirewallBlocks"

[UninstallDelete]
; collected data (usernames, IPs, command lines), settings, API key, logs
Type: filesandordirs; Name: "{commonappdata}\{#AppName}"
Type: dirifempty; Name: "{app}"

[Code]
const
  OldPerUserKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{79F4D6C1-89CF-4ABA-9A8F-CA41BF61D90D}_is1';

// v1.1.0 installed per-user into %LOCALAPPDATA%. Remove that copy so there
// aren't two Start Menu entries and no admin-run exe is left in a folder
// normal programs can write to.
procedure RemoveOldPerUserInstall();
var
  Uninstaller: String;
  ResultCode: Integer;
begin
  if RegQueryStringValue(HKCU, OldPerUserKey, 'UninstallString', Uninstaller) then
  begin
    Exec(RemoveQuotes(Uninstaller), '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '',
         SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    RemoveOldPerUserInstall();
end;
