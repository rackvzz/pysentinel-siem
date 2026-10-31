pysentinel-siem — Quick Start
==============================

WHAT THIS IS
A lightweight security monitor for this Windows PC. It watches your
Windows security logs in the background, flags suspicious activity
(failed logins, privilege escalation, malicious PowerShell, etc.), and
shows everything in one dashboard window.

HOW TO RUN IT
If you used the installer, open the Start Menu and type "pysentinel".
If you downloaded the portable zip:
1. Double-click "pysentinel-siem.exe".
2. Windows will ask "Do you want to allow this app to make changes to
   your device?" — click YES. This is required to read the Security
   log (Windows only allows administrators to read it).
3. A window opens with four tabs: Dashboard, Alerts, Posture, Settings.
   That's it — it's already watching and detecting in the background.

WHERE YOUR DATA GOES
Everything stays on this machine, next to the .exe (installer default:
%LOCALAPPDATA%\Programs\pysentinel-siem):
  - config.yaml   settings (safe to open in Notepad, all defaults work)
  - siem.db       the local database of collected events/alerts
Nothing is sent anywhere over the network except an optional, opt-in
threat-intel feed download you can turn on in Settings (off by default).
Your own events are never uploaded. Details: PRIVACY.md in this zip.

Only run this on computers you own or are allowed to administer.

OPTIONAL: FULLER DETECTION COVERAGE WITH SYSMON
A few detection rules (encoded/malicious PowerShell, credential theft
attempts) need Microsoft's free "Sysmon" tool installed. This is
optional — the app works without it, just with fewer detections.
  1. Download Sysmon from Microsoft's official Sysinternals site:
     https://learn.microsoft.com/sysinternals/downloads/sysmon
  2. Extract it, open an Administrator PowerShell/Command Prompt in
     that folder, and run:
       Sysmon64.exe -accepteula -i sysmonconfig-export.xml
     (the sysmonconfig-export.xml included in this zip is a
     ready-to-use, sensible configuration — no editing needed)

UNINSTALLING
Installer: Settings > Apps > Installed apps > pysentinel-siem > Uninstall.
This also deletes the local database, logs, and settings it created.
Portable zip: close the app and delete this folder. Nothing is installed elsewhere
on the system (no registry entries, no services) unless you separately
ran the optional "auto-start at logon" script from the full source
repo.

VERIFYING THE DOWNLOAD
The release page lists a SHA256 checksum for this zip. In PowerShell:
  Get-FileHash .\pysentinel-siem-*-windows.zip -Algorithm SHA256
The hash should match the one in SHA256SUMS.txt on the release page.
Windows SmartScreen may warn on first launch because the .exe isn't
code-signed yet. Click "More info" -> "Run anyway" if the hash matches.

FULL DOCS / SOURCE CODE
https://github.com/rackvzz/pysentinel-siem
Licenses for bundled components: THIRD_PARTY_NOTICES.md in this zip.

Copyright (c) 2026 Abhi Katragadda. MIT License (see LICENSE).
Provided as-is, without warranty. "pysentinel-siem" and its logo are
not licensed under MIT; see TRADEMARKS.md on GitHub.
