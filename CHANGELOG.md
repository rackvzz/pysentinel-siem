# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-11-06

This release fixes security issues found in a full audit of the app. **Everyone on 1.1.0 or earlier should upgrade.**

### Security
- **High: any website could read the dashboard and unblock IPs (DNS rebinding).**
  - The attack: a malicious page points its own domain at `127.0.0.1`, so the browser treats the dashboard as part of that site. The page could then read collected events, including command lines, and call Block/Unblock, and the Origin-based CSRF check didn't stop it.
  - The fix: the dashboard now rejects non-loopback `Host` headers and requires a random per-launch token, held in an `HttpOnly`, `SameSite=Strict` cookie. That also keeps other Windows users on the machine out.
- **High: non-admin programs could get admin rights through the app (local privilege escalation).**
  - The cause: the packaged app always runs as admin, but it read its config and wrote its database, logs, settings, and API key in a folder normal users can write to (next to the exe; the 1.1.0 installer used `%LOCALAPPDATA%`). A non-admin program could plant a config the elevated app acted on. For example, `db_path` pointing into `System32` made the app create that file and run `icacls` to hand it to the user. It could also swap the exe itself.
  - The fix: data now lives in an Administrators-owned, admin-only `%ProgramData%\pysentinel-siem`. Pre-existing untrusted folders are moved aside, symlinks and junctions are refused, and `db_path` is limited to a plain file name in that folder. The installer now puts the app in Program Files as a onedir build, so nothing is unpacked into the user's Temp folder.
- **High: the autostart task was a silent path to admin.**
  - The cause: `register_autostart.ps1` registered an elevated, no-prompt logon task that ran `desktop_app.py` from the source folder, which a non-admin program can edit.
  - The fix: it now only accepts the installed copy in Program Files and refuses any path a non-admin account can modify. A Windows CI job tests both cases.
- **Medium: `icacls` followed links.** Restricting `siem.db`/`secrets.yaml` (when running from source) now refuses symlinks and hard links, so it can't be steered onto another file.
- **Low: unbounded memory growth.** The brute-force and port-scan rules kept state for every source IP they ever saw. Idle sources are now forgotten.

### Changed
- **Installer:**
  - installs machine-wide into Program Files (one admin prompt to install)
  - removes a 1.1.0 per-user install automatically. History collected by the 1.1.0 installer isn't carried over, because it lived in the unsafe location.
  - uninstall also removes firewall blocks the app added
- **Data location:** existing data next to a portable exe is copied into the new folder on first launch.
- **Release pipeline:**
  - actions are pinned to commit SHAs
  - dependencies come from a hash-locked file (`packaging/requirements-release.txt`), which CI also audits
  - building and publishing are separate jobs, so the build (which runs third-party code) has read-only access
  - each release file gets a signed build-provenance attestation (`gh attestation verify`)
- The desktop app's Alerts tab now filters by severity before applying its 200-row limit, matching the dashboard fix from 1.1.0.

## [1.1.0] - 2026-10-31

### Added
- GitHub Actions CI: tests on Windows and Ubuntu (Python 3.10 and 3.12), plus Ruff lint, Bandit, and pip-audit on every push and pull request.
- Dependabot for Python dependencies and GitHub Actions.
- **Windows installer** (`pysentinel-siem-vX.Y.Z-setup.exe`, Inno Setup):
  - per-user install with no admin prompt to install
  - Start Menu entry, so the app is findable in Windows search
  - optional desktop shortcut
  - uninstaller in Settings → Apps that also removes the local database and logs
  - the portable zip is still published alongside it
- App icon for the `.exe`, installer, and Start Menu entry.
- `TRADEMARKS.md`: the MIT License covers the code, not the pysentinel-siem name or logo. Forks that redistribute must rename. Copyright holder in LICENSE set to the author's legal name. Added a contribution licensing note to CONTRIBUTING.md and a no-warranty disclaimer to the README.
- Release workflow: pushing a `v*` tag builds the `.exe` on a clean GitHub Windows runner (after the tests pass), zips it with the docs, and publishes the release with a SHA256 checksum.
- `pyproject.toml` with project metadata, a single version source (`siem.__version__`), and tool configuration.
- `SECURITY.md` (private vulnerability reporting), `PRIVACY.md` (what's collected and where it goes), `THIRD_PARTY_NOTICES.md`, `CONTRIBUTING.md`, issue and PR templates.
- Dashboard: strict `Content-Security-Policy` header.
- Dashboard: JSON error responses for `/api/*` routes.
- Dashboard: an "Offline" indicator when the server stops responding.
- Dashboard: version number in the page footer.
- Desktop app: Ctrl+Tab / Ctrl+Shift+Tab switches between tabs.

### Changed
- **Accessibility (WCAG 2.2 AA):**
  - All text now meets the 4.5:1 contrast minimum. Severity badges, muted text, and danger buttons previously failed (as low as 1.6:1). axe-core reports 0 violations, down from 64.
  - Added a skip link, labelled navigation with `aria-current`, and table headers with `scope`.
  - Scrollable tables can be focused and scrolled with the keyboard.
  - Every element has a visible focus ring.
  - Charts have text alternatives that describe their data.
  - "Block IP" and "Unblock" buttons have descriptive accessible names.
  - Toasts have a close button and pause while hovered or focused.
  - Keyboard focus is kept on the same button across the 5-second auto-refresh.
  - New high-severity alerts are announced even with reduced motion turned on. Previously they were silently skipped.
- Desktop app: severity text and muted text colors darkened to meet 4.5:1. Fill colors are unchanged.
- Dashboard polling pauses while the browser tab is hidden and never overlaps requests.
- `/api/alerts?severity=` now filters in SQL before applying the limit, so `limit=200&severity=high` returns up to 200 high alerts.
- API `limit`/`hours` parameters are clamped to sane ranges, and unknown severities return 400.
- `pytest` moved from runtime to dev requirements. Runtime requirements now have upper bounds on major versions.
- Sysmon config header now records this project's modification, as CC BY 4.0 requires.

### Fixed
- The packaged `.exe` now actually requests admin rights through its Windows manifest (`--uac-admin`). PyInstaller had been replacing `requireAdministrator` with `asInvoker`, so v1.0.0 relied on the app re-launching itself elevated.
- The test suite now runs on non-Windows machines, as the README always claimed. pywin32 is stubbed in `tests/conftest.py`. Tests that call real Windows tools skip where those tools can't behave as the test expects.

## [1.0.0] - 2026-08-11

### Added
- Windows Event Log + Sysmon collector with per-channel watermarks and SQLite storage.
- Ten MITRE ATT&CK-mapped detection rules, alert correlation, and threat intel matching (abuse.ch ThreatFox).
- Flask browser dashboard and Tkinter desktop app.
- Human-confirmed Windows Firewall IP blocking.
- Attack-surface (listening port) scanning, log retention, native notifications, and auto-start at logon.
- Standalone Windows `.exe` built with PyInstaller.

[1.2.0]: https://github.com/rackvzz/pysentinel-siem/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/rackvzz/pysentinel-siem/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rackvzz/pysentinel-siem/releases/tag/v1.0.0
