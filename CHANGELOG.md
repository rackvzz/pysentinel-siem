# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-31

### Added
- GitHub Actions CI: tests on Windows and Ubuntu (Python 3.10 and 3.12), plus Ruff lint, Bandit, and pip-audit on every push and pull request.
- Dependabot for Python dependencies and GitHub Actions.
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

[1.1.0]: https://github.com/rackvzz/pysentinel-siem/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rackvzz/pysentinel-siem/releases/tag/v1.0.0
