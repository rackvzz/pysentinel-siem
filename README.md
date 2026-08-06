# pysentinel-siem

A lightweight SIEM (Security Information and Event Management) system, built from scratch in Python, that runs on a single Windows host. It collects Windows Event Log telemetry, normalizes and stores it, evaluates it against MITRE ATT&CK-mapped detection rules, correlates related alerts, and surfaces everything through a live dashboard — with native notifications and a human-confirmed action to block a malicious IP.

![Dashboard screenshot](docs/screenshots/dashboard.jpg)

## Why

Built as a hands-on companion to CompTIA Security+ study: rather than only reading about SIEM concepts (log normalization, correlation rules, detection engineering), this implements a minimal but real version of one, end to end, on my own machine.

## Features at a glance

| Feature | What it does |
|---|---|
| **[Collection](#architecture)** | Polls Windows Event Log + Sysmon via the native `win32evtlog` API (no third-party agent), normalizes every event into one schema, stores it in SQLite |
| **[Detection](#detections-mitre-attck-mapped)** | 10 MITRE ATT&CK-mapped rules: brute force, privilege escalation, encoded/obfuscated PowerShell, credential dumping, persistence, port scanning, threat-intel IOC matches |
| **[Alert correlation](#alert-correlation)** | Chains weak, independent alerts from the same user/IP into one higher-confidence alert |
| **[Response actions](#response-actions)** | Human-confirmed "Block Source IP" — adds/removes a Windows Firewall rule, with safety guards against self-lockout |
| **[Attack-surface scanning](#attack-surface-scanning-posture-tab)** | Point-in-time scan of this machine's own exposed/listening ports |
| **[Threat intelligence](#threat-intelligence-feed)** | Cross-references observed IPs against a live feed of known-malicious infrastructure |
| **[Two interfaces](#running-it)** | A browser dashboard and a native desktop app — same data, same detections, pick whichever fits |
| **Notifications** | Native Windows (Action Center) toast the moment a high-severity alert fires |
| **[Reliability](#running-it)** | Crash-resilient collector loop, rotating log file, optional auto-start at logon with restart-on-failure |
| **[Log retention](#log-retention)** | Old raw events auto-purge on a schedule; alerts (the valuable distilled output) are kept much longer |
| **[Testing & security](#testing)** | 113 unit tests, zero known dependency CVEs, zero Medium/High static-analysis findings |

## Architecture

```
Windows Event Log (Security, System)         Sysmon (Microsoft-Windows-Sysmon/Operational)
              \_______________________  ________________________/
                                      \/
                              siem/collector.py
                        (pywin32 Evt* API, polls channels,
                     per-channel watermark for safe resume)
                                      |
                                      v
                              siem/normalize.py
                     (raw event XML -> common schema dict)
                                      |
                                      v
                               siem/storage.py  (SQLite: events, alerts)
                                      |
                                      v
                                siem/engine.py
                      (runs each new event through siem/rules/*)
                                      |
                      rule match --> siem/alerts.py --> alerts table
                                      |
                                      v
                              dashboard/app.py (Flask)
                    localhost web UI: live events, alerts, charts
```

Two independent long-running processes share one SQLite file:
- **`run_collector.py`** — the only writer. Must run elevated (reading the `Security` and Sysmon channels requires admin rights).
- **`run_dashboard.py`** — read-only web UI, no admin rights needed.

Sysmon is wired in as just another Windows Event Log channel — `siem/collector.py` doesn't know or care that it's a different telemetry source, since both Sysmon and the classic channels are read through the same `win32evtlog` Evt* API.

## Detections (MITRE ATT&CK-mapped)

| Rule | Trigger | Technique | Severity |
|---|---|---|---|
| `brute_force` | N failed logons (4625) from the same source within a time window | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) | High |
| `new_admin_account` | New local account created (4720) | [T1136 – Create Account](https://attack.mitre.org/techniques/T1136/) | Medium |
| `new_admin_account` | Account added to the `Administrators` group (4732) | [T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/) | High |
| `afterhours_logon` | Interactive/RDP logon (4624) outside configured business hours | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Low |
| `encoded_powershell` | PowerShell launched with `-enc`/`-EncodedCommand` (Sysmon event 1) | [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/) | High |
| `suspicious_parent_child` | Office app (Word/Excel/PowerPoint/Outlook) spawns a shell or script interpreter (Sysmon event 1) | [T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | High |
| `threat_intel_match` | A logon source IP, or an outbound Sysmon network connection, matches a known-malicious IP from the threat intel feed | TA0011 – Command and Control (tactic, not a technique — see below) | High |
| `port_scan_detection` | N distinct local ports blocked from the same remote IP within a time window (event 5157) | [T1595 – Active Scanning](https://attack.mitre.org/techniques/T1595/) | Medium |
| `powershell_scriptblock` | PowerShell script block content matches a download-cradle, offensive-tool, or encoded-command pattern (event 4104) | [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/) | High |
| `credential_access` | A process opens `lsass.exe` with memory-read access (Sysmon event 10) | [T1003 – OS Credential Dumping](https://attack.mitre.org/techniques/T1003/) | High |
| `persistence` | New scheduled task created (4698) | [T1053.005 – Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | Medium |
| `persistence` | New service installed (7045) | [T1543.003 – Windows Service](https://attack.mitre.org/techniques/T1543/003/) | Medium |

All thresholds and business hours are configurable in `config.yaml`. Business hours are evaluated in UTC to avoid timezone/DST ambiguity — see `siem/rules/afterhours_logon.py`.

`threat_intel_match` is different from the other rules: it's an indicator-of-compromise match against a live feed, not a fixed behavioral pattern, so it isn't tagged with a single ATT&CK technique ID the way the others are — see [Threat intelligence feed](#threat-intelligence-feed) below.

`port_scan_detection` needs Windows' "Filtering Platform Connection" audit policy (failure) enabled to see anything — both `run_collector.py` and `desktop_app.py` enable it automatically at startup (via `auditpol.exe`) when this rule is on, so there's no manual setup step. It's deliberately failure-only, not success: auditing every *allowed* connection would log essentially all network traffic on the machine, while failure-only mostly captures unsolicited/blocked connection attempts — exactly what a port scan produces. Microsoft's own documentation is internally inconsistent about which raw XML field (`SourceAddress`/`DestAddress`) represents "this machine" vs. "the remote side" for this event, so the rule sidesteps that ambiguity entirely: it checks both fields against this machine's actual local IP addresses and treats whichever one *isn't* local as the remote scanner — see `siem/rules/port_scan_detection.py`.

### Detection setup (`powershell_scriptblock`, `credential_access`)

Unlike `port_scan_detection` and `persistence`'s scheduled-task check (both self-configuring via `auditpol.exe` at startup), these two need a one-time manual step each — Windows doesn't expose either as a simple audit-policy subcategory, so there's no automatic-enable path here the way there is for the others:

- **`powershell_scriptblock`** needs PowerShell Script Block Logging turned on (off by default). From an elevated PowerShell prompt:
  ```powershell
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
  ```
  Takes effect for new PowerShell sessions, no reboot needed.

- **`credential_access`** needs Sysmon's ProcessAccess monitoring (event 10) enabled for `lsass.exe` — off by default in the stock SwiftOnSecurity config ("can cause high system load" if left unscoped to everything). This repo's `sysmon/sysmonconfig-export.xml` already scopes it to `lsass.exe` only; if you installed Sysmon before this rule was added, re-apply the config from an elevated terminal:
  ```
  cd sysmon
  .\Sysmon64.exe -c sysmonconfig-export.xml
  ```

## Screenshots

| Dashboard | Alerts |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.jpg) | ![Alerts](docs/screenshots/alerts.jpg) |

## Setup

Requires Windows and Python 3.10+.

**One command**, from the project folder (PowerShell):
```powershell
.\setup.ps1
```
Creates the virtual environment and installs dependencies. Safe to re-run any time (e.g. after pulling an update) — every step is a no-op if already done. You don't need to run this yourself before `.\start.bat` or `.\create_shortcut.ps1` either — both bootstrap themselves via `setup.ps1` automatically on first run if `.venv` doesn't exist yet, so a completely fresh clone works from a single double-click.

<details>
<summary>What setup.ps1 does, if you'd rather run it by hand</summary>

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```
</details>

Review `config.yaml` — channels watched, detection thresholds, poll interval, and the SQLite file path all live there. Defaults work out of the box; nothing below is required to get the app running.

**Sysmon** (required for the `encoded_powershell` and `suspicious_parent_child` rules): install it with the [SwiftOnSecurity baseline config](https://github.com/SwiftOnSecurity/sysmon-config), from an elevated terminal:
```
cd sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
Verify it's readable (also needs elevation — Sysmon's channel has the same restrictive ACL as Security):
```
python sysmon\check_access.py
```

## Log retention

Raw events are high-volume and low long-term value once they've passed through the detection engine, so they're purged after a configurable window — alerts (the distilled, valuable output) are kept much longer. Both run automatically in the background (no separate scheduled task needed) and are configurable under `retention` in `config.yaml`:

```yaml
retention:
  enabled: true
  events_retention_days: 30     # raw events
  alerts_retention_days: 365    # alerts
  check_interval_hours: 24      # how often to check whether a purge is due
```

A purge runs a `VACUUM` afterward so the SQLite file actually shrinks, not just the logical row count.

## Threat intelligence feed

Cross-references observed IPs against [abuse.ch ThreatFox](https://threatfox.abuse.ch/) — a free, community-maintained feed of IPs/domains/hashes tied to tracked malware campaigns. Two things get checked:
- **Logon source IPs** (Security channel, 4624/4625) — catches an inbound attack from a known-malicious IP.
- **Outbound Sysmon network connections** (event ID 3, initiated by this machine) — catches this machine calling out to known-malicious infrastructure, e.g. a C2 callback.

Disabled by default since it needs a free Auth-Key:
1. Sign in at [auth.abuse.ch](https://auth.abuse.ch/) with an existing Google/GitHub/LinkedIn/X account (free, no card required) and generate an Auth-Key.
2. Copy `secrets.yaml.example` to `secrets.yaml` (gitignored — never commit real keys) and paste your key into `threatfox_api_key`.
3. Set `threat_intel.enabled: true` in `config.yaml`.

The feed refreshes on its own schedule (`refresh_interval_hours`, default 24h) via the same background maintenance pass as retention — no separate process to run.

## Attack-surface scanning (Posture tab)

Unlike the detection rules (which react to streaming events), this is a point-in-time check of the machine's *current* exposure — a finding means "this is still true right now," not "this happened once," so each scan replaces the previous findings rather than accumulating history.

v1 covers one check: **listening TCP ports**, flagged by how exposed they are. A well-known lateral-movement/exploitation target (RDP, SMB, NetBIOS, RPC, FTP, Telnet, common DB ports) listening on `0.0.0.0` (or any non-loopback address — reachable from other machines on the network) is High; the same port bound only to `127.0.0.1` is Low; anything else exposed on all interfaces gets a quiet Low visibility entry. Runs automatically once every 24h (`posture.scan_interval_hours`) plus on-demand via the desktop app's **Scan Now** button.

## Alert correlation

Any single alert can be weak on its own — an after-hours logon happens for plenty of legitimate reasons. But if the *same* user or source IP triggers two or more distinct rules within a short window (afterhours logon, then a new admin account, then a brute-force burst — all traceable back to one actor within 15 minutes), that's a much stronger signal than any one of them alone, and easy to miss scanning the alert list one row at a time.

`siem/correlation.py` watches for this: when a newly-raised alert pushes an actor's distinct-rule count (within `correlation.window_minutes`, default 15) to `correlation.min_signals` (default 2) or higher, it raises one synthetic **High**-severity `correlated` alert summarizing which rules fired, and notifies same as any other alert. It only fires once per actor per active burst — not again on every subsequent alert once the threshold's already been flagged. Configurable (including fully off) under `correlation` in `config.yaml`, or the desktop app's Settings → Alert Correlation card.

## Response actions

Everything above is detection/visibility only — nothing in this project ever blocks anything on its own. `siem/response.py` adds one manual, human-in-the-loop action: **block an IP** via a Windows Firewall rule, triggered by clicking "Block Source IP" on a selected alert (desktop app's Alerts tab) or "Block" next to an alert row (web dashboard). Both require an explicit confirmation before anything happens.

Safety: only a public/global-routable IP can be blocked — `is_blockable_ip()` explicitly rejects private (RFC 1918), loopback, link-local, multicast, and reserved ranges, so this structurally can't be used to lock yourself out of your own LAN, router, or localhost, even by accident. Blocking is idempotent (blocking an already-blocked IP is a no-op success) and adds *both* an inbound and an outbound rule (so this machine can't be reached by, or reach out to, the blocked address) under one shared rule name, so unblocking removes both with a single call. Currently-blocked IPs are tracked in the `blocked_ips` table and listed in both UIs, each with its own "Unblock" action.

## Running it

There are two interfaces: a browser dashboard (two processes) or a native desktop app (one process, one window). Pick whichever fits.

### Desktop app

Run `.\create_shortcut.ps1` once to get a double-clickable desktop shortcut (uses `pythonw.exe` — no console window, and the app window forces itself to the foreground on launch). Or run it directly:
```
python desktop_app.py
```
A single self-elevating process: prompts once for Administrator via UAC, then opens a native window with four tabs:
- **Dashboard** — stat tiles, charts, recent alerts/events (newest first, older rows pushed down)
- **Alerts** — full alert history, filterable by severity
- **Posture** — attack-surface findings (see below) + a **Scan Now** button
- **Settings** — detection rule toggles + thresholds, retention windows, threat intel (including pasting in your Auth-Key), light/dark theme, display timezone (UTC or your system's local time — storage and business-hours logic always stay UTC regardless)

Settings changes are written to `user_settings.yaml` (gitignored, layered over `config.yaml` — your defaults file's comments are never touched) and take effect **immediately**, no restart, except the collector's poll interval (that's baked into the background thread at startup). The collector runs inside the same process on a background thread — no separate window, no browser. Auto-generates a default `config.yaml` next to itself if one doesn't already exist, so it also works as a standalone downloaded exe (see Roadmap).

**Auto-start at logon** (optional, for leaving it running permanently): from an elevated PowerShell prompt, run `.\register_autostart.ps1` once. It registers a Scheduled Task that launches the desktop app at logon, already elevated (no UAC click needed at logon) and set to restart itself up to 3 times if the process ever dies. Undo with `.\unregister_autostart.ps1`.

**Notifications**: a native Windows notification (Action Center toast) fires whenever an alert at or above a configurable severity is raised (default: High only) — see the Settings tab's Notifications card, or `notifications` in `config.yaml`.

### Browser dashboard

**Easiest way** — double-click `start.bat` (or run `.\start.bat` from the project root). It launches the collector in its own window (prompting once for Administrator via UAC), the dashboard in another window, and opens **http://127.0.0.1:5000** in your browser. Close either window to stop that process. No manual venv activation needed — the scripts call the venv's Python directly.

To run either half on its own:
```
.\start_collector.bat    REM self-elevates via UAC, since it reads Security/Sysmon
.\start_dashboard.bat    REM no elevation needed
```

**Manual/CI equivalent** (with the venv active):
```
python run_collector.py    # from an elevated terminal
python run_dashboard.py    # from a regular terminal
```

> Note: this machine has `NoDefaultCurrentDirectoryInExePath` set, a common security hardening setting that stops `cmd.exe` from running a bare filename out of the current directory. Always invoke the `.bat` files with an explicit `.\` prefix (as above) rather than typing the bare filename.

## Testing

```
pytest
```

Unit tests cover event normalization, all ten detection rules, alert correlation, the block/unblock response action, retention purging, maintenance scheduling, audit policy handling, the posture scanner's netstat parsing, the collector's crash-resilience loop, and the desktop app's settings-merge/timezone logic with synthetic data — no real Windows Event Log access required, so they run anywhere (including CI).

### Security scanning

```
pip install -r requirements-dev.txt
pip-audit -r requirements.txt      # dependency CVEs
bandit -r . -x ./.venv,./tests     # static analysis (subprocess usage, XXE, etc.)
```

Both run clean as of the last pass: no known CVEs in any dependency, and bandit reports zero Medium/High findings (dependency parsing is hardened via `defusedxml.defuse_stdlib()`, called once at each entrypoint's startup; `auditpol`/`netstat`/`netsh` are invoked by full `%SystemRoot%\System32` path rather than relying on `PATH`). The remaining Low-severity findings are inherent to a tool that has to shell out to Windows utilities at all (flagged for using `subprocess` in the first place) — each call already uses an argument list, never `shell=True`.

### Hardening beyond the automated scan

A few things bandit/pip-audit don't check for, done anyway:

- **CSRF protection on the two write endpoints** (`/api/alerts/<id>/block-ip`, `/api/blocked-ips/<ip>/unblock`) — a browser will happily send a cross-origin POST to `localhost` from any page a user has open in another tab, and the client-side confirmation dialog in `dashboard.js` is no defense against that (a forged request never runs that code at all). Both routes reject any request whose `Origin`/`Referer` doesn't match the dashboard's own origin. See `dashboard/app.py`'s `_check_same_origin`.
- **Security response headers** on every dashboard response: the default `Server: Werkzeug/x.y Python/x.y` banner is replaced (don't hand out exact framework/interpreter versions for free), plus `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (this dashboard is never meant to be framed — closes off a clickjacking path to the block-IP button), and `Referrer-Policy: no-referrer`.
- **Data minimization on JSON API responses** — `/api/events` used to serialize the *entire* stored row, including `raw_xml` (the full Windows Event Log XML, which for a PowerShell/Sysmon event can contain a complete command line or script block that the UI never displays). Both `/api/events` and `/api/alerts` now use an explicit field allowlist rather than "everything except the field I noticed was sensitive" — a new column added to either table later is excluded by default until someone deliberately opts it into the API.
- **File permissions**: `secrets.yaml` (the ThreatFox API key) and `siem.db` (the full local telemetry history) are restricted to the current Windows user only via `icacls`, once at startup/save — see `siem/file_security.py`. Best-effort and non-fatal if it fails (e.g. a non-NTFS filesystem).
- **Secrets never touch a log line** — grepped for it; confirmed clean. `secrets.yaml` itself has never been committed (verified against full git history, not just the current `.gitignore`).

## Roadmap

- [x] Phase 0 — project scaffold
- [x] Phase 1 — Windows Event Log collector + SQLite storage
- [x] Phase 2 — detection engine + MITRE ATT&CK-mapped rules
- [x] Phase 3 — Flask web dashboard
- [x] Phase 4 — Sysmon integration (process-creation, suspicious parent/child rules)
- [x] Phase 5 — polish, screenshots, MITRE coverage table
- [x] Native desktop app (`desktop_app.py`) — Tkinter GUI, single self-elevating process
- [x] Log retention (auto-purge old events/alerts) + threat intel feed (abuse.ch ThreatFox)
- [x] Settings tab (live-editable detection/retention/threat-intel config) + light/dark theme + display timezone
- [x] Port scan / active reconnaissance detection (T1595), auto-enables the required Windows audit policy
- [x] Attack-surface scanning (Posture tab) — exposed/listening port checks, on-demand + periodic
- [x] Reliability: crash-resilient collector loop, rotating file logging, native Windows notifications, auto-start-at-logon script
- [x] Detection coverage: PowerShell script block obfuscation (T1059.001), LSASS credential access (T1003), scheduled task / new service persistence (T1053.005 / T1543.003)
- [x] Alert correlation — chains related alerts from the same actor into one higher-confidence alert
- [x] Response actions — human-confirmed "Block Source IP" (Windows Firewall) from either UI, with a "Blocked IPs" management list
- [ ] Package `desktop_app.py` into a standalone downloadable `.exe` (PyInstaller)

## License

MIT
