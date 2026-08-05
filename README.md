# pysentinel-siem

A lightweight SIEM (Security Information and Event Management) system, built from scratch in Python, that runs on a single Windows host. It collects Windows Event Log telemetry, stores it, evaluates it against MITRE ATT&CK-mapped detection rules, and surfaces alerts through a local web dashboard.

![Dashboard screenshot](docs/screenshots/dashboard.jpg)

## Why

Built as a hands-on companion to CompTIA Security+ study: rather than only reading about SIEM concepts (log normalization, correlation rules, detection engineering), this implements a minimal but real version of one, end to end, on my own machine.

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

All thresholds and business hours are configurable in `config.yaml`. Business hours are evaluated in UTC to avoid timezone/DST ambiguity — see `siem/rules/afterhours_logon.py`.

`threat_intel_match` is different from the other rules: it's an indicator-of-compromise match against a live feed, not a fixed behavioral pattern, so it isn't tagged with a single ATT&CK technique ID the way the others are — see [Threat intelligence feed](#threat-intelligence-feed) below.

`port_scan_detection` needs Windows' "Filtering Platform Connection" audit policy (failure) enabled to see anything — both `run_collector.py` and `desktop_app.py` enable it automatically at startup (via `auditpol.exe`) when this rule is on, so there's no manual setup step. It's deliberately failure-only, not success: auditing every *allowed* connection would log essentially all network traffic on the machine, while failure-only mostly captures unsolicited/blocked connection attempts — exactly what a port scan produces. Microsoft's own documentation is internally inconsistent about which raw XML field (`SourceAddress`/`DestAddress`) represents "this machine" vs. "the remote side" for this event, so the rule sidesteps that ambiguity entirely: it checks both fields against this machine's actual local IP addresses and treats whichever one *isn't* local as the remote scanner — see `siem/rules/port_scan_detection.py`.

## Screenshots

| Dashboard | Alerts |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.jpg) | ![Alerts](docs/screenshots/alerts.jpg) |

## Setup

Requires Python 3.10+ on Windows.

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Review `config.yaml` — channels watched, detection thresholds, poll interval, and the SQLite file path all live there.

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

Unit tests cover event normalization, all seven detection rules, retention purging, maintenance scheduling, audit policy handling, the posture scanner's netstat parsing, and the desktop app's settings-merge/timezone logic with synthetic data — no real Windows Event Log access required, so they run anywhere (including CI).

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
- [ ] Package `desktop_app.py` into a standalone downloadable `.exe` (PyInstaller)
- [ ] Firewall management (block specific IPs/ports) — scoping in progress

## License

MIT
