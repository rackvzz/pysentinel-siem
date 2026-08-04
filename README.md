# pysentinel-siem

A lightweight SIEM (Security Information and Event Management) system, built from scratch in Python, that runs on a single Windows host. It collects Windows Event Log (and, later, Sysmon) telemetry, stores it, evaluates it against MITRE ATT&CK-mapped detection rules, and surfaces alerts through a local web dashboard.

> Status: in progress. This README is being filled in as each phase lands — see the roadmap below.

## Why

Built as a hands-on companion to CompTIA Security+ study: rather than only reading about SIEM concepts (log normalization, correlation rules, detection engineering), this implements a minimal but real version of one, end to end.

## Architecture

```
Windows Event Log (Security, System)         Sysmon (Microsoft-Windows-Sysmon/Operational)
              \_______________________  ________________________/
                                      \/
                              siem/collector.py
                        (pywin32, polls channels, bookmarks
                         last-read position per channel)
                                      |
                                      v
                              siem/normalize.py
                     (raw event -> common schema dict)
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
- `run_collector.py` — the only writer. Must run elevated (reading the Security channel requires admin rights).
- `run_dashboard.py` — read-only web UI.

## Roadmap

- [x] Phase 0 — project scaffold
- [ ] Phase 1 — Windows Event Log collector + SQLite storage
- [ ] Phase 2 — detection engine + MITRE ATT&CK-mapped rules
- [ ] Phase 3 — Flask web dashboard
- [ ] Phase 4 — Sysmon integration + process-creation rules
- [ ] Phase 5 — polish, screenshots, MITRE coverage table

## Setup

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Full run instructions land in Phase 5 once the collector and dashboard are both in place.

## License

MIT
