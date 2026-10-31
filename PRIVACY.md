# Privacy and Data Handling

pysentinel-siem collects security telemetry from the Windows machine it runs on. This page says exactly what it collects, where that data goes, and what you're responsible for when you run it.

## What it collects

From the Windows Event Log channels listed in `config.yaml` (by default Security, System, Sysmon, and PowerShell/Operational):

- usernames and account names
- source and destination IP addresses
- process names, full command lines, and parent processes (Sysmon)
- PowerShell script block contents (if Script Block Logging is turned on)
- logon times, service and scheduled-task names, and similar event details

Command lines and script blocks can contain sensitive data (file paths, and sometimes passwords that people typed on a command line).

## Where it's stored

- **Everything stays on this machine** in `siem.db`, a SQLite file next to the app.
- At startup, `siem.db` and `secrets.yaml` are restricted to the current Windows user (`icacls`).
- Raw events are deleted after **30 days** and alerts after **365 days** by default. Change this under `retention` in `config.yaml` or in the desktop app's Settings tab.
- The dashboard's API never returns the raw event XML. It only returns the summary fields shown in the UI.

## What leaves the machine

**Nothing, by default.** There is no telemetry, analytics, crash reporting, or update check.

The only network traffic happens if you **turn on the threat intelligence feed**. Then the app downloads the list of recent indicators from [abuse.ch ThreatFox](https://threatfox.abuse.ch/) every 24 hours, authenticated with your API key. Matching happens locally. **Your events, IPs, and usernames are never sent to ThreatFox.** The only thing abuse.ch sees is that your API key downloaded the feed.

The dashboard binds to `127.0.0.1`, so other machines on your network can't reach it.

## Your responsibilities

You are the one collecting this data, so:

- **Only run it on systems you own or are authorized to administer.**
- **If other people use the machine** (family members, employees, students), you may be collecting their personal data. Depending on where you are, that can require telling them, getting consent, or having a lawful basis to process it. Examples include the EU's GDPR and US state laws, such as New York's and Connecticut's, that require employers to notify employees about electronic monitoring.
- The **Block IP** action changes Windows Firewall rules. Only block addresses you have a reason to block.

This is general information, not legal advice. If you're deploying this anywhere other than your own personal machine, check what applies to you.

## Deleting your data

If you used the installer, uninstall from **Settings → Apps**. That removes the database, logs, settings, and API key file. For the portable zip, close the app and delete `siem.db` (plus `siem.db-wal` and `siem.db-shm` if present) and `pysentinel-siem.log*`. To remove the API key, delete `secrets.yaml`. Firewall rules added by the app are named `pysentinel-siem-block-<ip>`. Unblock them in the app first, or remove them in Windows Defender Firewall.
