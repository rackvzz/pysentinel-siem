# Security Policy

pysentinel-siem is a security tool. It runs elevated, reads the Security event log, and can change Windows Firewall rules, so I take vulnerabilities in it seriously.

## Supported versions

| Version | Supported |
|---|---|
| 1.1.x | Yes |
| 1.0.x | Security fixes only |
| < 1.0 | No |

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://github.com/rackvzz/pysentinel-siem/security/advisories/new).

Include:

- the version (shown in the dashboard footer, or `siem/__init__.py`)
- what an attacker could do, and what access they'd need first
- steps to reproduce, or a proof of concept

This is a one-person project, so responses are best effort. I aim to acknowledge reports within 7 days and to fix confirmed high-severity issues within 30 days. I'll credit you in the release notes unless you'd rather stay anonymous.

## In scope

- Anything that lets a non-admin user or a web page (including another browser tab) trigger the block/unblock actions, read collected events, or run code through the dashboard
- Ways to make the collector crash or stop detecting by feeding it crafted event log content
- Secrets (the ThreatFox API key) or event data leaking into logs, API responses, or files readable by other users
- Dependency vulnerabilities that are actually reachable from this code

## Out of scope

- Attacks that already require local admin rights. An admin can turn off any host-based tool.
- Detection gaps (an attack technique the rules don't catch). Those are welcome as feature requests.
- Findings that only affect the dashboard if someone deliberately rebinds it from `127.0.0.1` to a public interface.

## How the project defends itself

A summary of the existing controls, so reports can be measured against them:

- The dashboard listens on `127.0.0.1` only.
- State-changing endpoints check `Origin`/`Referer` (CSRF protection).
- Every response carries a strict `Content-Security-Policy` (no inline scripts or styles, no third-party origins), plus `X-Frame-Options: DENY`, `nosniff`, and `no-referrer`.
- API responses use explicit field allowlists, so raw event XML (which can contain full command lines) never leaves the backend.
- API query parameters are validated and clamped.
- XML parsing is hardened with `defusedxml` against XXE and entity-expansion attacks.
- `siem.db` and `secrets.yaml` are restricted to the current Windows user with `icacls`.
- Blocking refuses private, loopback, link-local, multicast, and reserved addresses, so you can't lock yourself out of your own network.
- CI runs Bandit (static analysis) and pip-audit (known CVEs) on every push.
