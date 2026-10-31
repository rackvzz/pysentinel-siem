# Contributing

Thanks for taking a look. Bug reports, new detection ideas, and pull requests are all welcome.

## Setup

The app needs Windows to collect real events. Development and tests work on any OS.

```powershell
# Windows
.\setup.ps1
.venv\Scripts\pip install -r requirements-dev.txt
```

```bash
# macOS / Linux (tests and the dashboard against a sample DB only)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

## Before opening a pull request

```bash
pytest                          # all tests pass
ruff check .                    # lint + import order
bandit -c pyproject.toml -r .   # no new medium/high findings
```

CI runs the same checks on Windows and Ubuntu.

## Adding a detection rule

1. Create `siem/rules/<rule_name>.py` with a subclass of `Rule` from `siem/rules/base.py`. Set `id`, `name`, `mitre_id`, and `severity`, and implement `evaluate(conn, event, row_id)`.
2. Register it in `siem/engine.py` and add an `enabled` toggle (plus any thresholds) under `detections` in `config.yaml`.
3. Add tests in `tests/test_rules.py`, covering both an event that should fire and one that shouldn't.
4. Add a row to the detections table in `README.md` with the Windows event ID, trigger, and ATT&CK technique.
5. If the rule needs an audit policy or Sysmon setting that's off by default, document it under "Detection setup".

## UI changes

The dashboard and desktop app target **WCAG 2.2 AA**:

- Text contrast of at least 4.5:1. Use the `--*-text` color tokens for colored text, not the fill colors.
- Everything works with the keyboard alone, with a visible focus ring.
- Never rely on color by itself. Severity always has a text label.
- Respect `prefers-reduced-motion`.
- No inline `<script>` or `style=""`. The Content-Security-Policy blocks them.

## Versioning

Versions follow [SemVer](https://semver.org/). The version lives in `siem/__init__.py` only. Record user-visible changes under "Unreleased" in `CHANGELOG.md`.
