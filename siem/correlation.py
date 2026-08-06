"""Chains independently-firing alerts from the same actor into one
higher-confidence "correlated" alert, when 2+ distinct rules fire for the
same user or source IP within a short window. Any single one of these
signals can be fairly weak on its own -- an after-hours logon happens,
plenty of legitimate reasons exist -- but two or three from the same
actor close together (afterhours logon, then a new admin account, then a
brute-force burst, all traceable to the same user or IP within 15
minutes) is a much stronger indicator than the sum of its parts, and
easy to miss if you're only scanning the alert list one row at a time.

Actor identity is looked up via each alert's event_id_ref -> events.user /
events.source_ip -- no schema change needed, that join already exists.
The synthetic "correlated" alert is inserted directly via
storage.insert_alert rather than through alerts.raise_alert, so it can
never trigger another correlation pass or get correlated into itself.
"""

import datetime
import logging

from . import storage
from .rules.base import parse_ts

logger = logging.getLogger("siem.correlation")

_settings = {"enabled": True, "window_minutes": 15, "min_signals": 2}


def configure(config: dict) -> None:
    c = config.get("correlation", {})
    _settings["enabled"] = c.get("enabled", True)
    _settings["window_minutes"] = c.get("window_minutes", 15)
    _settings["min_signals"] = c.get("min_signals", 2)


def _actor_for_event(conn, event_id_ref):
    """Returns (user, source_ip) for the event an alert references, each
    None if unknown/empty -- empty-string columns (normalize.py's default
    for a missing field) are normalized to None here specifically so an
    empty-string match never falsely links two unrelated actors together
    in the SQL query below."""
    if event_id_ref is None:
        return None, None
    row = conn.execute("SELECT user, source_ip FROM events WHERE id = ?", (event_id_ref,)).fetchone()
    if not row:
        return None, None
    return (row["user"] or None), (row["source_ip"] or None)


def check(conn, event_id_ref: int, ts: str) -> None:
    """Called by alerts.raise_alert after a normal alert is stored.
    Looks for other alerts from the same actor within the correlation
    window, and raises one synthetic "correlated" alert the first time
    the min_signals threshold is crossed for that actor in this window."""
    if not _settings["enabled"]:
        return

    user, source_ip = _actor_for_event(conn, event_id_ref)
    if not user and not source_ip:
        return

    window_start = (
        parse_ts(ts) - datetime.timedelta(minutes=_settings["window_minutes"])
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    rows = conn.execute(
        """
        SELECT a.rule_id
        FROM alerts a
        JOIN events e ON e.id = a.event_id_ref
        WHERE a.ts >= ? AND a.rule_id != 'correlated'
          AND ((? IS NOT NULL AND e.user = ?) OR (? IS NOT NULL AND e.source_ip = ?))
        """,
        (window_start, user, user, source_ip, source_ip),
    ).fetchall()

    distinct_rules = {r["rule_id"] for r in rows}
    if len(distinct_rules) < _settings["min_signals"]:
        return

    # Only fire once per actor per still-active burst -- not again on
    # every subsequent alert once the threshold's already been flagged.
    already = conn.execute(
        """
        SELECT COUNT(*) AS n
        FROM alerts a
        JOIN events e ON e.id = a.event_id_ref
        WHERE a.rule_id = 'correlated' AND a.ts >= ?
          AND ((? IS NOT NULL AND e.user = ?) OR (? IS NOT NULL AND e.source_ip = ?))
        """,
        (window_start, user, user, source_ip, source_ip),
    ).fetchone()["n"]
    if already:
        return

    actor_desc = user or source_ip
    alert = {
        "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "rule_id": "correlated",
        "mitre_id": "Multiple",
        "severity": "high",
        "description": (
            f"{len(distinct_rules)} distinct alerts for '{actor_desc}' within "
            f"{_settings['window_minutes']} minutes: {', '.join(sorted(distinct_rules))}"
        ),
        "event_id_ref": event_id_ref,
    }
    storage.insert_alert(conn, alert)
    logger.info("Correlated alert raised for actor '%s': %s", actor_desc, sorted(distinct_rules))

    from . import alerts  # local import: avoids a circular import at module load (alerts imports this module too)

    alerts._maybe_notify("correlated", "high", alert["description"])
