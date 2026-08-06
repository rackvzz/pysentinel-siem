"""Thin wrapper around storage.insert_alert so rules don't need to build
the alert dict / timestamp format themselves. Also fires a native Windows
notification for alerts at or above the configured severity threshold --
see notifier.py -- and, after storing the alert, hands off to
correlation.py to check whether this pushes the same actor over the
threshold for a synthetic "correlated" alert. Individual Rule instances
only get the config values their own constructor needs (see
engine.configure), so this module holds its own small piece of live
config the same way -- call configure() once at startup and again
whenever settings change, mirroring engine.configure.
"""

import datetime

from . import notifier, storage

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

_notify_settings = {"enabled": True, "min_severity": "high"}


def configure(config: dict) -> None:
    n = config.get("notifications", {})
    _notify_settings["enabled"] = n.get("enabled", True)
    _notify_settings["min_severity"] = n.get("min_severity", "high")


def _maybe_notify(rule_id: str, severity: str, description: str) -> None:
    threshold = _SEVERITY_RANK.get(_notify_settings["min_severity"], 2)
    if _notify_settings["enabled"] and _SEVERITY_RANK.get(severity, 0) >= threshold:
        notifier.notify_alert(rule_id, severity, description)


def raise_alert(conn, rule_id: str, mitre_id: str, severity: str, description: str, event_id_ref: int) -> int:
    alert = {
        "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "rule_id": rule_id,
        "mitre_id": mitre_id,
        "severity": severity,
        "description": description,
        "event_id_ref": event_id_ref,
    }
    alert_id = storage.insert_alert(conn, alert)
    _maybe_notify(rule_id, severity, description)

    from . import correlation  # local import: avoids a circular import at module load (correlation imports this module)

    correlation.check(conn, event_id_ref, alert["ts"])

    return alert_id
