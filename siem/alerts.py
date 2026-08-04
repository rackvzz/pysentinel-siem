"""Thin wrapper around storage.insert_alert so rules don't need to build
the alert dict / timestamp format themselves.
"""

import datetime

from . import storage


def raise_alert(conn, rule_id: str, mitre_id: str, severity: str, description: str, event_id_ref: int) -> int:
    alert = {
        "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "rule_id": rule_id,
        "mitre_id": mitre_id,
        "severity": severity,
        "description": description,
        "event_id_ref": event_id_ref,
    }
    return storage.insert_alert(conn, alert)
