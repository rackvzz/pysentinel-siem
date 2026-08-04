"""T1110 - Brute Force
https://attack.mitre.org/techniques/T1110/

Fires when N failed logons (event 4625 by default) arrive from the same
source within a sliding time window.
"""

import datetime
from collections import defaultdict, deque

from .. import alerts
from .base import Rule, parse_ts


class BruteForceRule(Rule):
    id = "brute_force"
    name = "Brute Force Login Attempts"
    mitre_id = "T1110"
    severity = "high"

    def __init__(self, event_id: int = 4625, threshold: int = 5, window_seconds: int = 300):
        self.event_id = event_id
        self.threshold = threshold
        self.window_seconds = window_seconds
        # Per-source sliding window of recent failed-logon timestamps.
        # In-memory is fine here: the collector is a single long-lived
        # process, and this state doesn't need to survive a restart.
        self._attempts: dict[str, deque] = defaultdict(deque)
        self._last_alert: dict[str, datetime.datetime] = {}

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        if event["event_id"] != self.event_id:
            return

        source = event["source_ip"] or event["computer"] or "unknown"
        ts = parse_ts(event["ts"])

        window = self._attempts[source]
        window.append(ts)
        window_start = ts - datetime.timedelta(seconds=self.window_seconds)
        while window and window[0] < window_start:
            window.popleft()

        if len(window) < self.threshold:
            return

        # Don't re-alert on every subsequent failure once the threshold is
        # crossed -- one alert per burst.
        last_alert = self._last_alert.get(source)
        if last_alert and (ts - last_alert).total_seconds() < self.window_seconds:
            return
        self._last_alert[source] = ts

        alerts.raise_alert(
            conn,
            rule_id=self.id,
            mitre_id=self.mitre_id,
            severity=self.severity,
            description=(
                f"{len(window)} failed logons from '{source}' within "
                f"{self.window_seconds}s (target user: {event['user'] or 'unknown'})"
            ),
            event_id_ref=row_id,
        )
