"""T1078 - Valid Accounts
https://attack.mitre.org/techniques/T1078/

Fires when a human-driven successful logon (event 4624, LogonType
Interactive/RemoteInteractive/Unlock) happens outside configured
business hours. Service/network/batch logons (LogonType 3, 4, 5, ...)
are deliberately excluded -- those happen constantly in the background
and would drown out anything meaningful.

Business hours are evaluated in UTC (matching how everything else in
this project stores timestamps) rather than the host's local time --
this sidesteps DST/timezone-offset ambiguity entirely. Set
business_hours_start/end in config.yaml as UTC hours.
"""

from .. import alerts
from ..normalize import parse_event_data
from .base import Rule, parse_ts

# LogonType values that represent an actual person sitting at (or
# remoting into) the machine, per Microsoft's event 4624 documentation.
HUMAN_LOGON_TYPES = {"2", "7", "10"}  # Interactive, Unlock, RemoteInteractive


class AfterHoursLogonRule(Rule):
    id = "afterhours_logon"
    name = "Successful Logon Outside Business Hours"
    mitre_id = "T1078"
    severity = "low"

    def __init__(self, event_id: int = 4624, business_hours_start: int = 7, business_hours_end: int = 19):
        self.event_id = event_id
        self.start = business_hours_start
        self.end = business_hours_end

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        if event["event_id"] != self.event_id:
            return

        data = parse_event_data(event["raw_xml"])
        if data.get("LogonType") not in HUMAN_LOGON_TYPES:
            return

        ts = parse_ts(event["ts"])
        if self.start <= ts.hour < self.end:
            return

        alerts.raise_alert(
            conn,
            rule_id=self.id,
            mitre_id=self.mitre_id,
            severity=self.severity,
            description=(
                f"Interactive logon by '{event['user'] or 'unknown'}' outside business hours "
                f"({ts.strftime('%Y-%m-%d %H:%M')} UTC)"
            ),
            event_id_ref=row_id,
        )
