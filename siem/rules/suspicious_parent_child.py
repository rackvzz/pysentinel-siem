"""T1059 - Command and Scripting Interpreter
https://attack.mitre.org/techniques/T1059/

Fires on Sysmon process creation (event ID 1) when a document-handling
application spawns a script interpreter or shell -- the classic
signature of a malicious macro document detonating its payload.
"""

from .. import alerts
from ..normalize import parse_event_data
from .base import Rule, basename

SUSPICIOUS_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe"}
SUSPICIOUS_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


class SuspiciousParentChildRule(Rule):
    id = "suspicious_parent_child"
    name = "Office Application Spawned a Script Interpreter"
    mitre_id = "T1059"
    severity = "high"

    def __init__(self, event_id: int = 1):
        self.event_id = event_id

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        if event["event_id"] != self.event_id:
            return

        data = parse_event_data(event["raw_xml"])
        parent = basename(data.get("ParentImage", "")).lower()
        child = basename(data.get("Image", "")).lower()
        if parent not in SUSPICIOUS_PARENTS or child not in SUSPICIOUS_CHILDREN:
            return

        alerts.raise_alert(
            conn,
            rule_id=self.id,
            mitre_id=self.mitre_id,
            severity=self.severity,
            description=(
                f"'{parent}' spawned '{child}' on {event['computer']} "
                f"(user: {data.get('User', 'unknown')})"
            ),
            event_id_ref=row_id,
        )
