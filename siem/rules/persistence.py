"""T1053.005 - Scheduled Task / T1543.003 - Windows Service
https://attack.mitre.org/techniques/T1053/005/
https://attack.mitre.org/techniques/T1543/003/

Fires on:
  - 4698 (Security channel: a scheduled task was created) -> T1053.005.
    Needs the "Other Object Access Events" audit subcategory (success) --
    off by default; siem/audit_policy.ensure_object_access_auditing_enabled()
    turns it on automatically at startup when this rule is enabled, same
    pattern as port_scan_detection's audit policy.
  - 7045 (System channel: a new service was installed) -> T1543.003.
    No audit policy needed -- the Service Control Manager logs this
    unconditionally.

Both are severity "medium": legitimate software installs create scheduled
tasks and services constantly, so this is a visibility signal worth
reviewing (least-common-first, an unfamiliar task/service name or an
unusual install path stands out fast in the alert list) rather than a
high-confidence detection on its own.
"""

from .. import alerts
from ..normalize import parse_event_data
from .base import Rule


class PersistenceRule(Rule):
    id = "persistence"
    name = "New Scheduled Task or Service"
    mitre_id = "T1053.005 / T1543.003"
    severity = "medium"

    def __init__(self, scheduled_task_event_id: int = 4698, new_service_event_id: int = 7045):
        self.scheduled_task_event_id = scheduled_task_event_id
        self.new_service_event_id = new_service_event_id

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        if event["event_id"] == self.scheduled_task_event_id:
            data = parse_event_data(event["raw_xml"])
            task_name = data.get("TaskName", "unknown")
            user = data.get("SubjectUserName") or event["user"] or "unknown"
            alerts.raise_alert(
                conn,
                rule_id=self.id,
                mitre_id="T1053.005",
                severity=self.severity,
                description=f"Scheduled task '{task_name}' created by '{user}' on {event['computer']}",
                event_id_ref=row_id,
            )
        elif event["event_id"] == self.new_service_event_id:
            data = parse_event_data(event["raw_xml"])
            service_name = data.get("ServiceName", "unknown")
            image_path = data.get("ImagePath", "unknown")
            alerts.raise_alert(
                conn,
                rule_id=self.id,
                mitre_id="T1543.003",
                severity=self.severity,
                description=f"New service '{service_name}' installed on {event['computer']}: {image_path}",
                event_id_ref=row_id,
            )
