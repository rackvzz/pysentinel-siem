"""T1136 - Create Account / T1098 - Account Manipulation
https://attack.mitre.org/techniques/T1136/
https://attack.mitre.org/techniques/T1098/

Fires on:
  - 4720 (a user account was created)                 -> T1136
  - 4732 (a member was added to a security-enabled
          local group), only when that group is an
          administrative group                         -> T1098

Note on event 4732's fields: Windows confusingly reuses "TargetUserName"
to mean the *group* name for this event ID (not the account being added
to it) -- the account being added is "MemberName"/"MemberSid". We read
the raw EventData directly here rather than relying on the common
schema's `user` field, which would be misleading for this event.
"""

from .. import alerts
from ..normalize import parse_event_data
from .base import Rule

ADMIN_GROUPS = {"Administrators"}


class NewAdminAccountRule(Rule):
    id = "new_admin_account"
    name = "Account Created or Added to Administrators"
    mitre_id = "T1136 / T1098"
    severity = "medium"

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        if event["event_id"] == 4720:
            alerts.raise_alert(
                conn,
                rule_id=self.id,
                mitre_id="T1136",
                severity="medium",
                description=f"New local user account created: '{event['user']}' on {event['computer']}",
                event_id_ref=row_id,
            )
        elif event["event_id"] == 4732:
            data = parse_event_data(event["raw_xml"])
            group = data.get("TargetUserName", "")
            if group not in ADMIN_GROUPS:
                return
            member = data.get("MemberName") or data.get("MemberSid") or "unknown"
            alerts.raise_alert(
                conn,
                rule_id=self.id,
                mitre_id="T1098",
                severity="high",
                description=f"'{member}' added to '{group}' group on {event['computer']}",
                event_id_ref=row_id,
            )
