"""T1003 - OS Credential Dumping
https://attack.mitre.org/techniques/T1003/

Fires on Sysmon ProcessAccess (event ID 10) when a process opens a handle
to lsass.exe with memory-read rights -- the fundamental capability every
LSASS credential-dumping technique needs (Mimikatz and its many
derivatives all work this way, whatever their specific extraction method).

Requires sysmonconfig-export.xml's ProcessAccess RuleGroup to include
lsass.exe as a TargetImage (it's disabled entirely by default -- Sysmon's
own docs warn it "can cause high system load" if left unscoped). This
project's sysmonconfig-export.xml already scopes it to lsass.exe only;
re-apply the config (`Sysmon64.exe -c sysmonconfig-export.xml`) for that
to take effect if you installed Sysmon before this rule was added.

GrantedAccess filtering: most processes that touch lsass.exe (services
enumerating it, monitoring tools, antivirus) only ever request
PROCESS_QUERY_LIMITED_INFORMATION or similar -- they never ask for
PROCESS_VM_READ. This rule only fires when the granted access mask
includes PROCESS_VM_READ (0x0010), the access right actually needed to
read process memory. That's a narrower, more explainable signal than
matching a long, ever-changing list of specific "known-bad" access mask
values -- but it isn't perfect: a few legitimate tools (Task Manager's
"go to details", Process Explorer, some AV engines during a deep scan) do
occasionally request it too, so an occasional alert here can be benign.
"""

from .. import alerts
from ..normalize import parse_event_data
from .base import Rule, basename

PROCESS_VM_READ = 0x0010

# Sysmon logs GrantedAccess as a hex string, e.g. "0x1010" or "0x1FFFFF".
LSASS_IMAGE = "lsass.exe"


class CredentialAccessRule(Rule):
    id = "credential_access"
    name = "Possible LSASS Credential Dumping"
    mitre_id = "T1003"
    severity = "high"

    def __init__(self, event_id: int = 10):
        self.event_id = event_id

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        if event["event_id"] != self.event_id:
            return

        data = parse_event_data(event["raw_xml"])
        target = basename(data.get("TargetImage", "")).lower()
        if target != LSASS_IMAGE:
            return

        try:
            granted_access = int(data.get("GrantedAccess", "0x0"), 16)
        except (TypeError, ValueError):
            return
        if not (granted_access & PROCESS_VM_READ):
            return

        source = basename(data.get("SourceImage", "")).lower() or "unknown"
        alerts.raise_alert(
            conn,
            rule_id=self.id,
            mitre_id=self.mitre_id,
            severity=self.severity,
            description=(
                f"'{source}' opened lsass.exe with memory-read access "
                f"(GrantedAccess={data.get('GrantedAccess', '?')}) on {event['computer']}"
            ),
            event_id_ref=row_id,
        )
