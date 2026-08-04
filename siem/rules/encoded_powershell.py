"""T1059.001 - Command and Scripting Interpreter: PowerShell
https://attack.mitre.org/techniques/T1059/001/

Fires on Sysmon process creation (event ID 1) when PowerShell is
launched with an encoded/obfuscated command -- `-EncodedCommand`/`-enc`
is a base64-wrapped script, a very common way to smuggle a malicious
command past casual log review and naive string-matching AV signatures.
"""

from .. import alerts
from ..normalize import parse_event_data
from .base import Rule, basename

POWERSHELL_IMAGES = {"powershell.exe", "pwsh.exe"}
ENCODED_FLAGS = ("-enc", "-encodedcommand", " -e ")


class EncodedPowerShellRule(Rule):
    id = "encoded_powershell"
    name = "Encoded PowerShell Command"
    mitre_id = "T1059.001"
    severity = "high"

    def __init__(self, event_id: int = 1):
        self.event_id = event_id

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        if event["event_id"] != self.event_id:
            return

        data = parse_event_data(event["raw_xml"])
        image = basename(data.get("Image", "")).lower()
        if image not in POWERSHELL_IMAGES:
            return

        command_line = (data.get("CommandLine") or "").lower()
        if not any(flag in command_line for flag in ENCODED_FLAGS):
            return

        alerts.raise_alert(
            conn,
            rule_id=self.id,
            mitre_id=self.mitre_id,
            severity=self.severity,
            description=(
                f"Encoded PowerShell launched by '{data.get('User', 'unknown')}' on {event['computer']}: "
                f"{(data.get('CommandLine') or '')[:200]}"
            ),
            event_id_ref=row_id,
        )
