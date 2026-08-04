"""Threat intelligence IOC match.

Checks two different observed-IP fields against the locally-cached
threat intel feed (siem/threat_intel.py, refreshed periodically from
abuse.ch ThreatFox):

  - Security channel logons (event 4624/4625): the already-normalized
    source_ip field -- catches an inbound logon attempt FROM a
    known-malicious IP.
  - Sysmon network connections (event ID 3), but only when
    Initiated="true" (i.e. this machine initiated the connection, not
    the reverse): the raw event's DestinationIp field -- catches THIS
    machine calling out to known-malicious infrastructure, e.g. a C2
    callback.

Unlike the other rules, this isn't tied to a single MITRE ATT&CK
technique -- an IOC match is evidence of known-bad infrastructure, not
a specific behavior. Tagged with the Command and Control tactic
(TA0011) rather than a technique ID.
"""

from .. import alerts
from ..normalize import parse_event_data
from .base import Rule

LOGON_EVENT_IDS = {4624, 4625}
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_NETWORK_CONNECT_EVENT_ID = 3


class ThreatIntelMatchRule(Rule):
    id = "threat_intel_match"
    name = "Known-Malicious IP Contacted"
    mitre_id = "TA0011"  # Command and Control (tactic, not a technique)
    severity = "high"

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        ip = None
        direction = None

        if event["event_id"] in LOGON_EVENT_IDS:
            ip = event["source_ip"]
            direction = "Inbound logon attempt from"
        elif event["channel"] == SYSMON_CHANNEL and event["event_id"] == SYSMON_NETWORK_CONNECT_EVENT_ID:
            data = parse_event_data(event["raw_xml"])
            if data.get("Initiated") == "true":
                ip = data.get("DestinationIp")
                direction = "Outbound connection to"

        if not ip or ip in ("-", ""):
            return

        row = conn.execute(
            "SELECT source, malware FROM threat_intel_iocs WHERE ioc_type = 'ip' AND value = ?", (ip,)
        ).fetchone()
        if not row:
            return

        malware = row["malware"] or "unattributed"
        alerts.raise_alert(
            conn,
            rule_id=self.id,
            mitre_id=self.mitre_id,
            severity=self.severity,
            description=(
                f"{direction} '{ip}', a known-malicious IP tracked by {row['source']} "
                f"(associated malware: {malware})"
            ),
            event_id_ref=row_id,
        )
