"""T1595 - Active Scanning
https://attack.mitre.org/techniques/T1595/

Fires when many distinct local ports are probed by the same remote IP
within a short window. Windows Filtering Platform logs event 5157
once per blocked connection attempt, so a port scan (nmap and similar
tools rapidly probing many ports) leaves one 5157 per port probed.

Microsoft's own documentation is inconsistent about whether
SourceAddress/SourcePort or DestAddress/DestPort represents "this
machine" vs "the remote side" for this event -- the field descriptions
on the 5156 and 5157 doc pages directly disagree despite using the
same example XML. Rather than trust either, this rule determines the
remote side empirically: whichever of SourceAddress/DestAddress does
NOT match one of this machine's own local IP addresses is treated as
the remote IP, and the paired port on the *local* side is what gets
counted as "a distinct port probed". This is correct regardless of
which field the docs actually meant.

Requires 'Filtering Platform Connection' failure auditing enabled --
see siem/audit_policy.py, which the collector enables automatically at
startup when config.yaml's port_scan_detection.enabled is true.
"""

import datetime
import socket
from collections import defaultdict, deque

from .. import alerts
from ..normalize import parse_event_data
from .base import Rule, parse_ts

WFP_BLOCK_EVENT_ID = 5157


def local_ip_addresses() -> set[str]:
    """Best-effort set of this machine's own IP addresses, used to tell
    which side of a 5157 event is "us" vs "the remote scanner"."""
    addrs = {"127.0.0.1", "::1", "0.0.0.0", "::"}
    try:
        hostname = socket.gethostname()
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        addrs.update(ip_list)
    except OSError:
        pass
    return addrs


class PortScanDetectionRule(Rule):
    id = "port_scan_detection"
    name = "Port Scan / Active Reconnaissance"
    mitre_id = "T1595"
    severity = "medium"

    def __init__(
        self, event_id: int = WFP_BLOCK_EVENT_ID, distinct_ports_threshold: int = 10,
        window_seconds: int = 30, local_ips: set[str] | None = None,
    ):
        self.event_id = event_id
        self.distinct_ports_threshold = distinct_ports_threshold
        self.window_seconds = window_seconds
        # Overridable for tests; defaults to this machine's real addresses.
        self._local_ips = local_ips if local_ips is not None else local_ip_addresses()
        # remote_ip -> deque[(timestamp, local_port)]
        self._attempts: dict[str, deque] = defaultdict(deque)
        self._last_alert: dict[str, datetime.datetime] = {}

    def evaluate(self, conn, event: dict, row_id: int) -> None:
        if event["event_id"] != self.event_id:
            return

        data = parse_event_data(event["raw_xml"])
        src_addr, src_port = data.get("SourceAddress"), data.get("SourcePort")
        dst_addr, dst_port = data.get("DestAddress"), data.get("DestPort")
        if not src_addr or not dst_addr:
            return

        if src_addr in self._local_ips and dst_addr not in self._local_ips:
            remote_ip, local_port = dst_addr, src_port
        elif dst_addr in self._local_ips and src_addr not in self._local_ips:
            remote_ip, local_port = src_addr, dst_port
        else:
            # Both local, both remote, or neither recognized -- can't
            # confidently tell which side is "us"; skip rather than guess.
            return

        ts = parse_ts(event["ts"])
        window = self._attempts[remote_ip]
        window.append((ts, local_port))
        window_start = ts - datetime.timedelta(seconds=self.window_seconds)
        while window and window[0][0] < window_start:
            window.popleft()

        distinct_ports = {p for _, p in window}
        if len(distinct_ports) < self.distinct_ports_threshold:
            return

        last_alert = self._last_alert.get(remote_ip)
        if last_alert and (ts - last_alert).total_seconds() < self.window_seconds:
            return
        self._last_alert[remote_ip] = ts

        alerts.raise_alert(
            conn,
            rule_id=self.id,
            mitre_id=self.mitre_id,
            severity=self.severity,
            description=(
                f"{len(distinct_ports)} distinct local ports probed by '{remote_ip}' within "
                f"{self.window_seconds}s -- consistent with a port scan"
            ),
            event_id_ref=row_id,
        )
