"""Attack-surface scanning: point-in-time checks of *current system
state* (as opposed to the rule engine, which reacts to *streaming
events*). "Findings" from a scan describe standing conditions ("port
445 is listening on all interfaces") rather than something that just
happened -- each scan replaces the previous one's findings rather than
accumulating a history the way events/alerts do (see
storage.replace_posture_findings).

v1 covers one check: listening TCP ports, flagged by how exposed they
are (bound to 0.0.0.0/all interfaces vs. 127.0.0.1/localhost-only) and
whether the port is a well-known lateral-movement/exploitation target.
"""

import datetime
import logging
import subprocess

logger = logging.getLogger("siem.posture")

# port -> (service name, MITRE ATT&CK technique if there's a clean fit, or None)
RISKY_PORTS = {
    21: ("FTP", None),
    23: ("Telnet", None),
    135: ("RPC/DCOM", None),
    139: ("NetBIOS", "T1021.002"),
    445: ("SMB", "T1021.002"),
    1433: ("MSSQL", None),
    3306: ("MySQL", None),
    3389: ("RDP", "T1021.001"),
    5432: ("PostgreSQL", None),
    5900: ("VNC", "T1021.005"),
}


def _parse_netstat_listening(output: str) -> list[dict]:
    """Parses `netstat -ano` text output, returning one dict per LISTENING
    TCP entry: {local_addr, port, pid}. Split out from scan_listening_ports
    so it's testable against a fixed text sample without needing the real
    command."""
    findings = []
    for line in output.splitlines():
        parts = line.split()
        # Proto, Local Address, Foreign Address, State, PID -- 5 columns.
        if len(parts) != 5 or parts[0] != "TCP" or parts[3] != "LISTENING":
            continue
        local = parts[1]
        if ":" not in local:
            continue
        addr, _, port_str = local.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            continue
        findings.append({"local_addr": addr, "port": port})
    return findings


def _run_netstat() -> str:
    result = subprocess.run(
        ["netstat", "-ano"], capture_output=True, text=True, timeout=15,
    )
    return result.stdout


LOCALHOST_ADDRS = {"127.0.0.1", "::1"}


def scan_listening_ports() -> list[dict]:
    """Returns a list of finding dicts: {check_id, title, severity,
    description, mitre_id}."""
    try:
        raw = _run_netstat()
    except (OSError, subprocess.TimeoutExpired):
        logger.warning("Could not run netstat for the port-exposure scan.")
        return []

    listening = _parse_netstat_listening(raw)

    # Group by port number rather than (addr, port): Windows commonly
    # dual-stacks the same service across IPv4 (0.0.0.0) and IPv6 ([::])
    # simultaneously, which would otherwise produce two near-identical
    # findings for what's really one exposure. A port counts as exposed
    # if *any* of its listening addresses is non-localhost.
    addrs_by_port: dict[int, set] = {}
    for entry in listening:
        addrs_by_port.setdefault(entry["port"], set()).add(entry["local_addr"])

    findings = []
    for port, addrs in sorted(addrs_by_port.items()):
        exposed = any(a not in LOCALHOST_ADDRS for a in addrs)
        addr = next((a for a in addrs if a not in LOCALHOST_ADDRS), next(iter(addrs)))
        risky = RISKY_PORTS.get(port)

        if risky and exposed:
            service, mitre_id = risky
            findings.append({
                "check_id": "listening_port",
                "title": f"{service} (port {port}) exposed on all interfaces",
                "severity": "high",
                "description": (
                    f"Port {port} ({service}) is listening on {addr} (all interfaces), reachable from "
                    f"other machines on the network, not just this one."
                ),
                "mitre_id": mitre_id,
            })
        elif risky and not exposed:
            service, mitre_id = risky
            findings.append({
                "check_id": "listening_port",
                "title": f"{service} (port {port}) listening (localhost-only)",
                "severity": "low",
                "description": (
                    f"Port {port} ({service}) is listening but only on {addr} (localhost) -- "
                    f"not reachable from other machines on the network."
                ),
                "mitre_id": mitre_id,
            })
        elif exposed and port >= 1024:
            # Anything else exposed on all interfaces is lower-priority
            # noise (lots of legitimate apps do this), but still worth a
            # quiet visibility entry rather than silently dropping it.
            findings.append({
                "check_id": "listening_port",
                "title": f"Port {port} exposed on all interfaces",
                "severity": "low",
                "description": f"Port {port} is listening on {addr} (all interfaces).",
                "mitre_id": None,
            })

    return findings


def run_scan() -> list[dict]:
    """The single entrypoint other modules call -- currently just the
    port scan, but the natural place to fold in more checks later."""
    return scan_listening_ports()
