"""Periodic threat intelligence feed refresh.

Pulls recently-reported IOCs (IPs/domains/hashes tied to tracked
malware campaigns) from abuse.ch's ThreatFox API into the local
threat_intel_iocs table, so siem/rules/threat_intel_match.py can check
observed IPs against them with a plain local SQLite lookup instead of a
network call on every single event.

Requires a free Auth-Key -- sign in at https://auth.abuse.ch/ with an
existing Google/GitHub/LinkedIn/X account, then copy it into
secrets.yaml (see secrets.yaml.example). Without a key, refresh() logs
a warning and no-ops rather than failing the whole collector.
"""

import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger("siem.threat_intel")

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_recent_iocs(api_key: str, days: int = 3) -> list[tuple[str, str, str, str]]:
    """Fetch IOCs reported in the last `days` days (ThreatFox caps this
    at 7). Returns a list of (ioc_type, value, source, malware) tuples,
    where ioc_type is one of "ip" / "domain" / "hash"."""
    body = json.dumps({"query": "get_iocs", "days": min(days, 7)}).encode("utf-8")
    req = urllib.request.Request(
        THREATFOX_API_URL, data=body,
        headers={"Content-Type": "application/json", "Auth-Key": api_key},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.load(resp)

    if payload.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox returned query_status={payload.get('query_status')!r}")

    iocs = []
    for item in payload.get("data", []):
        ioc_value = item.get("ioc")
        ioc_type_raw = item.get("ioc_type", "")
        malware = item.get("malware_printable") or item.get("malware")
        if not ioc_value:
            continue
        if ioc_type_raw.startswith("ip"):  # ThreatFox reports these as "ip:port"
            ip = ioc_value.split(":")[0]
            iocs.append(("ip", ip, "abuse.ch ThreatFox", malware))
        elif ioc_type_raw == "domain":
            iocs.append(("domain", ioc_value, "abuse.ch ThreatFox", malware))
        elif ioc_type_raw in ("md5_hash", "sha1_hash", "sha256_hash"):
            iocs.append(("hash", ioc_value, "abuse.ch ThreatFox", malware))
    return iocs


def refresh(conn, api_key: str | None, days: int = 3) -> int:
    """Fetch the latest IOCs and upsert them into threat_intel_iocs.
    Returns the number of IOCs fetched (0 if disabled/failed -- this
    never raises, so a feed hiccup doesn't take down the collector)."""
    if not api_key:
        logger.warning(
            "threat_intel is enabled but no API key is configured -- "
            "copy secrets.yaml.example to secrets.yaml and fill in threatfox_api_key. Skipping refresh."
        )
        return 0

    try:
        iocs = fetch_recent_iocs(api_key, days)
    except (urllib.error.URLError, RuntimeError, ValueError, TimeoutError):
        logger.exception("Failed to refresh threat intel feed")
        return 0

    for ioc_type, value, source, malware in iocs:
        conn.execute(
            "INSERT INTO threat_intel_iocs (ioc_type, value, source, malware, first_seen) "
            "VALUES (?, ?, ?, ?, datetime('now')) "
            "ON CONFLICT(ioc_type, value) DO UPDATE SET malware = excluded.malware, source = excluded.source",
            (ioc_type, value, source, malware),
        )
    conn.commit()
    logger.info("Threat intel: refreshed %d IOC(s) from ThreatFox", len(iocs))
    return len(iocs)
