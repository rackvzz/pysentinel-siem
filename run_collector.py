#!/usr/bin/env python
"""Entrypoint for the collector process.

Must be run as Administrator to read the Security and Sysmon channels:

    (from an elevated terminal, with the venv active)
    python run_collector.py
"""

import ctypes
import logging
import os
import sys

import defusedxml
import yaml

from siem import alerts, audit_policy, collector, correlation, engine, logging_setup, secrets_loader, storage

# Hardens the stdlib's xml.etree.ElementTree process-wide (rejects DOCTYPE
# declarations, closing off both XXE and entity-expansion/"billion laughs"
# attacks) without touching any of siem/normalize.py's actual ET.fromstring
# call sites. Event XML normally comes from the local Windows Event Log
# (not attacker-controlled network input), but this is cheap, standard
# defense-in-depth for a security tool that parses XML at all -- called
# once, here, before any event XML is ever parsed.
defusedxml.defuse_stdlib()

# Channels with restrictive ACLs that only Administrators (and SYSTEM) can read.
PRIVILEGED_CHANNELS = {"Security", "Microsoft-Windows-Sysmon/Operational"}


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main() -> int:
    logging_setup.configure_logging(os.path.dirname(os.path.abspath(__file__)))
    logger = logging.getLogger("run_collector")

    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    secrets = secrets_loader.load(".")
    config.setdefault("threat_intel", {})["api_key"] = secrets.get("threatfox_api_key")

    channels = config["channels"]
    privileged = PRIVILEGED_CHANNELS.intersection(channels)
    if privileged and not _is_admin():
        logger.error(
            "Config watches %s, which require(s) admin rights. "
            "Re-run this script from an elevated (Run as Administrator) terminal.",
            ", ".join(sorted(privileged)),
        )
        return 1

    if config.get("detections", {}).get("port_scan_detection", {}).get("enabled", True):
        audit_policy.ensure_failure_auditing_enabled()
    if config.get("detections", {}).get("persistence", {}).get("enabled", True):
        audit_policy.ensure_object_access_auditing_enabled()

    conn = storage.connect(config["db_path"])
    storage.init_db(conn)
    engine.configure(config)
    alerts.configure(config)
    correlation.configure(config)

    try:
        collector.run_forever(conn, channels, config["poll_interval_seconds"], config=config)
    except KeyboardInterrupt:
        logger.info("Stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
