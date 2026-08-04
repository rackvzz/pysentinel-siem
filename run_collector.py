#!/usr/bin/env python
"""Entrypoint for the collector process.

Must be run as Administrator to read the Security and Sysmon channels:

    (from an elevated terminal, with the venv active)
    python run_collector.py
"""

import ctypes
import logging
import sys

import yaml

from siem import collector, engine, secrets_loader, storage

# Channels with restrictive ACLs that only Administrators (and SYSTEM) can read.
PRIVILEGED_CHANNELS = {"Security", "Microsoft-Windows-Sysmon/Operational"}


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
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

    conn = storage.connect(config["db_path"])
    storage.init_db(conn)
    engine.configure(config)

    try:
        collector.run_forever(conn, channels, config["poll_interval_seconds"], config=config)
    except KeyboardInterrupt:
        logger.info("Stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
