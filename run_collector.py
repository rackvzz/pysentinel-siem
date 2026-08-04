#!/usr/bin/env python
"""Entrypoint for the collector process.

Must be run as Administrator to read the Security channel:

    (from an elevated terminal, with the venv active)
    python run_collector.py
"""

import ctypes
import logging
import sys

import yaml

from siem import collector, storage


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

    channels = config["channels"]
    needs_admin = "Security" in channels
    if needs_admin and not _is_admin():
        logger.error(
            "Config watches the 'Security' channel, which requires admin rights. "
            "Re-run this script from an elevated (Run as Administrator) terminal."
        )
        return 1

    conn = storage.connect(config["db_path"])
    storage.init_db(conn)

    try:
        collector.run_forever(conn, channels, config["poll_interval_seconds"])
    except KeyboardInterrupt:
        logger.info("Stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
