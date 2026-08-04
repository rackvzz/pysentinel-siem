"""Periodic background maintenance: log retention purge + threat intel
feed refresh. Each task tracks its own last-run time in the
maintenance_state table, so `run_periodic_tasks` is cheap to call on
every collector poll cycle (siem/collector.py does) -- the actual work
(DELETE+VACUUM, an HTTP call) only happens when a task's own interval
has actually elapsed.
"""

import datetime
import logging

from . import retention, threat_intel
from .rules.base import parse_ts

logger = logging.getLogger("siem.maintenance")


def _due(conn, task: str, interval_hours: float) -> bool:
    row = conn.execute("SELECT last_run_ts FROM maintenance_state WHERE task = ?", (task,)).fetchone()
    if not row:
        return True
    elapsed_hours = (datetime.datetime.now(datetime.timezone.utc) - parse_ts(row["last_run_ts"])).total_seconds() / 3600
    return elapsed_hours >= interval_hours


def _mark_done(conn, task: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    conn.execute(
        "INSERT INTO maintenance_state (task, last_run_ts) VALUES (?, ?) "
        "ON CONFLICT(task) DO UPDATE SET last_run_ts = excluded.last_run_ts",
        (task, now),
    )
    conn.commit()


def run_periodic_tasks(conn, config: dict) -> None:
    r = config.get("retention", {})
    if r.get("enabled", True) and _due(conn, "retention", r.get("check_interval_hours", 24)):
        retention.purge(conn, r.get("events_retention_days", 30), r.get("alerts_retention_days", 365))
        _mark_done(conn, "retention")

    ti = config.get("threat_intel", {})
    if ti.get("enabled", False) and _due(conn, "threat_intel", ti.get("refresh_interval_hours", 24)):
        threat_intel.refresh(conn, api_key=ti.get("api_key"), days=ti.get("lookback_days", 3))
        _mark_done(conn, "threat_intel")
