"""Periodic cleanup so the local SQLite database doesn't grow unbounded.

Raw events are high-volume and low long-term value once they've passed
through the detection engine, so they get a short retention window.
Alerts are the distilled, valuable output of the whole system -- far
fewer rows, worth keeping much longer -- so they default to a much
longer window. Both are configurable in config.yaml's `retention`
section; see siem/maintenance.py for how/when this actually runs.
"""

import datetime
import logging

logger = logging.getLogger("siem.retention")


def _cutoff(days: int) -> str:
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )


def purge(conn, events_retention_days: int, alerts_retention_days: int) -> tuple[int, int]:
    """Delete events/alerts older than their respective retention
    windows, then VACUUM to actually reclaim disk space (SQLite doesn't
    shrink the file on DELETE alone). Returns (events_deleted, alerts_deleted)."""
    events_cutoff = _cutoff(events_retention_days)
    alerts_cutoff = _cutoff(alerts_retention_days)

    cur = conn.execute("DELETE FROM events WHERE ts < ?", (events_cutoff,))
    events_deleted = cur.rowcount
    cur = conn.execute("DELETE FROM alerts WHERE ts < ?", (alerts_cutoff,))
    alerts_deleted = cur.rowcount
    conn.commit()

    if events_deleted or alerts_deleted:
        conn.execute("VACUUM")
        logger.info(
            "Retention: purged %d event(s) older than %dd, %d alert(s) older than %dd; reclaimed space via VACUUM",
            events_deleted, events_retention_days, alerts_deleted, alerts_retention_days,
        )
    return events_deleted, alerts_deleted
