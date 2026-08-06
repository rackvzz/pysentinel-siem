"""Polls configured Windows Event Log channels for new events, normalizes
them, and hands each one to the detection engine + storage.

Uses the Vista-era Windows Event Log API (`win32evtlog.Evt*` functions)
rather than the classic `ReadEventLog` API. Two reasons:
  1. It works on both classic channels (Security, System) and the
     provider-specific channels used by Sysmon -- so the Phase 4 Sysmon
     integration is just adding a channel name to config.yaml, no new
     collection code.
  2. It supports XPath filtering server-side, which is what we use for
     resuming from where we left off (see `_since_query` below).

Resuming across restarts: for each channel we track a "watermark"
timestamp in the `channel_state` table (the SystemTime of the newest
event we've stored) and query with `TimeCreated > watermark` on the next
poll. This is simpler than a true EvtBookmark and is safe here because
`storage.insert_event` treats (channel, record_id) as a dedupe key -- an
event landing exactly on the watermark boundary is a harmless no-op
insert, not a duplicate row.
"""

import datetime
import logging
import time

import win32evtlog
import pywintypes

from . import normalize, storage

logger = logging.getLogger("siem.collector")

# How far back to look on a channel's very first poll (no watermark yet).
INITIAL_LOOKBACK = datetime.timedelta(hours=1)


def _iso(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _since_query(since_ts: str) -> str:
    return f"*[System[TimeCreated[@SystemTime>'{since_ts}']]]"


def _fetch_new_events(channel: str, since_ts: str):
    """Query `channel` for events newer than `since_ts`, oldest first.
    Returns a list of raw XML strings."""
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
    handle = win32evtlog.EvtQuery(channel, flags, _since_query(since_ts))

    xml_events = []
    while True:
        try:
            batch = win32evtlog.EvtNext(handle, 50)
        except pywintypes.error as exc:
            # ERROR_NO_MORE_ITEMS surfaces as a win32 error here.
            if exc.winerror == 259:
                break
            raise
        if not batch:
            break
        for evt in batch:
            xml_events.append(win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml))
    return xml_events


def poll_once(conn, channels: list[str]) -> int:
    """Poll every configured channel once. Returns the number of new
    events stored."""
    stored = 0
    for channel in channels:
        since_ts = storage.get_last_ts(conn, channel)
        if since_ts is None:
            since_ts = _iso(datetime.datetime.now(datetime.timezone.utc) - INITIAL_LOOKBACK)

        try:
            raw_events = _fetch_new_events(channel, since_ts)
        except pywintypes.error as exc:
            if exc.winerror == 5:
                logger.error(
                    "Access denied reading channel '%s' -- run_collector.py must be run "
                    "as Administrator to read this channel.",
                    channel,
                )
                continue
            logger.error("Error querying channel '%s': %s", channel, exc)
            continue

        newest_ts = since_ts
        for raw_xml in raw_events:
            event = normalize.normalize_event(raw_xml, channel)
            row_id = storage.insert_event(conn, event)
            if row_id is not None:
                stored += 1
                from . import engine  # local import: avoids a circular import at module load

                engine.evaluate_event(conn, event, row_id)
            if event["ts"] and event["ts"] > newest_ts:
                newest_ts = event["ts"]

        if newest_ts != since_ts:
            storage.set_last_ts(conn, channel, newest_ts)

    return stored


def run_forever(conn, channels: list[str], poll_interval_seconds: int, config: dict | None = None) -> None:
    """`config`, if given, enables periodic background maintenance
    (retention purge + threat intel feed refresh -- see
    siem/maintenance.py) once per poll cycle. It's optional and
    defaults to off so tests/callers that don't care about maintenance
    don't need to pass a full config dict.

    Per-channel query errors and per-rule exceptions are already caught
    lower down (poll_once, engine.evaluate_event) -- this loop is the
    backstop for everything else (a maintenance task blowing up, a DB
    hiccup, anything unanticipated). Without it, one unhandled exception
    here would silently kill detection entirely: the process is gone, but
    nothing in the UI says so. Logging + continuing means the collector
    stays up through a transient failure; five in a row backs off harder
    instead of spinning a tight, log-spamming crash loop."""
    logger.info("Collector started. Watching channels: %s", ", ".join(channels))
    consecutive_failures = 0
    while True:
        try:
            n = poll_once(conn, channels)
            if n:
                logger.info("Collected %d new event(s).", n)
            if config is not None:
                from . import maintenance  # local import: avoids a circular import at module load

                maintenance.run_periodic_tasks(conn, config)
            consecutive_failures = 0
        except Exception:
            consecutive_failures += 1
            logger.exception(
                "Unexpected error in the collector loop (failure #%d) -- logging it and "
                "continuing rather than letting detection go dark.",
                consecutive_failures,
            )
            if consecutive_failures >= 5:
                time.sleep(min(poll_interval_seconds * consecutive_failures, 300))
                continue
        time.sleep(poll_interval_seconds)
