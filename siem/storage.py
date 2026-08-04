"""SQLite storage layer for pysentinel-siem.

Two tables:
  - events: every normalized event the collector has seen.
  - alerts: every detection-rule match, referencing the triggering event.

Plus:
  - channel_state: per Windows Event Log channel, the timestamp of the
    last event collected -- the "watermark" the collector uses to avoid
    re-processing old events on restart (see siem/collector.py).
  - maintenance_state: per background task (retention purge, threat
    intel refresh), when it last ran -- see siem/maintenance.py.
  - threat_intel_iocs: the locally-cached feed of known-malicious
    IPs/domains/hashes -- see siem/threat_intel.py and
    siem/rules/threat_intel_match.py.

The collector process is the sole writer; the dashboard only reads.
"""

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    level TEXT,
    computer TEXT,
    user TEXT,
    source_ip TEXT,
    message TEXT,
    raw_xml TEXT NOT NULL,
    UNIQUE(channel, record_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    mitre_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    event_id_ref INTEGER,
    FOREIGN KEY (event_id_ref) REFERENCES events (id)
);

CREATE TABLE IF NOT EXISTS channel_state (
    channel TEXT PRIMARY KEY,
    last_ts TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS maintenance_state (
    task TEXT PRIMARY KEY,
    last_run_ts TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    malware TEXT,
    first_seen TEXT,
    PRIMARY KEY (ioc_type, value)
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events (event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def get_last_ts(conn: sqlite3.Connection, channel: str):
    row = conn.execute(
        "SELECT last_ts FROM channel_state WHERE channel = ?", (channel,)
    ).fetchone()
    return row["last_ts"] if row else None


def set_last_ts(conn: sqlite3.Connection, channel: str, ts: str) -> None:
    conn.execute(
        "INSERT INTO channel_state (channel, last_ts) VALUES (?, ?) "
        "ON CONFLICT(channel) DO UPDATE SET last_ts = excluded.last_ts",
        (channel, ts),
    )
    conn.commit()


def insert_event(conn: sqlite3.Connection, event: dict):
    """Insert a normalized event. Returns the new row id, or None if this
    (channel, record_id) pair was already stored -- the UNIQUE constraint
    makes re-collection at the watermark boundary a safe no-op rather than
    a duplicate row."""
    try:
        cur = conn.execute(
            "INSERT INTO events "
            "(channel, record_id, ts, event_id, level, computer, user, source_ip, message, raw_xml) "
            "VALUES (:channel, :record_id, :ts, :event_id, :level, :computer, :user, :source_ip, :message, :raw_xml)",
            event,
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def insert_alert(conn: sqlite3.Connection, alert: dict) -> int:
    cur = conn.execute(
        "INSERT INTO alerts (ts, rule_id, mitre_id, severity, description, event_id_ref) "
        "VALUES (:ts, :rule_id, :mitre_id, :severity, :description, :event_id_ref)",
        alert,
    )
    conn.commit()
    return cur.lastrowid


def get_recent_events(conn: sqlite3.Connection, limit: int = 100):
    return conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()


def get_recent_alerts(conn: sqlite3.Connection, limit: int = 100):
    return conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()


def get_events_by_event_id_since(conn: sqlite3.Connection, event_id: int, since_ts: str):
    return conn.execute(
        "SELECT * FROM events WHERE event_id = ? AND ts >= ? ORDER BY ts ASC",
        (event_id, since_ts),
    ).fetchall()


def get_event_counts_by_id(conn: sqlite3.Connection, limit: int = 10):
    return conn.execute(
        "SELECT event_id, COUNT(*) AS n FROM events GROUP BY event_id ORDER BY n DESC LIMIT ?",
        (limit,),
    ).fetchall()


def get_events_over_time(conn: sqlite3.Connection, buckets: int = 24):
    """Hourly event counts for the last `buckets` hours, for the dashboard chart."""
    return conn.execute(
        "SELECT strftime('%Y-%m-%dT%H:00:00', ts) AS bucket, COUNT(*) AS n "
        "FROM events "
        "WHERE ts >= strftime('%Y-%m-%dT%H:%M:%S', 'now', ?) "
        "GROUP BY bucket ORDER BY bucket ASC",
        (f"-{buckets} hours",),
    ).fetchall()
