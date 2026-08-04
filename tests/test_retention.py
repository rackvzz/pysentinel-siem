import datetime

import pytest

from siem import retention, storage


@pytest.fixture
def conn():
    c = storage.connect(":memory:")
    storage.init_db(c)
    return c


def _ts(days_ago: int) -> str:
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _insert_event(conn, days_ago: int, record_id: int) -> None:
    storage.insert_event(conn, {
        "channel": "System", "record_id": record_id, "ts": _ts(days_ago), "event_id": 1,
        "level": "Information", "computer": "HOST", "user": "", "source_ip": "",
        "message": "test", "raw_xml": "<Event/>",
    })


def _insert_alert(conn, days_ago: int, rule_id: str) -> None:
    storage.insert_alert(conn, {
        "ts": _ts(days_ago), "rule_id": rule_id, "mitre_id": "T0000", "severity": "low",
        "description": "test", "event_id_ref": None,
    })


def test_purge_deletes_old_events_keeps_recent(conn):
    _insert_event(conn, days_ago=40, record_id=1)
    _insert_event(conn, days_ago=5, record_id=2)

    events_deleted, _ = retention.purge(conn, events_retention_days=30, alerts_retention_days=365)

    assert events_deleted == 1
    remaining = storage.get_recent_events(conn, 10)
    assert len(remaining) == 1
    assert remaining[0]["record_id"] == 2


def test_purge_deletes_old_alerts_keeps_recent(conn):
    _insert_alert(conn, days_ago=400, rule_id="old_rule")
    _insert_alert(conn, days_ago=10, rule_id="recent_rule")

    _, alerts_deleted = retention.purge(conn, events_retention_days=30, alerts_retention_days=365)

    assert alerts_deleted == 1
    remaining = storage.get_recent_alerts(conn, 10)
    assert len(remaining) == 1
    assert remaining[0]["rule_id"] == "recent_rule"


def test_purge_is_noop_when_nothing_is_old(conn):
    _insert_event(conn, days_ago=1, record_id=1)
    _insert_alert(conn, days_ago=1, rule_id="recent_rule")

    events_deleted, alerts_deleted = retention.purge(conn, events_retention_days=30, alerts_retention_days=365)

    assert (events_deleted, alerts_deleted) == (0, 0)
    assert len(storage.get_recent_events(conn, 10)) == 1
    assert len(storage.get_recent_alerts(conn, 10)) == 1
