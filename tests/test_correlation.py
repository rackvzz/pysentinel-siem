import pytest

from siem import alerts, correlation, notifier, storage


@pytest.fixture
def conn():
    c = storage.connect(":memory:")
    storage.init_db(c)
    return c


@pytest.fixture(autouse=True)
def _reset_correlation_config():
    correlation.configure({})  # defaults: enabled, 15-minute window, 2 signals
    yield
    correlation.configure({})


def _make_event(conn, ts, user=None, source_ip=None, record_id=1):
    event = {
        "channel": "Security", "record_id": record_id, "ts": ts, "event_id": 4624,
        "level": "Information", "computer": "HOST", "user": user or "", "source_ip": source_ip or "",
        "message": "", "raw_xml": "<Event/>",
    }
    return storage.insert_event(conn, event)


def test_no_correlation_below_min_signals(conn):
    event_id = _make_event(conn, "2026-08-05T12:00:00.000Z", user="alice")
    alerts.raise_alert(conn, "afterhours_logon", "T1078", "low", "desc", event_id)
    correlated = [a for a in storage.get_recent_alerts(conn) if a["rule_id"] == "correlated"]
    assert correlated == []


def test_correlation_fires_at_threshold(conn):
    e1 = _make_event(conn, "2026-08-05T12:00:00.000Z", user="alice", record_id=1)
    e2 = _make_event(conn, "2026-08-05T12:05:00.000Z", user="alice", record_id=2)
    alerts.raise_alert(conn, "afterhours_logon", "T1078", "low", "desc", e1)
    alerts.raise_alert(conn, "new_admin_account", "T1136", "medium", "desc", e2)

    correlated = [a for a in storage.get_recent_alerts(conn) if a["rule_id"] == "correlated"]
    assert len(correlated) == 1
    assert correlated[0]["severity"] == "high"
    assert "alice" in correlated[0]["description"]
    assert "afterhours_logon" in correlated[0]["description"]
    assert "new_admin_account" in correlated[0]["description"]


def test_correlation_matches_by_source_ip_too(conn):
    e1 = _make_event(conn, "2026-08-05T12:00:00.000Z", source_ip="203.0.113.9", record_id=1)
    e2 = _make_event(conn, "2026-08-05T12:02:00.000Z", source_ip="203.0.113.9", record_id=2)
    alerts.raise_alert(conn, "brute_force", "T1110", "high", "desc", e1)
    alerts.raise_alert(conn, "threat_intel_match", "TA0011", "high", "desc", e2)

    correlated = [a for a in storage.get_recent_alerts(conn) if a["rule_id"] == "correlated"]
    assert len(correlated) == 1
    assert "203.0.113.9" in correlated[0]["description"]


def test_no_correlation_across_different_actors(conn):
    e1 = _make_event(conn, "2026-08-05T12:00:00.000Z", user="alice", record_id=1)
    e2 = _make_event(conn, "2026-08-05T12:01:00.000Z", user="bob", record_id=2)
    alerts.raise_alert(conn, "afterhours_logon", "T1078", "low", "desc", e1)
    alerts.raise_alert(conn, "new_admin_account", "T1136", "medium", "desc", e2)

    correlated = [a for a in storage.get_recent_alerts(conn) if a["rule_id"] == "correlated"]
    assert correlated == []


def test_no_correlation_outside_window(conn):
    # alerts.raise_alert always timestamps at wall-clock "now" (detection
    # time, not the originating event's time), so exercising the window
    # boundary needs explicit control over both alerts' ts -- done here by
    # calling storage.insert_alert + correlation.check directly rather
    # than going through raise_alert's real-time timestamp generation.
    correlation.configure({"correlation": {"window_minutes": 5}})
    e1 = _make_event(conn, "2026-08-05T12:00:00.000Z", user="alice", record_id=1)
    e2 = _make_event(conn, "2026-08-05T12:10:00.000Z", user="alice", record_id=2)  # 10 min later
    storage.insert_alert(conn, {
        "ts": "2026-08-05T12:00:00.000Z", "rule_id": "afterhours_logon", "mitre_id": "T1078",
        "severity": "low", "description": "desc", "event_id_ref": e1,
    })
    storage.insert_alert(conn, {
        "ts": "2026-08-05T12:10:00.000Z", "rule_id": "new_admin_account", "mitre_id": "T1136",
        "severity": "medium", "description": "desc", "event_id_ref": e2,
    })
    correlation.check(conn, e2, "2026-08-05T12:10:00.000Z")

    correlated = [a for a in storage.get_recent_alerts(conn) if a["rule_id"] == "correlated"]
    assert correlated == []


def test_does_not_double_fire_within_same_burst(conn):
    e1 = _make_event(conn, "2026-08-05T12:00:00.000Z", user="alice", record_id=1)
    e2 = _make_event(conn, "2026-08-05T12:01:00.000Z", user="alice", record_id=2)
    e3 = _make_event(conn, "2026-08-05T12:02:00.000Z", user="alice", record_id=3)
    alerts.raise_alert(conn, "afterhours_logon", "T1078", "low", "desc", e1)
    alerts.raise_alert(conn, "new_admin_account", "T1136", "medium", "desc", e2)
    alerts.raise_alert(conn, "brute_force", "T1110", "high", "desc", e3)

    correlated = [a for a in storage.get_recent_alerts(conn) if a["rule_id"] == "correlated"]
    assert len(correlated) == 1  # not 2


def test_correlation_disabled_via_config(conn):
    correlation.configure({"correlation": {"enabled": False}})
    e1 = _make_event(conn, "2026-08-05T12:00:00.000Z", user="alice", record_id=1)
    e2 = _make_event(conn, "2026-08-05T12:01:00.000Z", user="alice", record_id=2)
    alerts.raise_alert(conn, "afterhours_logon", "T1078", "low", "desc", e1)
    alerts.raise_alert(conn, "new_admin_account", "T1136", "medium", "desc", e2)

    correlated = [a for a in storage.get_recent_alerts(conn) if a["rule_id"] == "correlated"]
    assert correlated == []


def test_correlated_alert_triggers_notification(conn, monkeypatch):
    calls = []
    monkeypatch.setattr(notifier, "notify_alert", lambda rule_id, severity, description: calls.append(rule_id))
    alerts.configure({"notifications": {"enabled": True, "min_severity": "high"}})

    e1 = _make_event(conn, "2026-08-05T12:00:00.000Z", user="alice", record_id=1)
    e2 = _make_event(conn, "2026-08-05T12:01:00.000Z", user="alice", record_id=2)
    alerts.raise_alert(conn, "afterhours_logon", "T1078", "low", "desc", e1)
    alerts.raise_alert(conn, "new_admin_account", "T1136", "medium", "desc", e2)

    assert "correlated" in calls
    alerts.configure({})  # restore defaults
