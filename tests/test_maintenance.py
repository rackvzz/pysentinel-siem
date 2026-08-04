import datetime

import pytest

from siem import maintenance, storage


@pytest.fixture
def conn():
    c = storage.connect(":memory:")
    storage.init_db(c)
    return c


def test_due_is_true_when_never_run(conn):
    assert maintenance._due(conn, "retention", interval_hours=24) is True


def test_due_is_false_right_after_marking_done(conn):
    maintenance._mark_done(conn, "retention")
    assert maintenance._due(conn, "retention", interval_hours=24) is False


def test_due_is_true_once_interval_has_elapsed(conn):
    stale = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=25)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )
    conn.execute(
        "INSERT INTO maintenance_state (task, last_run_ts) VALUES (?, ?)", ("retention", stale)
    )
    conn.commit()
    assert maintenance._due(conn, "retention", interval_hours=24) is True


def test_run_periodic_tasks_runs_retention_when_enabled_and_due(conn):
    config = {"retention": {"enabled": True, "check_interval_hours": 24}, "threat_intel": {"enabled": False}}
    maintenance.run_periodic_tasks(conn, config)
    # retention ran -> marked done -> immediately not due again
    assert maintenance._due(conn, "retention", interval_hours=24) is False


def test_run_periodic_tasks_skips_disabled_threat_intel(conn):
    config = {"retention": {"enabled": False}, "threat_intel": {"enabled": False}}
    maintenance.run_periodic_tasks(conn, config)
    # neither task should have run/marked done
    assert maintenance._due(conn, "retention", interval_hours=24) is True
    assert maintenance._due(conn, "threat_intel", interval_hours=24) is True
