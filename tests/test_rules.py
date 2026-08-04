import pytest

from siem import storage
from siem.rules.afterhours_logon import AfterHoursLogonRule
from siem.rules.brute_force import BruteForceRule
from siem.rules.new_admin_account import NewAdminAccountRule


@pytest.fixture
def conn():
    c = storage.connect(":memory:")
    storage.init_db(c)
    return c


def make_event(event_id, ts, user="alice", source_ip="10.0.0.5", computer="HOST", raw_xml=""):
    return {
        "channel": "Security",
        "record_id": 1,
        "ts": ts,
        "event_id": event_id,
        "level": "Information",
        "computer": computer,
        "user": user,
        "source_ip": source_ip,
        "message": "",
        "raw_xml": raw_xml,
    }


def event_data_xml(**fields):
    data = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in fields.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System></System>"
        f"<EventData>{data}</EventData>"
        "</Event>"
    )


class TestBruteForceRule:
    def test_fires_after_threshold_reached(self, conn):
        rule = BruteForceRule(event_id=4625, threshold=3, window_seconds=60)
        base_ts = "2026-08-04T12:00:0{}.000Z"

        for i in range(2):
            rule.evaluate(conn, make_event(4625, base_ts.format(i)), row_id=i)
        assert len(storage.get_recent_alerts(conn)) == 0  # below threshold

        rule.evaluate(conn, make_event(4625, base_ts.format(2)), row_id=2)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "brute_force"
        assert alerts[0]["mitre_id"] == "T1110"

    def test_does_not_double_alert_within_same_burst(self, conn):
        rule = BruteForceRule(event_id=4625, threshold=2, window_seconds=60)
        base_ts = "2026-08-04T12:00:0{}.000Z"
        for i in range(4):
            rule.evaluate(conn, make_event(4625, base_ts.format(i)), row_id=i)
        # threshold of 2 reached at i=1, i=2, i=3 -- should only alert once
        assert len(storage.get_recent_alerts(conn)) == 1

    def test_ignores_unrelated_event_ids(self, conn):
        rule = BruteForceRule(event_id=4625, threshold=1, window_seconds=60)
        rule.evaluate(conn, make_event(4624, "2026-08-04T12:00:00.000Z"), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_separate_sources_tracked_independently(self, conn):
        rule = BruteForceRule(event_id=4625, threshold=2, window_seconds=60)
        rule.evaluate(conn, make_event(4625, "2026-08-04T12:00:00.000Z", source_ip="1.1.1.1"), row_id=1)
        rule.evaluate(conn, make_event(4625, "2026-08-04T12:00:01.000Z", source_ip="2.2.2.2"), row_id=2)
        # each source only has 1 attempt -- neither should fire yet
        assert len(storage.get_recent_alerts(conn)) == 0


class TestNewAdminAccountRule:
    def test_new_account_creation_fires(self, conn):
        rule = NewAdminAccountRule()
        rule.evaluate(conn, make_event(4720, "2026-08-04T12:00:00.000Z", user="bob"), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1136"
        assert "bob" in alerts[0]["description"]

    def test_admin_group_addition_fires(self, conn):
        rule = NewAdminAccountRule()
        raw_xml = event_data_xml(TargetUserName="Administrators", MemberName="evil_intern")
        rule.evaluate(conn, make_event(4732, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1098"
        assert "evil_intern" in alerts[0]["description"]

    def test_non_admin_group_addition_does_not_fire(self, conn):
        rule = NewAdminAccountRule()
        raw_xml = event_data_xml(TargetUserName="Remote Desktop Users", MemberName="bob")
        rule.evaluate(conn, make_event(4732, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0


class TestAfterHoursLogonRule:
    def test_fires_outside_business_hours(self, conn):
        rule = AfterHoursLogonRule(business_hours_start=7, business_hours_end=19)
        raw_xml = event_data_xml(LogonType="2")
        rule.evaluate(conn, make_event(4624, "2026-08-04T03:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 1
        assert storage.get_recent_alerts(conn)[0]["mitre_id"] == "T1078"

    def test_ignores_non_human_logon_types(self, conn):
        rule = AfterHoursLogonRule(business_hours_start=7, business_hours_end=19)
        raw_xml = event_data_xml(LogonType="5")  # Service logon
        rule.evaluate(conn, make_event(4624, "2026-08-04T03:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0
