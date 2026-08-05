import pytest

from siem import storage


@pytest.fixture
def conn():
    c = storage.connect(":memory:")
    storage.init_db(c)
    return c


def test_replace_posture_findings_stores_all_fields(conn):
    findings = [
        {"check_id": "listening_port", "title": "SMB exposed", "severity": "high",
         "description": "port 445 open", "mitre_id": "T1021.002"},
    ]
    storage.replace_posture_findings(conn, findings)
    rows = storage.get_posture_findings(conn)
    assert len(rows) == 1
    assert rows[0]["title"] == "SMB exposed"
    assert rows[0]["mitre_id"] == "T1021.002"


def test_replace_posture_findings_wipes_previous_scan(conn):
    storage.replace_posture_findings(conn, [
        {"check_id": "listening_port", "title": "old finding", "severity": "low", "description": "x", "mitre_id": None},
    ])
    storage.replace_posture_findings(conn, [
        {"check_id": "listening_port", "title": "new finding", "severity": "low", "description": "y", "mitre_id": None},
    ])
    rows = storage.get_posture_findings(conn)
    assert len(rows) == 1
    assert rows[0]["title"] == "new finding"


def test_get_posture_findings_orders_by_severity(conn):
    storage.replace_posture_findings(conn, [
        {"check_id": "c", "title": "low finding", "severity": "low", "description": "x", "mitre_id": None},
        {"check_id": "c", "title": "high finding", "severity": "high", "description": "x", "mitre_id": None},
        {"check_id": "c", "title": "medium finding", "severity": "medium", "description": "x", "mitre_id": None},
    ])
    rows = storage.get_posture_findings(conn)
    assert [r["severity"] for r in rows] == ["high", "medium", "low"]


def test_get_last_posture_scan_ts_returns_none_when_no_scans_yet(conn):
    assert storage.get_last_posture_scan_ts(conn) is None


def test_get_last_posture_scan_ts_returns_the_scan_timestamp(conn):
    storage.replace_posture_findings(conn, [
        {"check_id": "c", "title": "x", "severity": "low", "description": "x", "mitre_id": None},
    ])
    assert storage.get_last_posture_scan_ts(conn) is not None
