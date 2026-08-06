import tempfile
import os

import pytest

from dashboard import app as dashboard_app_module
from siem import storage


@pytest.fixture
def client(monkeypatch):
    """A real Flask test client wired to a throwaway file-based DB (not
    :memory: -- the dashboard opens a fresh connection per request via
    storage.connect(db_path), and each :memory: connection is its own
    blank database, so a real temp file is needed for state to persist
    across requests within one test)."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    storage.init_db(storage.connect(path))

    monkeypatch.setattr(dashboard_app_module, "load_config", lambda: {"db_path": path})
    app = dashboard_app_module.create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c

    # WAL mode (storage.connect enables it) leaves -wal/-shm sidecar files
    # alongside the main db file; best-effort cleanup of all three.
    for p in (path, f"{path}-wal", f"{path}-shm"):
        try:
            os.remove(p)
        except OSError:
            pass


def test_get_routes_need_no_origin_header(client):
    # Read-only routes were never guarded and shouldn't require one.
    assert client.get("/api/stats").status_code == 200
    assert client.get("/api/blocked-ips").status_code == 200


def test_security_headers_present_on_every_response(client):
    resp = client.get("/api/stats")
    assert resp.headers["Server"] == "pysentinel-siem"
    assert "Werkzeug" not in resp.headers["Server"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_api_events_never_leaks_raw_xml(client):
    # raw_xml can contain a full command line or PowerShell script block --
    # never intended to leave the machine even to localhost. Regression
    # test for EVENT_API_FIELDS' allowlist.
    conn = storage.connect(dashboard_app_module.load_config()["db_path"])
    storage.insert_event(conn, {
        "channel": "Security", "record_id": 1, "ts": "2026-08-05T12:00:00.000Z", "event_id": 4624,
        "level": "Information", "computer": "HOST", "user": "alice", "source_ip": "10.0.0.5",
        "message": "Successful logon", "raw_xml": "<Event>SENTINEL_SECRET_MARKER</Event>",
    })
    conn.close()
    resp = client.get("/api/events")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "SENTINEL_SECRET_MARKER" not in body
    assert "raw_xml" not in body
    row = resp.get_json()[0]
    assert row["message"] == "Successful logon"  # confirms real data still came through


def test_api_alerts_never_leaks_event_id_ref(client):
    conn = storage.connect(dashboard_app_module.load_config()["db_path"])
    event_id = storage.insert_event(conn, {
        "channel": "Security", "record_id": 2, "ts": "2026-08-05T12:00:00.000Z", "event_id": 4625,
        "level": "Information", "computer": "HOST", "user": "alice", "source_ip": "10.0.0.5",
        "message": "Failed logon", "raw_xml": "<Event/>",
    })
    storage.insert_alert(conn, {
        "ts": "2026-08-05T12:00:01.000Z", "rule_id": "brute_force", "mitre_id": "T1110",
        "severity": "high", "description": "test alert", "event_id_ref": event_id,
    })
    conn.close()
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    row = resp.get_json()[0]
    assert "event_id_ref" not in row
    assert row["rule_id"] == "brute_force"


def test_block_ip_post_without_origin_or_referer_is_rejected(client):
    # Simulates a forged request (e.g. a plain cross-site <form> POST,
    # which browsers never attach Origin/Referer-matching headers to in a
    # way an attacker controls) -- must not reach response.block_ip at all.
    resp = client.post("/api/alerts/1/block-ip")
    assert resp.status_code == 403


def test_block_ip_post_with_foreign_origin_is_rejected(client):
    resp = client.post("/api/alerts/1/block-ip", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403


def test_block_ip_post_with_matching_origin_is_allowed_through(client):
    # No alert with id=1 exists in the fresh test DB, so this reaches the
    # "no associated source IP" branch -- 400, not 403 -- proving the
    # origin check passed and the real handler ran.
    resp = client.post("/api/alerts/1/block-ip", headers={"Origin": "http://localhost"})
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


def test_unblock_post_without_origin_is_rejected(client):
    resp = client.post("/api/blocked-ips/8.8.8.8/unblock")
    assert resp.status_code == 403


def test_unblock_post_with_matching_referer_is_allowed_through(client):
    # Some older/edge-case browser paths omit Origin but still send
    # Referer -- the fallback path must also work, not just Origin.
    resp = client.post(
        "/api/blocked-ips/8.8.8.8/unblock",
        headers={"Referer": "http://localhost/alerts"},
    )
    assert resp.status_code == 400  # not currently blocked -- proves it got past the guard
    assert resp.get_json()["ok"] is False
