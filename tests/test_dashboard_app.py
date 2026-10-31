import os
import tempfile

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


def _add_alerts(severities):
    conn = storage.connect(dashboard_app_module.load_config()["db_path"])
    for i, sev in enumerate(severities):
        storage.insert_alert(conn, {
            "ts": f"2026-08-05T12:00:{i:02d}.000Z", "rule_id": "brute_force", "mitre_id": "T1110",
            "severity": sev, "description": f"alert {i}", "event_id_ref": None,
        })
    conn.close()


def test_content_security_policy_blocks_outside_sources(client):
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp


def test_severity_filter_is_applied_before_the_limit(client):
    # 3 high alerts buried under 5 newer low ones: limit=3&severity=high
    # should still return all 3 highs, not "highs among the newest 3"
    _add_alerts(["high"] * 3 + ["low"] * 5)
    rows = client.get("/api/alerts?limit=3&severity=high").get_json()
    assert len(rows) == 3
    assert all(r["severity"] == "high" for r in rows)


def test_unknown_severity_is_a_json_400(client):
    resp = client.get("/api/alerts?severity=critical")
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


def test_limit_is_clamped(client):
    _add_alerts(["low"] * 3)
    assert client.get("/api/alerts?limit=-5").status_code == 200
    assert len(client.get("/api/alerts?limit=-5").get_json()) == 1  # clamped up to 1
    assert client.get("/api/events?limit=999999999").status_code == 200


def test_unknown_api_route_returns_json_404(client):
    resp = client.get("/api/nope")
    assert resp.status_code == 404
    assert resp.is_json


def test_pages_render_with_accessibility_landmarks(client):
    html = client.get("/").get_data(as_text=True)
    assert 'class="skip-link" href="#main"' in html
    assert 'id="main"' in html
    assert 'aria-current="page"' in html
    assert '<th scope="col">' in html
    assert "style=" not in html  # inline styles would be blocked by the CSP
