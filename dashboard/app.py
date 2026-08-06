"""Flask dashboard: a web UI over the same SQLite database the collector
(run_collector.py) writes to. Almost entirely read-only -- the one
exception is the block-IP response action (see siem/response.py), a
human-triggered, confirmation-gated write from the Alerts page.

Routes:
  /                                   recent events + alerts + charts (HTML)
  /alerts                             full alert list, filterable by severity (HTML)
  /api/stats                          summary counters (JSON)
  /api/events                         recent events (JSON)
  /api/alerts                         recent alerts, optional ?severity= filter (JSON)
  /api/charts/events-over-time        hourly event counts for the last N hours (JSON)
  /api/charts/top-event-ids           most frequent event IDs (JSON)
  /api/blocked-ips                    currently-blocked IPs (JSON)
  POST /api/alerts/<id>/block-ip      blocks that alert's source IP (JSON)
  POST /api/blocked-ips/<ip>/unblock  unblocks it (JSON)

The frontend (static/dashboard.js) polls the /api/* endpoints every few
seconds so the page updates live without a full reload.
"""

import yaml
from flask import Flask, abort, jsonify, render_template, request

from siem import file_security, response, storage


def load_config() -> dict:
    with open("config.yaml") as f:
        return yaml.safe_load(f)


# Explicit allowlist (not "everything except raw_xml") for /api/events: the
# events table's raw_xml column is the full Windows Event Log XML for that
# event -- for a PowerShell/Sysmon event that can include a complete
# command line or script block, which the dashboard UI never displays
# (dashboard.js's events table only ever renders the fields below). An
# allowlist means a future column added to the events table is excluded
# from the API by default too, not exposed until someone deliberately
# opts it in here -- the safer default for a JSON endpoint.
EVENT_API_FIELDS = ("id", "ts", "channel", "event_id", "level", "user", "source_ip", "message")

# Same reasoning as EVENT_API_FIELDS: the alerts table's event_id_ref (an
# internal foreign key) is never read by dashboard.js -- the block-ip
# route resolves the source IP with its own direct join, not through this
# endpoint's response -- so it's left out rather than passed through.
ALERT_API_FIELDS = ("id", "ts", "rule_id", "mitre_id", "severity", "description")


def _check_same_origin() -> None:
    """CSRF guard for the two state-changing routes below (block-ip /
    unblock). Without this, a malicious page open in another browser tab
    could POST to this server's block-ip endpoint directly -- the
    confirm() dialog in dashboard.js is client-side only and simply never
    runs for a request that doesn't come from this app's own JS in the
    first place, so it isn't protection against a forged request.

    Rejects any POST whose Origin (or, if the browser omitted it, Referer)
    header doesn't match this server's own origin. Every modern browser
    sets Origin on same-origin POSTs too, so this doesn't get in the way
    of the dashboard's own fetch() calls -- only a request that didn't
    genuinely originate from a page this server served."""
    expected = f"http://{request.host}"
    origin = request.headers.get("Origin")
    if origin is not None:
        if origin != expected:
            abort(403)
        return
    referer = request.headers.get("Referer", "")
    if not referer.startswith(expected + "/"):
        abort(403)


def create_app() -> Flask:
    app = Flask(__name__)
    config = load_config()
    db_path = config["db_path"]

    # The dashboard is otherwise read-only (the collector is the sole
    # writer/schema-owner for events/alerts -- see module docstring), but
    # blocked_ips is a table either UI can write to, and a db file created
    # before that table existed won't have it yet. init_db()'s CREATE
    # TABLE/INDEX IF NOT EXISTS statements are safe to run against an
    # already-populated, up-to-date database -- this is a one-time
    # ensure-schema-current step at startup, not a per-request cost.
    storage.init_db(storage.connect(db_path))
    file_security.restrict_to_current_user(db_path)

    def get_conn():
        return storage.connect(db_path)

    @app.after_request
    def _security_headers(resp):
        # Standard security-header hardening (OWASP Secure Headers
        # baseline), scoped to what actually applies to a same-origin,
        # localhost-only dashboard with no third-party embeds:
        #  - Server: replaces Werkzeug's default "Werkzeug/x.y Python/x.y"
        #    banner, which hands an attacker the exact framework/interpreter
        #    version for free. Low practical risk here (127.0.0.1-only, not
        #    reachable off-box) but free to close off.
        #  - X-Content-Type-Options: stops the browser from trying to
        #    guess/override a response's declared content type.
        #  - X-Frame-Options: this dashboard is never meant to be framed by
        #    another site -- blocks a clickjacking overlay tricking a user
        #    into an unintended "Block IP" click.
        #  - Referrer-Policy: don't leak this page's URL (which can include
        #    alert/IP details in the query string) via the Referer header
        #    if a user ever follows an outbound link from here.
        resp.headers["Server"] = "pysentinel-siem"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/alerts")
    def alerts_page():
        return render_template("alerts.html")

    @app.route("/api/stats")
    def api_stats():
        conn = get_conn()
        total_events = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        total_alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        alerts_24h = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE ts >= strftime('%Y-%m-%dT%H:%M:%S', 'now', '-24 hours')"
        ).fetchone()["n"]
        high_severity = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE severity = 'high'"
        ).fetchone()["n"]
        conn.close()
        return jsonify(
            {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "alerts_24h": alerts_24h,
                "high_severity_alerts": high_severity,
            }
        )

    @app.route("/api/events")
    def api_events():
        conn = get_conn()
        limit = request.args.get("limit", 50, type=int)
        rows = [{k: r[k] for k in EVENT_API_FIELDS} for r in storage.get_recent_events(conn, limit)]
        conn.close()
        return jsonify(rows)

    @app.route("/api/alerts")
    def api_alerts():
        conn = get_conn()
        limit = request.args.get("limit", 100, type=int)
        severity = request.args.get("severity")
        rows = [{k: r[k] for k in ALERT_API_FIELDS} for r in storage.get_recent_alerts(conn, limit)]
        conn.close()
        if severity:
            rows = [r for r in rows if r["severity"] == severity]
        return jsonify(rows)

    @app.route("/api/charts/events-over-time")
    def api_events_over_time():
        conn = get_conn()
        hours = request.args.get("hours", 24, type=int)
        rows = [dict(r) for r in storage.get_events_over_time(conn, hours)]
        conn.close()
        return jsonify(rows)

    @app.route("/api/charts/top-event-ids")
    def api_top_event_ids():
        conn = get_conn()
        limit = request.args.get("limit", 8, type=int)
        rows = [dict(r) for r in storage.get_event_counts_by_id(conn, limit)]
        conn.close()
        return jsonify(rows)

    @app.route("/api/blocked-ips")
    def api_blocked_ips():
        conn = get_conn()
        rows = [dict(r) for r in response.list_blocked_ips(conn)]
        conn.close()
        return jsonify(rows)

    @app.route("/api/alerts/<int:alert_id>/block-ip", methods=["POST"])
    def api_block_alert_ip(alert_id):
        _check_same_origin()
        conn = get_conn()
        row = conn.execute(
            "SELECT a.rule_id, e.source_ip FROM alerts a "
            "LEFT JOIN events e ON e.id = a.event_id_ref WHERE a.id = ?",
            (alert_id,),
        ).fetchone()
        if not row or not row["source_ip"]:
            conn.close()
            return jsonify({"ok": False, "message": "That alert has no associated source IP."}), 400

        ok, message = response.block_ip(conn, row["source_ip"], reason=f"alert: {row['rule_id']}")
        conn.close()
        return jsonify({"ok": ok, "message": message, "ip": row["source_ip"]}), (200 if ok else 400)

    @app.route("/api/blocked-ips/<ip>/unblock", methods=["POST"])
    def api_unblock_ip(ip):
        _check_same_origin()
        conn = get_conn()
        ok, message = response.unblock_ip(conn, ip)
        conn.close()
        return jsonify({"ok": ok, "message": message}), (200 if ok else 400)

    return app


app = create_app()
