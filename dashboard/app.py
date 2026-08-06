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
from flask import Flask, jsonify, render_template, request

from siem import response, storage


def load_config() -> dict:
    with open("config.yaml") as f:
        return yaml.safe_load(f)


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

    def get_conn():
        return storage.connect(db_path)

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
        rows = [dict(r) for r in storage.get_recent_events(conn, limit)]
        conn.close()
        return jsonify(rows)

    @app.route("/api/alerts")
    def api_alerts():
        conn = get_conn()
        limit = request.args.get("limit", 100, type=int)
        severity = request.args.get("severity")
        rows = [dict(r) for r in storage.get_recent_alerts(conn, limit)]
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
        conn = get_conn()
        ok, message = response.unblock_ip(conn, ip)
        conn.close()
        return jsonify({"ok": ok, "message": message}), (200 if ok else 400)

    return app


app = create_app()
