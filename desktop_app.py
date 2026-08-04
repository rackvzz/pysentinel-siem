#!/usr/bin/env python
"""Desktop app entrypoint: a single-window, single-process, self-elevating
GUI for pysentinel-siem. Runs the collector in a background thread and
shows live events/alerts in a native Tkinter interface -- no browser tab,
no separate elevated terminal, no manual venv activation.

    python desktop_app.py

When packaged with PyInstaller (see README's "Download & run" section)
this becomes a single double-clickable .exe: Windows itself elevates it
via UAC before the process even starts (the build embeds a
requireAdministrator manifest), so the self-elevation check below is
mainly what makes `python desktop_app.py` behave the same way in dev.

The GUI talks to SQLite directly (no HTTP/JSON layer, unlike
dashboard/app.py) since it's all one process now -- the collector thread
and the GUI's periodic refresh each hold their own sqlite3 connection
(WAL mode, set in siem/storage.py, makes that safe).
"""

import ctypes
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk

import yaml

from siem import collector, engine, secrets_loader, storage

# ---------------------------------------------------------------------------
# Palette -- same hex values as dashboard/static/style.css, adapted for a
# native (light-only) Tkinter surface rather than CSS custom properties.
BG = "#f4f4f2"
SURFACE = "#ffffff"
BORDER = "#dedcd4"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
TEXT_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE = "#c3c2b7"
SERIES_BLUE = "#2a78d6"
# Severity -> status color. Slightly darkened from the web palette's
# warning/serious/critical steps so they stay legible as plain text on a
# white Treeview row (the web version could lean on a tinted badge
# background; a native list row can't cheaply do that same wash).
SEVERITY_COLOR = {"low": "#a66a00", "medium": "#c1552f", "high": "#d03b3b"}

POLL_MS = 5000
FONT = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 9, "bold")

DEFAULT_CONFIG = """# pysentinel-siem configuration

# Windows Event Log channels to collect from.
channels:
  - Security
  - System
  - Microsoft-Windows-Sysmon/Operational

# How often the collector polls each channel, in seconds.
poll_interval_seconds: 5

# SQLite database file (relative to this file's directory).
db_path: siem.db

detections:
  brute_force:
    enabled: true
    failed_logon_event_id: 4625
    threshold: 5
    window_seconds: 300
  new_admin_account:
    enabled: true
    event_ids: [4720, 4732]
  afterhours_logon:
    enabled: true
    successful_logon_event_id: 4624
    # Hours are UTC (all timestamps in this project are stored in UTC).
    business_hours_start: 7
    business_hours_end: 19
  # The two rules below read Sysmon process-creation events (event ID 1
  # on Microsoft-Windows-Sysmon/Operational).
  encoded_powershell:
    enabled: true
  suspicious_parent_child:
    enabled: true
  threat_intel_match:
    enabled: true

# Keeps the local database from growing unbounded. Raw events are
# high-volume and low long-term value; alerts are the valuable distilled
# output, so they're kept much longer by default.
retention:
  enabled: true
  events_retention_days: 30
  alerts_retention_days: 365
  check_interval_hours: 24

# Cross-references observed IPs against abuse.ch ThreatFox. Disabled by
# default since it needs a free Auth-Key -- see secrets.yaml.example.
threat_intel:
  enabled: false
  refresh_interval_hours: 24
  lookback_days: 3
"""


def app_dir() -> str:
    """Directory the exe/script lives in. Used instead of the process's
    working directory so a double-clicked exe finds its config.yaml and
    writes siem.db next to itself, regardless of how Explorer launched it."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def ensure_config(path: str) -> None:
    """Write a default config.yaml next to the exe if one isn't already
    there -- lets a freshly-downloaded exe run with zero setup."""
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(DEFAULT_CONFIG)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """Re-invoke this process elevated via UAC, then let the (unelevated)
    caller exit. Redundant with the packaged exe's UAC manifest, but keeps
    `python desktop_app.py` behaving the same way in dev."""
    if getattr(sys, "frozen", False):
        target = sys.executable
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        target = sys.executable
        params = " ".join([f'"{os.path.abspath(__file__)}"'] + [f'"{a}"' for a in sys.argv[1:]])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, app_dir(), 1)


# --------------------------------------------------------------- charts ----
class LineChart(tk.Canvas):
    """Hand-drawn events-over-time line chart (single series, sequential
    blue) -- Tkinter Canvas has no alpha blending, so this skips the web
    version's area wash and keeps a clean 2px line + end marker."""

    def __init__(self, parent, width: int, height: int):
        super().__init__(parent, width=width, height=height, bg=SURFACE, highlightthickness=0)
        self._cw, self._ch = width, height

    def update_data(self, data: list[dict]) -> None:
        self.delete("all")
        pad_l, pad_r, pad_t, pad_b = 36, 10, 8, 20
        plot_w = self._cw - pad_l - pad_r
        plot_h = self._ch - pad_t - pad_b

        if not data:
            self.create_text(self._cw / 2, self._ch / 2, text="No events yet", fill=TEXT_MUTED, font=FONT)
            return

        max_n = max((d["n"] for d in data), default=0) or 1
        nice_max = max_n if max_n % 5 == 0 else ((max_n // 5) + 1) * 5

        def x_for(i):
            return pad_l + (plot_w / 2 if len(data) == 1 else (i / (len(data) - 1)) * plot_w)

        def y_for(n):
            return pad_t + plot_h - (n / nice_max) * plot_h

        for frac in (0, 0.5, 1.0):
            val = nice_max * frac
            y = y_for(val)
            self.create_line(pad_l, y, self._cw - pad_r, y, fill=GRIDLINE)
            self.create_text(pad_l - 6, y, text=f"{int(val)}", fill=TEXT_MUTED, anchor="e", font=("Segoe UI", 8))
        self.create_line(pad_l, pad_t + plot_h, self._cw - pad_r, pad_t + plot_h, fill=BASELINE)

        points = []
        for i, d in enumerate(data):
            points.extend([x_for(i), y_for(d["n"])])
        if len(points) >= 4:
            self.create_line(*points, fill=SERIES_BLUE, width=2, joinstyle="round", capstyle="round")

        last_x, last_y = points[-2], points[-1]
        r = 4
        self.create_oval(last_x - r, last_y - r, last_x + r, last_y + r, fill=SERIES_BLUE, outline=SURFACE, width=2)

        for i in (0, len(data) // 2, len(data) - 1):
            label = data[i]["bucket"].split("T")[-1][:5]
            self.create_text(x_for(i), self._ch - 6, text=label, fill=TEXT_MUTED, font=("Segoe UI", 8))


class BarChart(tk.Canvas):
    """Hand-drawn horizontal bar chart (top event IDs), single blue hue,
    value labeled at the bar tip -- mirrors dashboard/static/dashboard.js's
    SVG version."""

    def __init__(self, parent, width: int, height: int):
        super().__init__(parent, width=width, height=height, bg=SURFACE, highlightthickness=0)
        self._cw, self._ch = width, height

    def update_data(self, data: list[dict]) -> None:
        self.delete("all")
        pad_l, pad_r, pad_t = 46, 40, 6
        row_h = 20

        if not data:
            self.create_text(self._cw / 2, self._ch / 2, text="No events yet", fill=TEXT_MUTED, font=FONT)
            return

        max_n = max(d["n"] for d in data) or 1
        plot_w = self._cw - pad_l - pad_r
        for i, d in enumerate(data):
            y = pad_t + i * row_h
            bar_h = 14
            bar_w = max(2, (d["n"] / max_n) * plot_w)
            self.create_text(pad_l - 6, y + row_h / 2, text=str(d["event_id"]), fill=TEXT_SECONDARY, anchor="e", font=FONT)
            self.create_rectangle(
                pad_l, y + (row_h - bar_h) / 2, pad_l + bar_w, y + (row_h - bar_h) / 2 + bar_h,
                fill=SERIES_BLUE, outline="",
            )
            self.create_text(pad_l + bar_w + 6, y + row_h / 2, text=f"{d['n']:,}", fill=TEXT_SECONDARY, anchor="w", font=FONT)


# ----------------------------------------------------------------- app -----
class App(tk.Tk):
    def __init__(self, conn):
        super().__init__()
        self.conn = conn
        self.title("pysentinel-siem")
        self.geometry("1100x740")
        self.configure(bg=BG)
        self._setup_style()
        self._build_ui()
        self._refresh()

    def _setup_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 8), font=FONT)
        style.configure(
            "Treeview", background=SURFACE, fieldbackground=SURFACE,
            foreground=TEXT_PRIMARY, rowheight=24, font=FONT, borderwidth=0,
        )
        style.configure("Treeview.Heading", font=FONT_BOLD, background=BG, foreground=TEXT_SECONDARY)
        style.map("Treeview", background=[("selected", "#dce8fb")])

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        dash = ttk.Frame(notebook)
        alerts_tab = ttk.Frame(notebook)
        notebook.add(dash, text="Dashboard")
        notebook.add(alerts_tab, text="Alerts")

        self._build_dashboard_tab(dash)
        self._build_alerts_tab(alerts_tab)

    def _tile(self, parent, key: str, label: str, accent: bool = False) -> None:
        tile = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        tile.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(tile, text=label, bg=SURFACE, fg=TEXT_SECONDARY, font=FONT).pack(anchor="w", padx=12, pady=(10, 0))
        var = tk.StringVar(value="—")
        color = SEVERITY_COLOR["high"] if accent else TEXT_PRIMARY
        tk.Label(tile, textvariable=var, bg=SURFACE, fg=color, font=("Segoe UI", 20, "bold")).pack(
            anchor="w", padx=12, pady=(0, 10)
        )
        self.stat_vars[key] = var

    def _build_dashboard_tab(self, parent) -> None:
        self.stat_vars: dict[str, tk.StringVar] = {}
        stat_row = tk.Frame(parent, bg=BG)
        stat_row.pack(fill="x", pady=(0, 10))
        self._tile(stat_row, "total_events", "Total events")
        self._tile(stat_row, "total_alerts", "Total alerts")
        self._tile(stat_row, "alerts_24h", "Alerts (24h)")
        self._tile(stat_row, "high_severity", "High-severity alerts", accent=True)

        chart_row = tk.Frame(parent, bg=BG)
        chart_row.pack(fill="x", pady=(0, 10))

        line_frame = tk.Frame(chart_row, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        line_frame.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(line_frame, text="Events over time (24h)", bg=SURFACE, fg=TEXT_PRIMARY, font=FONT_BOLD).pack(
            anchor="w", padx=12, pady=(10, 0)
        )
        self.line_chart = LineChart(line_frame, width=460, height=180)
        self.line_chart.pack(padx=12, pady=10)

        bar_frame = tk.Frame(chart_row, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        bar_frame.pack(side="left", fill="both", expand=True)
        tk.Label(bar_frame, text="Top event IDs", bg=SURFACE, fg=TEXT_PRIMARY, font=FONT_BOLD).pack(
            anchor="w", padx=12, pady=(10, 0)
        )
        self.bar_chart = BarChart(bar_frame, width=380, height=180)
        self.bar_chart.pack(padx=12, pady=10)

        tk.Label(parent, text="Recent alerts", bg=BG, fg=TEXT_PRIMARY, font=FONT_BOLD).pack(anchor="w")
        self.alerts_tree = self._make_alerts_tree(parent, height=6)
        self.alerts_tree.pack(fill="x", pady=(2, 10))

        tk.Label(parent, text="Recent events", bg=BG, fg=TEXT_PRIMARY, font=FONT_BOLD).pack(anchor="w")
        self.events_tree = self._make_events_tree(parent, height=10)
        self.events_tree.pack(fill="both", expand=True, pady=(2, 0))

    def _build_alerts_tab(self, parent) -> None:
        filter_row = tk.Frame(parent, bg=BG)
        filter_row.pack(fill="x", pady=(0, 8))
        tk.Label(filter_row, text="Severity:", bg=BG, fg=TEXT_SECONDARY, font=FONT).pack(side="left", padx=(0, 6))
        self.severity_filter = tk.StringVar(value="All")
        combo = ttk.Combobox(
            filter_row, textvariable=self.severity_filter, values=["All", "High", "Medium", "Low"],
            state="readonly", width=12,
        )
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", lambda e: self._refresh_alerts_tab())

        self.full_alerts_tree = self._make_alerts_tree(parent, height=28)
        self.full_alerts_tree.pack(fill="both", expand=True)

    def _make_alerts_tree(self, parent, height: int) -> ttk.Treeview:
        cols = ("time", "severity", "mitre", "rule", "description")
        widths = {"time": 150, "severity": 80, "mitre": 90, "rule": 150, "description": 420}
        headings = {"time": "Time (UTC)", "severity": "Severity", "mitre": "MITRE", "rule": "Rule", "description": "Description"}
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=height)
        for c in cols:
            tree.heading(c, text=headings[c])
            tree.column(c, width=widths[c], anchor="w")
        for sev, color in SEVERITY_COLOR.items():
            tree.tag_configure(f"sev-{sev}", foreground=color, font=FONT_BOLD)
        return tree

    def _make_events_tree(self, parent, height: int) -> ttk.Treeview:
        cols = ("time", "channel", "event_id", "level", "user", "source", "message")
        widths = {"time": 150, "channel": 90, "event_id": 70, "level": 80, "user": 110, "source": 120, "message": 380}
        headings = {
            "time": "Time (UTC)", "channel": "Channel", "event_id": "Event ID", "level": "Level",
            "user": "User", "source": "Source", "message": "Message",
        }
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=height)
        for c in cols:
            tree.heading(c, text=headings[c])
            tree.column(c, width=widths[c], anchor="w")
        return tree

    @staticmethod
    def _populate_alerts_tree(tree: ttk.Treeview, rows) -> None:
        tree.delete(*tree.get_children())
        for r in rows:
            tree.insert(
                "", "end",
                values=(r["ts"], r["severity"].upper(), r["mitre_id"], r["rule_id"], r["description"]),
                tags=(f"sev-{r['severity']}",),
            )

    @staticmethod
    def _populate_events_tree(tree: ttk.Treeview, rows) -> None:
        tree.delete(*tree.get_children())
        for r in rows:
            tree.insert(
                "", "end",
                values=(r["ts"], r["channel"], r["event_id"], r["level"], r["user"], r["source_ip"], r["message"]),
            )

    def _refresh(self) -> None:
        try:
            self._refresh_stats()
            self._refresh_charts()
            self._populate_alerts_tree(self.alerts_tree, storage.get_recent_alerts(self.conn, 10))
            self._populate_events_tree(self.events_tree, storage.get_recent_events(self.conn, 25))
            self._refresh_alerts_tab()
        except Exception:
            pass  # a transient DB hiccup shouldn't kill the whole app
        self.after(POLL_MS, self._refresh)

    def _refresh_stats(self) -> None:
        total_events = self.conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        total_alerts = self.conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        alerts_24h = self.conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE ts >= strftime('%Y-%m-%dT%H:%M:%S', 'now', '-24 hours')"
        ).fetchone()["n"]
        high = self.conn.execute("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'high'").fetchone()["n"]
        self.stat_vars["total_events"].set(f"{total_events:,}")
        self.stat_vars["total_alerts"].set(f"{total_alerts:,}")
        self.stat_vars["alerts_24h"].set(f"{alerts_24h:,}")
        self.stat_vars["high_severity"].set(f"{high:,}")

    def _refresh_charts(self) -> None:
        self.line_chart.update_data([dict(r) for r in storage.get_events_over_time(self.conn, 24)])
        self.bar_chart.update_data([dict(r) for r in storage.get_event_counts_by_id(self.conn, 8)])

    def _refresh_alerts_tab(self) -> None:
        sev = self.severity_filter.get()
        rows = [dict(r) for r in storage.get_recent_alerts(self.conn, 200)]
        if sev != "All":
            rows = [r for r in rows if r["severity"] == sev.lower()]
        self._populate_alerts_tree(self.full_alerts_tree, rows)


def main() -> None:
    if not is_admin():
        relaunch_as_admin()
        return

    cfg_path = os.path.join(app_dir(), "config.yaml")
    ensure_config(cfg_path)
    with open(cfg_path) as f:
        config = yaml.safe_load(f)

    secrets = secrets_loader.load(app_dir())
    config.setdefault("threat_intel", {})["api_key"] = secrets.get("threatfox_api_key")

    db_path = config.get("db_path", "siem.db")
    if not os.path.isabs(db_path):
        db_path = os.path.join(app_dir(), db_path)

    engine.configure(config)

    collector_conn = storage.connect(db_path)
    storage.init_db(collector_conn)
    channels = config["channels"]
    poll_interval = config.get("poll_interval_seconds", 5)
    thread = threading.Thread(
        target=collector.run_forever,
        args=(collector_conn, channels, poll_interval),
        kwargs={"config": config},
        daemon=True,
    )
    thread.start()

    gui_conn = storage.connect(db_path)
    App(gui_conn).mainloop()


if __name__ == "__main__":
    main()
