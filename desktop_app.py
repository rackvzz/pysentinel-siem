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

Settings (Settings tab) are layered on top of config.yaml rather than
overwriting it: changes get written to user_settings.yaml (a small
overlay file, gitignored, deep-merged over config.yaml at startup) plus
secrets.yaml for the API key. config.yaml's own comments/defaults are
never touched by the app. Most settings apply immediately -- the
collector thread holds a reference to the same `config` dict this app
mutates in place, so it sees rule/retention/threat-intel changes on its
next loop iteration without a restart. Only `poll_interval_seconds`
(baked into the thread's call args at startup) needs a restart.
"""

import ctypes
import logging
import os
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import defusedxml
import yaml

from siem import alerts, audit_policy, collector, correlation, engine, file_security, logging_setup, posture, response, secrets_loader, storage

# Hardens xml.etree.ElementTree process-wide against DOCTYPE-based XXE/
# entity-expansion attacks -- see run_collector.py's matching call for the
# full rationale. Module-level (not inside main()) since desktop_app.py's
# tests import this module directly without going through main().
defusedxml.defuse_stdlib()

# ---------------------------------------------------------------------------
# Theme -- same hex values as dashboard/static/style.css where applicable.
# `apply_theme()` reassigns the module-level names below; every widget
# builder reads them at call time, so a full UI rebuild (App._rebuild_theme)
# after a theme switch picks up the new values everywhere.
THEMES = {
    "light": {
        "bg": "#f4f4f2", "surface": "#ffffff", "border": "#dedcd4",
        "text_primary": "#0b0b0b", "text_secondary": "#52514e", "text_muted": "#898781",
        "gridline": "#e1e0d9", "baseline": "#c3c2b7", "series_blue": "#2a78d6",
        "selection": "#dce8fb",
        # low=green (status-good), medium=blue (matches series_blue above),
        # high=red (status-critical) -- all already clear 3:1 on the light
        # surface as-is (3.27 / n/a-reused-from-charts / 4.68), no darkening needed.
        "severity": {"low": "#0ca30c", "medium": "#2a78d6", "high": "#d03b3b"},
    },
    "dark": {
        "bg": "#0d0d0d", "surface": "#1a1a19", "border": "#383835",
        "text_primary": "#ffffff", "text_secondary": "#c3c2b7", "text_muted": "#898781",
        "gridline": "#2c2c2a", "baseline": "#383835", "series_blue": "#3987e5",
        "selection": "#28374a",
        # Same mapping, dark-surface steps -- all clear 3:1 (5.19 / n/a / 3.62).
        "severity": {"low": "#0ca30c", "medium": "#3987e5", "high": "#d03b3b"},
    },
}

CURRENT_THEME = "light"
BG = SURFACE = BORDER = TEXT_PRIMARY = TEXT_SECONDARY = TEXT_MUTED = ""
GRIDLINE = BASELINE = SERIES_BLUE = SELECTION = ""
SEVERITY_COLOR: dict = {}


def apply_theme(name: str) -> None:
    global CURRENT_THEME, BG, SURFACE, BORDER, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED
    global GRIDLINE, BASELINE, SERIES_BLUE, SELECTION, SEVERITY_COLOR
    t = THEMES.get(name, THEMES["light"])
    CURRENT_THEME = name if name in THEMES else "light"
    BG, SURFACE, BORDER = t["bg"], t["surface"], t["border"]
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED = t["text_primary"], t["text_secondary"], t["text_muted"]
    GRIDLINE, BASELINE, SERIES_BLUE = t["gridline"], t["baseline"], t["series_blue"]
    SELECTION = t["selection"]
    SEVERITY_COLOR = t["severity"]


apply_theme("light")  # sane defaults so module-level widgets aren't built with ""


# ---------------------------------------------------------------- color ----
def _mix(hex_a: str, hex_b: str, t: float) -> str:
    """Linear-interpolates between two hex colors (t=0 -> hex_a, t=1 ->
    hex_b). Tkinter has no alpha compositing, so this is how a "wash" tint
    (e.g. an icon chip's translucent-looking background) gets approximated
    on an opaque surface: blend a little of the accent into the surface
    color directly, same idea as CSS color-mix()."""
    a = hex_a.lstrip("#")
    b = hex_b.lstrip("#")
    ar, ag, ab = (int(a[i:i + 2], 16) for i in (0, 2, 4))
    br, bg_, bb = (int(b[i:i + 2], 16) for i in (0, 2, 4))
    r = round(ar + (br - ar) * t)
    g = round(ag + (bg_ - ag) * t)
    bch = round(ab + (bb - ab) * t)
    return f"#{r:02x}{g:02x}{bch:02x}"


def _shade(hex_color: str, amount: float) -> str:
    """Lightens (amount > 0) or darkens (amount < 0) a hex color toward
    white/black -- used for button hover/pressed states, which need a
    distinct shade per interaction state independent of any surface."""
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    if amount >= 0:
        r, g, b = (int(c + (255 - c) * amount) for c in (r, g, b))
    else:
        r, g, b = (int(c * (1 + amount)) for c in (r, g, b))
    return f"#{r:02x}{g:02x}{b:02x}"


def _rounded_rect_points(x1: float, y1: float, x2: float, y2: float, radius: float) -> list:
    """Point list for a Canvas smoothed polygon that reads as a rounded
    rectangle -- used only for small, fixed-size shapes (icon chips, the
    live-status dot) where the size is set once at construction, never
    stretched by the layout manager."""
    radius = max(0, min(radius, (x2 - x1) / 2, (y2 - y1) / 2))
    return [
        x1 + radius, y1, x2 - radius, y1, x2, y1, x2, y1 + radius,
        x2, y2 - radius, x2, y2, x2 - radius, y2, x1 + radius, y2,
        x1, y2, x1, y2 - radius, x1, y1 + radius, x1, y1,
    ]

# Display-only timezone preference for the events/alerts tables. Storage,
# the afterhours_logon business-hours comparison, and every other
# timestamp in the system stay UTC regardless of this setting -- only
# what's *shown* in the tables changes. "Local" uses datetime.astimezone()
# with no argument, which reads the host's own OS timezone -- no zoneinfo/
# tzdata dependency needed.
CURRENT_TIMEZONE = "UTC"


def apply_timezone(name: str) -> None:
    global CURRENT_TIMEZONE
    CURRENT_TIMEZONE = name if name in ("UTC", "Local") else "UTC"


def format_display_ts(raw_ts: str) -> str:
    """Formats a stored UTC ISO timestamp for display, converting to the
    host's local timezone if that's the current preference. Falls back to
    the raw string unchanged if it doesn't parse (e.g. unexpected format)."""
    if not raw_ts:
        return raw_ts
    from siem.rules.base import parse_ts

    try:
        dt = parse_ts(raw_ts)
    except (ValueError, TypeError):
        return raw_ts
    if CURRENT_TIMEZONE == "Local":
        dt = dt.astimezone()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


POLL_MS = 5000
FONT = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 9, "bold")
TILE_ICONS = {
    "total_events": "\U0001F4CA",   # bar chart
    "total_alerts": "\U0001F6A8",   # rotating light
    "alerts_24h": "\U0000231B",     # hourglass
    "high_severity": "\U000026A0",  # warning
}

DEFAULT_CONFIG = """# pysentinel-siem configuration

# Windows Event Log channels to collect from.
channels:
  - Security
  - System
  - Microsoft-Windows-Sysmon/Operational
  # Needed for powershell_scriptblock's detection (event 4104). Always
  # exists as a channel; only emits 4104 once Script Block Logging is
  # turned on (off by default -- see README's "Detection setup" section).
  - Microsoft-Windows-PowerShell/Operational

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
  # Watches for many distinct local ports blocked from the same remote IP
  # in a short window -- a port scan (nmap etc.) signature. Requires
  # Windows' "Filtering Platform Connection" audit policy (failure) to be
  # enabled -- this app turns it on automatically at startup when this
  # rule is enabled, no manual setup step.
  port_scan_detection:
    enabled: true
    distinct_ports_threshold: 10
    window_seconds: 30
  # Reads PowerShell Script Block Logging (event 4104) -- catches
  # obfuscation encoded_powershell's command-line check can't see.
  powershell_scriptblock:
    enabled: true
  # Sysmon ProcessAccess (event 10) targeting lsass.exe with memory-read
  # rights -- LSASS credential dumping (T1003).
  credential_access:
    enabled: true
  # New scheduled task (4698) or new service (7045). 4698 needs an audit
  # policy this app turns on automatically at startup, same as
  # port_scan_detection's.
  persistence:
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

# Desktop app UI preferences. Normally managed via the Settings tab
# (which writes to user_settings.yaml, not this file) -- this default
# only matters the very first time the app runs, before any
# user_settings.yaml exists. "timezone" only affects display in the
# events/alerts tables -- storage and business-hours comparisons always
# stay UTC regardless of this setting.
ui:
  theme: light
  timezone: UTC

# Periodically scans this machine's own current state (not streaming
# events) for attack-surface issues -- currently just exposed/listening
# ports. Findings appear in the Posture tab, replaced fresh on each scan.
posture:
  enabled: true
  scan_interval_hours: 24

# Native Windows notification (Action Center toast) fired when an alert at
# or above min_severity is raised.
notifications:
  enabled: true
  min_severity: high

# Chains independently-firing alerts from the same user/source IP into one
# higher-confidence "correlated" alert.
correlation:
  enabled: true
  window_minutes: 15
  min_signals: 2
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


def deep_merge_in_place(base: dict, override: dict) -> None:
    """Recursively merge `override` into `base`, mutating `base` in place
    (rather than returning a new dict) so callers that need the update to
    propagate to other holders of the same dict reference -- the
    collector thread, specifically -- see it without re-wiring anything."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge_in_place(base[key], value)
        else:
            base[key] = value


def load_user_settings(directory: str) -> dict:
    path = os.path.join(directory, "user_settings.yaml")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def save_user_settings(directory: str, settings: dict) -> None:
    path = os.path.join(directory, "user_settings.yaml")
    with open(path, "w") as f:
        yaml.safe_dump(settings, f, sort_keys=False)


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
    def __init__(self, conn, config: dict, app_directory: str):
        super().__init__()
        self.conn = conn
        self.config = config
        self._app_dir = app_directory
        self._initial_poll_interval = config.get("poll_interval_seconds", 5)
        self._refresh_job = None
        self._pulse_job = None

        self.title("pysentinel-siem")
        self.geometry("1180x790")
        self.minsize(900, 600)
        self.configure(bg=BG)
        self._setup_style()
        self._build_header()
        self._build_ui()
        self._start_refresh_loop()
        self._bring_to_front()

    def _bring_to_front(self) -> None:
        """A freshly UAC-elevated process's window can end up buried
        behind whatever you were looking at -- force it forward once on
        startup rather than leaving you hunting for it in the taskbar."""
        self.lift()
        self.attributes("-topmost", True)
        self.after(400, lambda: self.attributes("-topmost", False))
        self.focus_force()

    def _build_header(self) -> None:
        tk.Frame(self, bg=SERIES_BLUE, height=4).pack(fill="x", side="top")
        header = tk.Frame(self, bg=SURFACE)
        header.pack(fill="x", side="top")
        inner = tk.Frame(header, bg=SURFACE)
        inner.pack(fill="x", padx=20, pady=(14, 12))

        left = tk.Frame(inner, bg=SURFACE)
        left.pack(side="left", fill="x")
        tk.Label(
            left, text="\U0001F6E1  pysentinel-siem", bg=SURFACE, fg=TEXT_PRIMARY, font=("Segoe UI", 16, "bold")
        ).pack(anchor="w")
        tk.Label(
            left, text="Live security monitoring for this PC", bg=SURFACE, fg=TEXT_SECONDARY, font=FONT
        ).pack(anchor="w")

        right = tk.Frame(inner, bg=SURFACE)
        right.pack(side="right", anchor="e")
        self._pulse_canvas = tk.Canvas(right, width=10, height=10, bg=SURFACE, highlightthickness=0)
        self._pulse_canvas.pack(side="left", padx=(0, 6))
        self._pulse_dot = self._pulse_canvas.create_oval(1, 1, 9, 9, fill=SEVERITY_COLOR.get("low", "#0ca30c"), outline="")
        tk.Label(right, text="Live", bg=SURFACE, fg=TEXT_SECONDARY, font=FONT).pack(side="left")
        self._start_pulse()

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", side="top")

    def _start_pulse(self) -> None:
        """Blinks the header's live-status dot -- the desktop counterpart
        of the web dashboard's CSS pulse animation, and cheap visual proof
        the refresh loop is still running. Tracked via self._pulse_job (like
        self._refresh_job) so a theme rebuild can cancel the old loop
        instead of stacking a second one on top of it."""
        base = SEVERITY_COLOR.get("low", "#0ca30c")
        dim = _mix(SURFACE, base, 0.35)
        state = {"dim": False}

        def tick():
            state["dim"] = not state["dim"]
            try:
                self._pulse_canvas.itemconfig(self._pulse_dot, fill=dim if state["dim"] else base)
            except tk.TclError:
                return  # canvas destroyed (theme rebuild or app close) -- just stop
            self._pulse_job = self.after(700, tick)

        tick()

    def _setup_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=BG)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(22, 11), font=FONT, background=BG, foreground=TEXT_SECONDARY)
        style.map(
            "TNotebook.Tab",
            background=[("selected", SURFACE)],
            foreground=[("selected", TEXT_PRIMARY)],
            font=[("selected", FONT_BOLD)],
        )
        style.configure(
            "Treeview", background=SURFACE, fieldbackground=SURFACE,
            foreground=TEXT_PRIMARY, rowheight=26, font=FONT, borderwidth=0,
        )
        style.configure(
            "Treeview.Heading", font=FONT_BOLD, background=BG, foreground=TEXT_SECONDARY,
            relief="flat", padding=(4, 6),
        )
        style.map("Treeview", background=[("selected", SELECTION)])
        style.configure("TCombobox", padding=(8, 4), font=FONT, fieldbackground=SURFACE, foreground=TEXT_PRIMARY)
        style.configure("TCheckbutton", background=SURFACE, foreground=TEXT_PRIMARY, font=FONT)
        style.map("TCheckbutton", background=[("active", SURFACE)])
        style.configure("TEntry", fieldbackground=SURFACE, foreground=TEXT_PRIMARY, insertcolor=TEXT_PRIMARY, padding=(6, 4))
        style.configure(
            "TButton", background=SERIES_BLUE, foreground="#ffffff", font=FONT_BOLD,
            padding=(14, 7), borderwidth=0,
        )
        style.map(
            "TButton",
            background=[("pressed", _shade(SERIES_BLUE, -0.15)), ("active", _shade(SERIES_BLUE, 0.12))],
        )
        style.configure("TScrollbar", background=BG, troughcolor=BG, bordercolor=BORDER, arrowcolor=TEXT_SECONDARY)

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=16, pady=(16, 16))

        dash = ttk.Frame(notebook)
        alerts_tab = ttk.Frame(notebook)
        posture_tab = ttk.Frame(notebook)
        settings_tab = ttk.Frame(notebook)
        notebook.add(dash, text="Dashboard")
        notebook.add(alerts_tab, text="Alerts")
        notebook.add(posture_tab, text="Posture")
        notebook.add(settings_tab, text="Settings")

        self._build_dashboard_tab(dash)
        self._build_alerts_tab(alerts_tab)
        self._build_posture_tab(posture_tab)
        self._build_settings_tab(settings_tab)

    def _rebuild_theme(self) -> None:
        """Full UI rebuild after a theme switch. Plain tk widgets (Frame/
        Label bg=/fg=) bake their color in at creation time -- there's no
        cheap way to retint them in place, so this just tears everything
        down and rebuilds it with the new module-level color values.
        Called via after_idle from _save_settings -- see the comment
        there for why this can't run synchronously inside Save's own
        click callback."""
        if self._refresh_job is not None:
            self.after_cancel(self._refresh_job)
            self._refresh_job = None
        if self._pulse_job is not None:
            self.after_cancel(self._pulse_job)
            self._pulse_job = None
        self.unbind_all("<MouseWheel>")  # backstop in case a rebuild lands mid-hover over the settings canvas
        for child in self.winfo_children():
            child.destroy()
        self.configure(bg=BG)
        self._setup_style()
        self._build_header()
        self._build_ui()
        self._start_refresh_loop()
        self.settings_status.set(f"Theme switched to {CURRENT_THEME}.")
        self.update_idletasks()  # force an immediate repaint rather than waiting for the next idle cycle

    @staticmethod
    def _icon_chip(parent, emoji: str, accent: str, size: int = 34) -> tk.Canvas:
        """A small rounded, accent-tinted square behind a tile's emoji --
        the desktop counterpart of the web dashboard's `.stat-icon` chip.
        Fixed size, drawn once: safe from the resize-propagation issues a
        stretchy rounded container would hit under Tkinter's geometry
        managers (see Card, further down)."""
        chip = tk.Canvas(parent, width=size, height=size, bg=SURFACE, highlightthickness=0)
        wash = _mix(SURFACE, accent, 0.18 if CURRENT_THEME == "light" else 0.28)
        chip.create_polygon(
            _rounded_rect_points(1, 1, size - 1, size - 1, 9), smooth=True, fill=wash, outline="",
        )
        chip.create_text(size / 2, size / 2 + 1, text=emoji, font=("Segoe UI Emoji", 13))
        return chip

    def _tile(self, parent, key: str, label: str, accent: bool = False) -> None:
        tile = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        tile.pack(side="left", fill="both", expand=True, padx=(0, 10))
        accent_color = SEVERITY_COLOR["high"] if accent else SERIES_BLUE
        tk.Frame(tile, bg=accent_color, height=3).pack(fill="x", side="top")
        label_row = tk.Frame(tile, bg=SURFACE)
        label_row.pack(anchor="w", padx=14, pady=(13, 0), fill="x")
        self._icon_chip(label_row, TILE_ICONS.get(key, ""), accent_color).pack(side="left")
        tk.Label(label_row, text=label, bg=SURFACE, fg=TEXT_SECONDARY, font=FONT).pack(side="left", padx=(10, 0))
        var = tk.StringVar(value="—")
        color = SEVERITY_COLOR["high"] if accent else TEXT_PRIMARY
        tk.Label(tile, textvariable=var, bg=SURFACE, fg=color, font=("Segoe UI", 26, "bold")).pack(
            anchor="w", padx=14, pady=(6, 16)
        )
        self.stat_vars[key] = var

    def _section_label(self, parent, text: str) -> None:
        row = tk.Frame(parent, bg=BG)
        row.pack(anchor="w", fill="x", pady=(4, 8))
        tk.Frame(row, bg=SERIES_BLUE, width=3, height=14).pack(side="left", padx=(0, 8))
        tk.Label(row, text=text, bg=BG, fg=TEXT_PRIMARY, font=("Segoe UI", 11, "bold")).pack(side="left")

    def _build_dashboard_tab(self, parent) -> None:
        self.stat_vars: dict[str, tk.StringVar] = {}
        stat_row = tk.Frame(parent, bg=BG)
        stat_row.pack(fill="x", pady=(0, 14))
        self._tile(stat_row, "total_events", "Total events")
        self._tile(stat_row, "total_alerts", "Total alerts")
        self._tile(stat_row, "alerts_24h", "Alerts (24h)")
        self._tile(stat_row, "high_severity", "High-severity alerts", accent=True)

        chart_row = tk.Frame(parent, bg=BG)
        chart_row.pack(fill="x", pady=(0, 14))

        line_frame = tk.Frame(chart_row, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        line_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tk.Frame(line_frame, bg=SERIES_BLUE, height=3).pack(fill="x", side="top")
        tk.Label(line_frame, text="Events over time (24h)", bg=SURFACE, fg=TEXT_PRIMARY, font=FONT_BOLD).pack(
            anchor="w", padx=16, pady=(13, 0)
        )
        self.line_chart = LineChart(line_frame, width=460, height=180)
        self.line_chart.pack(padx=16, pady=14)

        bar_frame = tk.Frame(chart_row, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        bar_frame.pack(side="left", fill="both", expand=True)
        tk.Frame(bar_frame, bg=SERIES_BLUE, height=3).pack(fill="x", side="top")
        tk.Label(bar_frame, text="Top event IDs", bg=SURFACE, fg=TEXT_PRIMARY, font=FONT_BOLD).pack(
            anchor="w", padx=16, pady=(13, 0)
        )
        self.bar_chart = BarChart(bar_frame, width=380, height=180)
        self.bar_chart.pack(padx=16, pady=14)

        # Newest first: get_recent_* already returns rows ORDER BY id DESC,
        # and inserting them in that order at Treeview position "end" puts
        # the newest row at the top with each older one pushed down below
        # it -- a live feed, not a static log tail.
        self._section_label(parent, "Recent alerts")
        alerts_card = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        alerts_card.pack(fill="x", pady=(0, 14))
        self.alerts_tree = self._make_alerts_tree(alerts_card, height=6, fill="x", expand=False)

        self._section_label(parent, "Recent events")
        events_card = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        events_card.pack(fill="both", expand=True)
        self.events_tree = self._make_events_tree(events_card, height=10)

    def _build_alerts_tab(self, parent) -> None:
        filter_row = tk.Frame(parent, bg=BG)
        filter_row.pack(fill="x", pady=(4, 10))
        tk.Label(filter_row, text="Severity:", bg=BG, fg=TEXT_SECONDARY, font=FONT).pack(side="left", padx=(0, 6))
        self.severity_filter = tk.StringVar(value="All")
        combo = ttk.Combobox(
            filter_row, textvariable=self.severity_filter, values=["All", "High", "Medium", "Low"],
            state="readonly", width=12,
        )
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", lambda e: self._refresh_alerts_tab())

        ttk.Button(filter_row, text="Block Source IP", command=self._block_selected_alert_ip).pack(
            side="left", padx=(16, 0)
        )
        self.block_status = tk.StringVar(value="")
        tk.Label(filter_row, textvariable=self.block_status, bg=BG, fg=TEXT_SECONDARY, font=FONT).pack(
            side="left", padx=(8, 0)
        )

        card = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="both", expand=True, pady=(0, 14))
        self.full_alerts_tree = self._make_alerts_tree(card, height=22)

        self._section_label(parent, "Blocked IPs")
        blocked_row = tk.Frame(parent, bg=BG)
        blocked_row.pack(fill="x", pady=(0, 6))
        ttk.Button(blocked_row, text="Unblock Selected", command=self._unblock_selected_ip).pack(side="left")

        blocked_card = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        blocked_card.pack(fill="x")
        cols = ("ip", "reason", "blocked_ts")
        widths = {"ip": 140, "reason": 300, "blocked_ts": 180}
        headings = {"ip": "IP", "reason": "Reason", "blocked_ts": "Blocked at (UTC)"}
        tree = ttk.Treeview(blocked_card, columns=cols, show="headings", height=5)
        for c in cols:
            tree.heading(c, text=headings[c])
            tree.column(c, width=widths[c], anchor="w")
        tree.pack(fill="x", padx=10, pady=10)
        self.blocked_ips_tree = tree
        self._refresh_blocked_ips()

    def _selected_alert_source_ip(self):
        """Returns (alert_id, rule_id, source_ip) for the Alerts tab's
        currently-selected row, or (None, None, None) if nothing's
        selected or that alert has no associated source IP. Looked up
        on demand (not cached at populate time) -- this only runs once
        per button click, not once per row per 5-second refresh."""
        selection = self.full_alerts_tree.selection()
        if not selection:
            return None, None, None
        alert_id = int(selection[0])
        row = self.conn.execute(
            "SELECT a.rule_id, e.source_ip FROM alerts a "
            "LEFT JOIN events e ON e.id = a.event_id_ref WHERE a.id = ?",
            (alert_id,),
        ).fetchone()
        if not row or not row["source_ip"]:
            return alert_id, (row["rule_id"] if row else None), None
        return alert_id, row["rule_id"], row["source_ip"]

    def _block_selected_alert_ip(self) -> None:
        alert_id, rule_id, ip = self._selected_alert_source_ip()
        if alert_id is None:
            self.block_status.set("Select an alert first.")
            return
        if not ip:
            self.block_status.set("That alert has no associated source IP.")
            return

        ok, reason = response.is_blockable_ip(ip)
        if not ok:
            self.block_status.set(reason)
            return

        if not messagebox.askyesno(
            "Block IP",
            f"Block all inbound and outbound traffic to/from {ip}?\n\n"
            "This adds a Windows Firewall rule immediately. You can undo it any time "
            "from the Blocked IPs list below.",
        ):
            return

        success, message = response.block_ip(self.conn, ip, reason=f"alert: {rule_id}")
        self.block_status.set(message)
        self._refresh_blocked_ips()

    def _unblock_selected_ip(self) -> None:
        selection = self.blocked_ips_tree.selection()
        if not selection:
            self.block_status.set("Select a blocked IP first.")
            return
        ip = selection[0]
        success, message = response.unblock_ip(self.conn, ip)
        self.block_status.set(message)
        self._refresh_blocked_ips()

    def _refresh_blocked_ips(self) -> None:
        tree = self.blocked_ips_tree
        tree.delete(*tree.get_children())
        for row in response.list_blocked_ips(self.conn):
            tree.insert("", "end", iid=row["ip"], values=(row["ip"], row["reason"] or "", row["blocked_ts"]))

    def _build_posture_tab(self, parent) -> None:
        top_row = tk.Frame(parent, bg=BG)
        top_row.pack(fill="x", pady=(4, 10))
        ttk.Button(top_row, text="Scan Now", command=self._run_posture_scan).pack(side="left")
        self.posture_status = tk.StringVar(value=self._posture_status_text())
        tk.Label(top_row, textvariable=self.posture_status, bg=BG, fg=TEXT_SECONDARY, font=FONT).pack(
            side="left", padx=(10, 0)
        )

        tk.Label(
            parent,
            text="Point-in-time checks of this machine's current exposure -- not events, so a finding "
                 "here means \"this is still true right now,\" not \"this happened once.\"",
            bg=BG, fg=TEXT_MUTED, font=("Segoe UI", 8), wraplength=900, justify="left",
        ).pack(anchor="w", pady=(0, 10))

        cols = ("severity", "title", "mitre", "description")
        widths = {"severity": 80, "title": 320, "mitre": 90, "description": 480}
        headings = {"severity": "Severity", "title": "Finding", "mitre": "MITRE", "description": "Description"}
        card = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="both", expand=True)

        def build(container):
            tree = ttk.Treeview(container, columns=cols, show="headings", height=28)
            for c in cols:
                tree.heading(c, text=headings[c])
                tree.column(c, width=widths[c], anchor="w", stretch=False)
            for sev, color in SEVERITY_COLOR.items():
                tree.tag_configure(f"sev-{sev}", foreground=color, font=FONT_BOLD)
            tree.tag_configure("zebra", background=_mix(SURFACE, TEXT_PRIMARY, 0.045))
            return tree

        self.posture_tree = self._with_hscroll(card, build)
        self._refresh_posture_tab()

    def _posture_status_text(self) -> str:
        ts = storage.get_last_posture_scan_ts(self.conn)
        if not ts:
            return "Never scanned."
        return f"Last scanned: {format_display_ts(ts)}"

    def _run_posture_scan(self) -> None:
        storage.replace_posture_findings(self.conn, posture.run_scan())
        self._refresh_posture_tab()

    def _refresh_posture_tab(self) -> None:
        self.posture_status.set(self._posture_status_text())
        rows = storage.get_posture_findings(self.conn)
        self.posture_tree.delete(*self.posture_tree.get_children())
        if not rows:
            return
        for i, r in enumerate(rows):
            zebra = ("zebra",) if i % 2 == 1 else ()
            self.posture_tree.insert(
                "", "end",
                values=(r["severity"].upper(), r["title"], r["mitre_id"] or "", r["description"]),
                tags=(f"sev-{r['severity']}",) + zebra,
            )

    # ------------------------------------------------------------ settings --
    def _settings_card(self, parent, title: str) -> tk.Frame:
        outer = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        outer.pack(fill="x", pady=(0, 12), padx=2)
        tk.Frame(outer, bg=SERIES_BLUE, height=3).pack(fill="x", side="top")
        tk.Label(outer, text=title, bg=SURFACE, fg=TEXT_PRIMARY, font=FONT_BOLD).pack(
            anchor="w", padx=14, pady=(12, 4)
        )
        body = tk.Frame(outer, bg=SURFACE)
        body.pack(fill="x", padx=2, pady=(0, 10))
        return body

    def _int_entry(self, parent, key: str, initial) -> ttk.Entry:
        var = tk.StringVar(value=str(initial))
        self.settings_vars[key] = var
        return ttk.Entry(parent, textvariable=var, width=10)

    def _settings_row(self, parent, row: int, label: str, widget) -> int:
        tk.Label(parent, text=label, bg=SURFACE, fg=TEXT_SECONDARY, font=FONT).grid(
            row=row, column=0, sticky="w", padx=12, pady=4
        )
        widget.grid(row=row, column=1, sticky="w", padx=(0, 12), pady=4)
        return row + 1

    def _settings_checkbox(self, parent, row: int, key: str, label: str, initial: bool) -> int:
        var = tk.BooleanVar(value=initial)
        self.settings_vars[key] = var
        ttk.Checkbutton(parent, text=label, variable=var).grid(
            row=row, column=0, columnspan=2, sticky="w", padx=12, pady=4
        )
        return row + 1

    def _build_settings_tab(self, parent) -> None:
        self.settings_vars: dict = {}

        # Save bar is a fixed footer, packed *before* the scrollable area
        # below claims the remaining space -- it stays visible regardless
        # of scroll position instead of being buried at the bottom of a
        # long list of cards where it's easy to miss entirely.
        footer = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        footer.pack(side="bottom", fill="x")
        footer_inner = tk.Frame(footer, bg=SURFACE)
        footer_inner.pack(fill="x", padx=12, pady=10)
        ttk.Button(footer_inner, text="Save Settings", command=self._save_settings).pack(side="left")
        self.settings_status = tk.StringVar(value="")
        tk.Label(footer_inner, textvariable=self.settings_status, bg=SURFACE, fg="#0ca30c", font=FONT).pack(
            side="left", padx=(10, 0)
        )

        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=BG)
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True, pady=(4, 0))
        scrollbar.pack(side="right", fill="y")

        # Mouse-wheel scrolling: bind_all is normally risky (a global
        # binding that can outlive the widget across a theme rebuild), so
        # this only holds the binding while the cursor is actually over
        # the canvas -- bound on <Enter>, released on <Leave>. _rebuild_theme
        # also unconditionally unbinds before tearing down, as a backstop
        # for the case where a rebuild happens mid-hover.
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

        cfg = self.config

        # --- Appearance ---
        card = self._settings_card(scroll_frame, "Appearance")
        theme_var = tk.StringVar(value=cfg.get("ui", {}).get("theme", "light"))
        self.settings_vars["ui.theme"] = theme_var
        row = self._settings_row(
            card, 0, "Theme",
            ttk.Combobox(card, textvariable=theme_var, values=["light", "dark"], state="readonly", width=12),
        )
        tz_var = tk.StringVar(value=cfg.get("ui", {}).get("timezone", "UTC"))
        self.settings_vars["ui.timezone"] = tz_var
        self._settings_row(
            card, row, "Display timezone",
            ttk.Combobox(card, textvariable=tz_var, values=["UTC", "Local"], state="readonly", width=12),
        )

        # --- Notifications ---
        card = self._settings_card(scroll_frame, "Notifications")
        nf = cfg.get("notifications", {})
        row = self._settings_checkbox(
            card, 0, "notifications.enabled",
            "Show a Windows notification when an alert fires", nf.get("enabled", True),
        )
        min_sev_var = tk.StringVar(value=nf.get("min_severity", "high").capitalize())
        self.settings_vars["notifications.min_severity"] = min_sev_var
        self._settings_row(
            card, row, "Minimum severity",
            ttk.Combobox(card, textvariable=min_sev_var, values=["Low", "Medium", "High"], state="readonly", width=12),
        )

        # --- Alert correlation ---
        card = self._settings_card(scroll_frame, "Alert Correlation")
        co = cfg.get("correlation", {})
        row = self._settings_checkbox(
            card, 0, "correlation.enabled",
            "Chain related alerts from the same user/IP into one high-severity alert", co.get("enabled", True),
        )
        row = self._settings_row(card, row, "Time window (minutes)",
                                  self._int_entry(card, "correlation.window_minutes", co.get("window_minutes", 15)))
        row = self._settings_row(card, row, "Minimum distinct signals",
                                  self._int_entry(card, "correlation.min_signals", co.get("min_signals", 2)))

        # --- Detection rules ---
        card = self._settings_card(scroll_frame, "Detection Rules")
        d = cfg.get("detections", {})
        row = 0
        row = self._settings_checkbox(card, row, "detections.brute_force.enabled",
                                       "Brute force login detection", d.get("brute_force", {}).get("enabled", True))
        row = self._settings_checkbox(card, row, "detections.new_admin_account.enabled",
                                       "New / escalated admin accounts", d.get("new_admin_account", {}).get("enabled", True))
        row = self._settings_checkbox(card, row, "detections.afterhours_logon.enabled",
                                       "After-hours logon", d.get("afterhours_logon", {}).get("enabled", True))
        row = self._settings_checkbox(card, row, "detections.encoded_powershell.enabled",
                                       "Encoded PowerShell", d.get("encoded_powershell", {}).get("enabled", True))
        row = self._settings_checkbox(card, row, "detections.suspicious_parent_child.enabled",
                                       "Office app spawns a shell", d.get("suspicious_parent_child", {}).get("enabled", True))
        row = self._settings_checkbox(card, row, "detections.threat_intel_match.enabled",
                                       "Threat intel IOC match", d.get("threat_intel_match", {}).get("enabled", True))
        row = self._settings_checkbox(card, row, "detections.port_scan_detection.enabled",
                                       "Port scan / active reconnaissance", d.get("port_scan_detection", {}).get("enabled", True))
        row = self._settings_checkbox(card, row, "detections.powershell_scriptblock.enabled",
                                       "PowerShell script block obfuscation", d.get("powershell_scriptblock", {}).get("enabled", True))
        row = self._settings_checkbox(card, row, "detections.credential_access.enabled",
                                       "LSASS credential access (T1003)", d.get("credential_access", {}).get("enabled", True))
        row = self._settings_checkbox(card, row, "detections.persistence.enabled",
                                       "New scheduled task / service", d.get("persistence", {}).get("enabled", True))

        bf = d.get("brute_force", {})
        row = self._settings_row(card, row, "Brute force threshold (failed logons)",
                                  self._int_entry(card, "detections.brute_force.threshold", bf.get("threshold", 5)))
        row = self._settings_row(card, row, "Brute force window (seconds)",
                                  self._int_entry(card, "detections.brute_force.window_seconds", bf.get("window_seconds", 300)))
        ah = d.get("afterhours_logon", {})
        row = self._settings_row(card, row, "Business hours start (UTC)",
                                  self._int_entry(card, "detections.afterhours_logon.business_hours_start", ah.get("business_hours_start", 7)))
        row = self._settings_row(card, row, "Business hours end (UTC)",
                                  self._int_entry(card, "detections.afterhours_logon.business_hours_end", ah.get("business_hours_end", 19)))
        ps = d.get("port_scan_detection", {})
        row = self._settings_row(card, row, "Port scan: distinct ports threshold",
                                  self._int_entry(card, "detections.port_scan_detection.distinct_ports_threshold", ps.get("distinct_ports_threshold", 10)))
        row = self._settings_row(card, row, "Port scan: window (seconds)",
                                  self._int_entry(card, "detections.port_scan_detection.window_seconds", ps.get("window_seconds", 30)))
        tk.Label(
            card, text="Requires Windows audit policy for blocked connections -- enabled automatically on save.",
            bg=SURFACE, fg=TEXT_MUTED, font=("Segoe UI", 8),
        ).grid(row=row, column=0, columnspan=3, sticky="w", padx=12, pady=(0, 8))
        row += 1
        tk.Label(
            card, text="New scheduled task also requires an audit policy -- enabled automatically on save. "
                       "PowerShell script block logging and LSASS access monitoring need one-time manual setup; see README.",
            bg=SURFACE, fg=TEXT_MUTED, font=("Segoe UI", 8), wraplength=520, justify="left",
        ).grid(row=row, column=0, columnspan=3, sticky="w", padx=12, pady=(0, 8))
        row += 1

        # --- Retention ---
        card = self._settings_card(scroll_frame, "Log Retention")
        r = cfg.get("retention", {})
        row = self._settings_checkbox(card, 0, "retention.enabled", "Automatically purge old data", r.get("enabled", True))
        row = self._settings_row(card, row, "Keep events for (days)",
                                  self._int_entry(card, "retention.events_retention_days", r.get("events_retention_days", 30)))
        row = self._settings_row(card, row, "Keep alerts for (days)",
                                  self._int_entry(card, "retention.alerts_retention_days", r.get("alerts_retention_days", 365)))
        self._settings_row(card, row, "Check interval (hours)",
                            self._int_entry(card, "retention.check_interval_hours", r.get("check_interval_hours", 24)))

        # --- Threat intel ---
        card = self._settings_card(scroll_frame, "Threat Intelligence (abuse.ch ThreatFox)")
        ti = cfg.get("threat_intel", {})
        row = self._settings_checkbox(card, 0, "threat_intel.enabled", "Enable threat intel feed", ti.get("enabled", False))

        api_key_var = tk.StringVar(value=ti.get("api_key") or "")
        self.settings_vars["threat_intel.api_key"] = api_key_var
        tk.Label(card, text="Auth-Key", bg=SURFACE, fg=TEXT_SECONDARY, font=FONT).grid(
            row=row, column=0, sticky="w", padx=12, pady=4
        )
        key_entry = ttk.Entry(card, textvariable=api_key_var, width=26, show="•")
        key_entry.grid(row=row, column=1, sticky="w", pady=4)
        show_btn = ttk.Button(card, text="Show", width=6)
        show_btn.grid(row=row, column=2, sticky="w", padx=(6, 12), pady=4)

        def _toggle_key_visibility():
            hidden = key_entry.cget("show") == "•"
            key_entry.configure(show="" if hidden else "•")
            show_btn.configure(text="Hide" if hidden else "Show")

        show_btn.configure(command=_toggle_key_visibility)
        row += 1
        tk.Label(
            card, text="Free key: sign in at auth.abuse.ch with an existing Google/GitHub/LinkedIn/X account.",
            bg=SURFACE, fg=TEXT_MUTED, font=("Segoe UI", 8),
        ).grid(row=row, column=0, columnspan=3, sticky="w", padx=12, pady=(0, 8))
        row += 1

        row = self._settings_row(card, row, "Refresh interval (hours)",
                                  self._int_entry(card, "threat_intel.refresh_interval_hours", ti.get("refresh_interval_hours", 24)))
        self._settings_row(card, row, "Lookback window (days)",
                            self._int_entry(card, "threat_intel.lookback_days", ti.get("lookback_days", 3)))

        # --- Collector ---
        card = self._settings_card(scroll_frame, "Collector (requires restart to take effect)")
        self._settings_row(card, 0, "Poll interval (seconds)",
                            self._int_entry(card, "poll_interval_seconds", cfg.get("poll_interval_seconds", 5)))

        tk.Frame(scroll_frame, bg=BG, height=8).pack()  # breathing room above the fixed footer

    def _save_settings(self) -> None:
        try:
            self._do_save_settings()
        except Exception:
            # This runs inside a button-click callback dispatched by Tcl --
            # an uncaught exception here gets silently swallowed by
            # Tkinter's default report_callback_exception (a stderr print),
            # which is completely invisible when launched via pythonw.exe
            # (no console). Surface it in the UI instead of losing it.
            import traceback

            traceback.print_exc()
            try:
                self.settings_status.set("Something went wrong saving settings -- see logs.")
            except tk.TclError:
                pass  # the widget itself may be mid-destroy; nothing more we can do

    def _do_save_settings(self) -> None:
        v = self.settings_vars
        try:
            overlay = {
                "poll_interval_seconds": int(v["poll_interval_seconds"].get()),
                "detections": {
                    "brute_force": {
                        "enabled": v["detections.brute_force.enabled"].get(),
                        "threshold": int(v["detections.brute_force.threshold"].get()),
                        "window_seconds": int(v["detections.brute_force.window_seconds"].get()),
                    },
                    "new_admin_account": {"enabled": v["detections.new_admin_account.enabled"].get()},
                    "afterhours_logon": {
                        "enabled": v["detections.afterhours_logon.enabled"].get(),
                        "business_hours_start": int(v["detections.afterhours_logon.business_hours_start"].get()),
                        "business_hours_end": int(v["detections.afterhours_logon.business_hours_end"].get()),
                    },
                    "encoded_powershell": {"enabled": v["detections.encoded_powershell.enabled"].get()},
                    "suspicious_parent_child": {"enabled": v["detections.suspicious_parent_child.enabled"].get()},
                    "threat_intel_match": {"enabled": v["detections.threat_intel_match.enabled"].get()},
                    "port_scan_detection": {
                        "enabled": v["detections.port_scan_detection.enabled"].get(),
                        "distinct_ports_threshold": int(v["detections.port_scan_detection.distinct_ports_threshold"].get()),
                        "window_seconds": int(v["detections.port_scan_detection.window_seconds"].get()),
                    },
                    "powershell_scriptblock": {"enabled": v["detections.powershell_scriptblock.enabled"].get()},
                    "credential_access": {"enabled": v["detections.credential_access.enabled"].get()},
                    "persistence": {"enabled": v["detections.persistence.enabled"].get()},
                },
                "retention": {
                    "enabled": v["retention.enabled"].get(),
                    "events_retention_days": int(v["retention.events_retention_days"].get()),
                    "alerts_retention_days": int(v["retention.alerts_retention_days"].get()),
                    "check_interval_hours": int(v["retention.check_interval_hours"].get()),
                },
                "threat_intel": {
                    "enabled": v["threat_intel.enabled"].get(),
                    "refresh_interval_hours": int(v["threat_intel.refresh_interval_hours"].get()),
                    "lookback_days": int(v["threat_intel.lookback_days"].get()),
                },
                "ui": {"theme": v["ui.theme"].get(), "timezone": v["ui.timezone"].get()},
                "notifications": {
                    "enabled": v["notifications.enabled"].get(),
                    "min_severity": v["notifications.min_severity"].get().lower(),
                },
                "correlation": {
                    "enabled": v["correlation.enabled"].get(),
                    "window_minutes": int(v["correlation.window_minutes"].get()),
                    "min_signals": int(v["correlation.min_signals"].get()),
                },
            }
        except ValueError:
            self.settings_status.set("Invalid number in one of the fields -- not saved.")
            return

        new_poll_interval = overlay["poll_interval_seconds"]
        api_key = v["threat_intel.api_key"].get().strip()

        # Mutate the live config in place: the collector thread holds this
        # exact dict object, so it picks up rule/retention/threat-intel
        # changes on its next loop iteration -- no restart needed for those.
        deep_merge_in_place(self.config, overlay)
        self.config["threat_intel"]["api_key"] = api_key or None

        save_user_settings(self._app_dir, overlay)
        secrets_loader.save(self._app_dir, {"threatfox_api_key": api_key} if api_key else {})
        engine.configure(self.config)
        alerts.configure(self.config)
        correlation.configure(self.config)

        if overlay["detections"]["port_scan_detection"]["enabled"]:
            audit_policy.ensure_failure_auditing_enabled()
        if overlay["detections"]["persistence"]["enabled"]:
            audit_policy.ensure_object_access_auditing_enabled()

        # Timezone applies on its own -- no rebuild needed, since the
        # tables reformat every timestamp fresh on each refresh cycle.
        apply_timezone(overlay["ui"]["timezone"])

        messages = ["Saved."]
        if new_poll_interval != self._initial_poll_interval:
            messages.append("Restart the app for the new poll interval to take effect.")

        if overlay["ui"]["theme"] != CURRENT_THEME:
            apply_theme(overlay["ui"]["theme"])
            # Defer the destroy-and-rebuild to the next event-loop tick
            # rather than doing it synchronously here: this method is
            # running *inside* the Save button's own click callback, and
            # that button is one of the widgets about to be destroyed.
            # Destroying a widget mid-callback is a well-known Tkinter
            # footgun -- schedule it for right after this callback returns
            # instead, once Tcl has finished dispatching the click.
            self.after_idle(self._rebuild_theme)
            return  # rebuilt UI has a fresh settings_status var; nothing left to update here

        self.settings_status.set(" ".join(messages))

    # ---------------------------------------------------------------- tables --
    @staticmethod
    def _time_heading() -> str:
        return f"Time ({CURRENT_TIMEZONE})"

    @staticmethod
    def _with_hscroll(parent, build_tree, fill: str = "both", expand: bool = True) -> ttk.Treeview:
        """Wraps a Treeview-building callback with a horizontal scrollbar
        docked underneath it. Columns are fixed-width (stretch=False, set
        by each caller) rather than auto-fitting the pane, so a narrow
        window scrolls the feed sideways instead of squeezing every
        column down to unreadable slivers. Owns its own packing (into
        `parent`, with 10px breathing room) -- callers just use the
        returned Treeview, they don't pack it themselves."""
        container = tk.Frame(parent, bg=SURFACE)
        container.pack(fill=fill, expand=expand, padx=10, pady=10)
        tree = build_tree(container)
        hscroll = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(xscrollcommand=hscroll.set)
        hscroll.pack(side="bottom", fill="x")
        tree.pack(side="top", fill="both", expand=True)
        return tree

    def _make_alerts_tree(self, parent, height: int, fill: str = "both", expand: bool = True) -> ttk.Treeview:
        cols = ("time", "severity", "mitre", "rule", "description")
        widths = {"time": 150, "severity": 80, "mitre": 90, "rule": 150, "description": 420}
        headings = {"time": self._time_heading(), "severity": "Severity", "mitre": "MITRE", "rule": "Rule", "description": "Description"}

        def build(container):
            tree = ttk.Treeview(container, columns=cols, show="headings", height=height)
            for c in cols:
                tree.heading(c, text=headings[c])
                tree.column(c, width=widths[c], anchor="w", stretch=False)
            for sev, color in SEVERITY_COLOR.items():
                tree.tag_configure(f"sev-{sev}", foreground=color, font=FONT_BOLD)
            tree.tag_configure("zebra", background=_mix(SURFACE, TEXT_PRIMARY, 0.045))
            return tree

        return self._with_hscroll(parent, build, fill=fill, expand=expand)

    def _make_events_tree(self, parent, height: int, fill: str = "both", expand: bool = True) -> ttk.Treeview:
        cols = ("time", "channel", "event_id", "level", "user", "source", "message")
        widths = {"time": 150, "channel": 90, "event_id": 70, "level": 80, "user": 110, "source": 120, "message": 380}
        headings = {
            "time": self._time_heading(), "channel": "Channel", "event_id": "Event ID", "level": "Level",
            "user": "User", "source": "Source", "message": "Message",
        }

        def build(container):
            tree = ttk.Treeview(container, columns=cols, show="headings", height=height)
            for c in cols:
                tree.heading(c, text=headings[c])
                tree.column(c, width=widths[c], anchor="w", stretch=False)
            tree.tag_configure("zebra", background=_mix(SURFACE, TEXT_PRIMARY, 0.045))
            return tree

        return self._with_hscroll(parent, build, fill=fill, expand=expand)

    @staticmethod
    def _populate_alerts_tree(tree: ttk.Treeview, rows) -> None:
        tree.heading("time", text=App._time_heading())
        tree.delete(*tree.get_children())
        for i, r in enumerate(rows):
            zebra = ("zebra",) if i % 2 == 1 else ()
            tree.insert(
                "", "end", iid=str(r["id"]),
                values=(format_display_ts(r["ts"]), r["severity"].upper(), r["mitre_id"], r["rule_id"], r["description"]),
                tags=(f"sev-{r['severity']}",) + zebra,
            )

    @staticmethod
    def _populate_events_tree(tree: ttk.Treeview, rows) -> None:
        tree.heading("time", text=App._time_heading())
        tree.delete(*tree.get_children())
        for i, r in enumerate(rows):
            zebra = ("zebra",) if i % 2 == 1 else ()
            tree.insert(
                "", "end",
                values=(
                    format_display_ts(r["ts"]), r["channel"], r["event_id"], r["level"],
                    r["user"], r["source_ip"], r["message"],
                ),
                tags=zebra,
            )

    # ------------------------------------------------------------- refresh --
    def _start_refresh_loop(self) -> None:
        """Runs once immediately, then reschedules itself. Tracked via
        self._refresh_job so a theme-switch rebuild can cancel the pending
        callback instead of accidentally stacking a second, parallel
        refresh loop on top of it."""
        self._do_refresh()

    def _do_refresh(self) -> None:
        try:
            self._refresh_stats()
            self._refresh_charts()
            self._populate_alerts_tree(self.alerts_tree, storage.get_recent_alerts(self.conn, 10))
            self._populate_events_tree(self.events_tree, storage.get_recent_events(self.conn, 25))
            self._refresh_alerts_tab()
            self._refresh_posture_tab()
        except Exception:
            pass  # a transient DB hiccup shouldn't kill the whole app
        self._refresh_job = self.after(POLL_MS, self._do_refresh)

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
        self._refresh_blocked_ips()


def main() -> None:
    if not is_admin():
        relaunch_as_admin()
        return

    # pythonw.exe (what the desktop shortcut uses) has no console at all --
    # without a log file, a startup crash before the Tkinter window even
    # appears would be completely invisible.
    logging_setup.configure_logging(app_dir())
    logging.getLogger("desktop_app").info("Starting pysentinel-siem desktop app.")

    cfg_path = os.path.join(app_dir(), "config.yaml")
    ensure_config(cfg_path)
    with open(cfg_path) as f:
        config = yaml.safe_load(f)

    deep_merge_in_place(config, load_user_settings(app_dir()))

    secrets = secrets_loader.load(app_dir())
    config.setdefault("threat_intel", {})["api_key"] = secrets.get("threatfox_api_key")

    apply_theme(config.get("ui", {}).get("theme", "light"))
    apply_timezone(config.get("ui", {}).get("timezone", "UTC"))

    if config.get("detections", {}).get("port_scan_detection", {}).get("enabled", True):
        audit_policy.ensure_failure_auditing_enabled()
    if config.get("detections", {}).get("persistence", {}).get("enabled", True):
        audit_policy.ensure_object_access_auditing_enabled()

    db_path = config.get("db_path", "siem.db")
    if not os.path.isabs(db_path):
        db_path = os.path.join(app_dir(), db_path)

    engine.configure(config)
    alerts.configure(config)
    correlation.configure(config)

    collector_conn = storage.connect(db_path)
    storage.init_db(collector_conn)
    # Restricts siem.db (the full local telemetry history) to this
    # Windows user only -- see siem/file_security.py. Once at startup,
    # not per-connection.
    file_security.restrict_to_current_user(db_path)
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
    App(gui_conn, config, app_dir()).mainloop()


if __name__ == "__main__":
    main()
