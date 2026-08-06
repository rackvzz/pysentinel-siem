"""Native Windows notifications for high-severity alerts.

Uses win32gui.Shell_NotifyIcon rather than pulling in a separate toast
package: pywin32 is already a hard dependency (siem/collector.py needs it
for the Evt* event log API), and on Windows 10/11 a Shell_NotifyIcon
balloon notification is transparently rendered as a real Action Center
toast -- no extra package, no extra install step.

A single hidden message-only window owns one persistent tray icon for the
life of the process; each notification just updates that icon's balloon
text (NIM_MODIFY + NIF_INFO) instead of creating a new icon per alert.
Every public entrypoint here swallows its own errors -- a notification
failing to show is never allowed to take detection down with it, the same
principle as siem/collector.py's per-rule exception handling.
"""

import logging

import win32api
import win32con
import win32gui

logger = logging.getLogger("siem.notifier")

_WNDCLASS_NAME = "PysentinelSiemNotifierWindow"
_ICON_ID = 1

# None = not yet attempted. A real int hwnd = ready. False = tried and
# failed once already -- don't retry every single call after that (e.g. no
# desktop session attached, as can happen for a service-run collector).
_state: dict = {"hwnd": None}


def _wnd_proc(hwnd, msg, wparam, lparam):
    return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)


def _ensure_icon() -> bool:
    if _state["hwnd"] is False:
        return False
    if _state["hwnd"] is not None:
        return True
    try:
        hinst = win32api.GetModuleHandle(None)
        wnd_class = win32gui.WNDCLASS()
        wnd_class.hInstance = hinst
        wnd_class.lpszClassName = _WNDCLASS_NAME
        wnd_class.lpfnWndProc = _wnd_proc
        class_atom = win32gui.RegisterClass(wnd_class)
        hwnd = win32gui.CreateWindow(
            class_atom, _WNDCLASS_NAME, 0, 0, 0, 0, 0, 0, 0, hinst, None
        )
        hicon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)
        win32gui.Shell_NotifyIcon(
            win32gui.NIM_ADD,
            (hwnd, _ICON_ID, win32gui.NIF_ICON | win32gui.NIF_TIP, 0, hicon, "pysentinel-siem"),
        )
        _state["hwnd"] = hwnd
        return True
    except Exception:
        logger.exception("Could not create the notification tray icon -- notifications disabled this session.")
        _state["hwnd"] = False
        return False


_SEVERITY_ICON = {
    "high": "NIIF_ERROR",
    "medium": "NIIF_WARNING",
    "low": "NIIF_INFO",
}


def notify(title: str, message: str, severity: str = "high") -> None:
    """Best-effort native Windows notification. Never raises."""
    if not _ensure_icon():
        return
    try:
        info_icon = getattr(win32gui, _SEVERITY_ICON.get(severity, "NIIF_INFO"))
        win32gui.Shell_NotifyIcon(
            win32gui.NIM_MODIFY,
            (
                _state["hwnd"], _ICON_ID, win32gui.NIF_INFO,
                0, 0, "",
                message, 10000, title, info_icon,
            ),
        )
    except Exception:
        logger.exception("Failed to show a notification balloon.")


def notify_alert(rule_id: str, severity: str, description: str) -> None:
    """Convenience wrapper siem/alerts.py calls directly -- keeps the
    title/message formatting decision in one place."""
    title = f"pysentinel-siem: {severity.upper()} severity alert"
    notify(title, f"{rule_id}: {description}", severity=severity)
