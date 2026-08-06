from siem import alerts, correlation, notifier


def _reset_notifier_state():
    notifier._state["hwnd"] = None


def test_notify_alert_never_raises_when_shell_notify_icon_fails(monkeypatch):
    """notify()/notify_alert() are best-effort -- a Windows notification
    failing (no desktop session, API error, whatever) must never propagate
    into the caller (siem/alerts.py's raise_alert)."""
    _reset_notifier_state()

    def _raise(*a, **kw):
        raise OSError("no desktop session")

    monkeypatch.setattr(notifier.win32api, "GetModuleHandle", _raise)
    # Should not raise.
    notifier.notify_alert("brute_force", "high", "5 failed logons from 203.0.113.5")
    _reset_notifier_state()


def test_ensure_icon_only_retries_once_after_failure(monkeypatch):
    _reset_notifier_state()
    calls = {"n": 0}

    def _raise(*a, **kw):
        calls["n"] += 1
        raise OSError("boom")

    monkeypatch.setattr(notifier.win32api, "GetModuleHandle", _raise)
    assert notifier._ensure_icon() is False
    assert notifier._ensure_icon() is False
    # Second call short-circuits on the cached False sentinel rather than
    # retrying the (already-failed) window/icon setup every time.
    assert calls["n"] == 1
    _reset_notifier_state()


def test_notify_calls_shell_notify_icon_with_expected_severity_icon(monkeypatch):
    _reset_notifier_state()
    monkeypatch.setattr(notifier.win32api, "GetModuleHandle", lambda *_: 1)
    monkeypatch.setattr(notifier.win32gui, "WNDCLASS", lambda: type("WC", (), {})())
    monkeypatch.setattr(notifier.win32gui, "RegisterClass", lambda *_: "atom")
    monkeypatch.setattr(notifier.win32gui, "CreateWindow", lambda *a, **kw: 12345)
    monkeypatch.setattr(notifier.win32gui, "LoadIcon", lambda *_: 1)

    calls = []
    monkeypatch.setattr(notifier.win32gui, "Shell_NotifyIcon", lambda action, nid: calls.append((action, nid)))

    notifier.notify("pysentinel-siem: HIGH severity alert", "brute_force: 5 failed logons", severity="high")

    assert len(calls) == 2  # NIM_ADD (icon setup) then NIM_MODIFY (the balloon)
    modify_action, modify_nid = calls[-1]
    assert modify_action == notifier.win32gui.NIM_MODIFY
    assert modify_nid[6] == "brute_force: 5 failed logons"  # info (balloon body)
    assert modify_nid[8] == "pysentinel-siem: HIGH severity alert"  # info_title
    assert modify_nid[9] == notifier.win32gui.NIIF_ERROR  # high -> NIIF_ERROR
    _reset_notifier_state()


def test_raise_alert_notifies_only_at_or_above_min_severity(monkeypatch):
    calls = []
    monkeypatch.setattr(notifier, "notify_alert", lambda rule_id, severity, description: calls.append(severity))

    class FakeConn:
        def execute(self, *a, **kw):
            class R:
                def fetchone(self_inner):
                    return {"n": 1}
            return R()

        def commit(self):
            pass

    monkeypatch.setattr(alerts.storage, "insert_alert", lambda conn, alert: 1)
    # These tests exercise the notify-threshold logic only -- correlation
    # needs a real DB (it joins alerts to events), so it's stubbed out
    # here rather than given a fake connection it can't actually query.
    monkeypatch.setattr(correlation, "check", lambda *a, **kw: None)

    alerts.configure({"notifications": {"enabled": True, "min_severity": "medium"}})
    alerts.raise_alert(FakeConn(), "afterhours_logon", "T1078", "low", "desc", 1)
    alerts.raise_alert(FakeConn(), "new_admin_account", "T1136", "medium", "desc", 1)
    alerts.raise_alert(FakeConn(), "brute_force", "T1110", "high", "desc", 1)

    # "low" is below the medium threshold and shouldn't notify; medium/high should.
    assert calls == ["medium", "high"]


def test_raise_alert_respects_notifications_disabled(monkeypatch):
    calls = []
    monkeypatch.setattr(notifier, "notify_alert", lambda rule_id, severity, description: calls.append(severity))
    monkeypatch.setattr(alerts.storage, "insert_alert", lambda conn, alert: 1)
    monkeypatch.setattr(correlation, "check", lambda *a, **kw: None)

    alerts.configure({"notifications": {"enabled": False, "min_severity": "low"}})
    alerts.raise_alert(None, "brute_force", "T1110", "high", "desc", 1)

    assert calls == []
    alerts.configure({})  # restore defaults for any later test relying on them
