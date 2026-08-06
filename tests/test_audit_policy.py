from siem import audit_policy


def test_is_failure_auditing_enabled_returns_none_when_not_elevated():
    # This test suite doesn't run elevated, so auditpol should fail
    # with "required privilege not held" -- the function should return
    # None (unknown), not raise.
    result = audit_policy.is_failure_auditing_enabled()
    assert result is None


def test_ensure_failure_auditing_enabled_returns_false_when_not_elevated():
    # Same as above: can't actually set the policy without elevation,
    # should fail gracefully and report False rather than raising.
    result = audit_policy.ensure_failure_auditing_enabled()
    assert result is False


def test_ensure_failure_auditing_enabled_short_circuits_when_already_on(monkeypatch):
    monkeypatch.setattr(audit_policy, "is_failure_auditing_enabled", lambda: True)
    # If it's already enabled, ensure_* should return True immediately
    # without needing to actually invoke auditpol /set at all.
    called = []
    monkeypatch.setattr(
        audit_policy.subprocess, "run",
        lambda *a, **k: called.append(a) or (_ for _ in ()).throw(AssertionError("should not be called")),
    )
    assert audit_policy.ensure_failure_auditing_enabled() is True
    assert called == []


def test_is_object_access_auditing_enabled_returns_none_when_not_elevated():
    # Same real (unmocked) auditpol call as the failure-auditing test
    # above, against the other subcategory persistence.py needs.
    assert audit_policy.is_object_access_auditing_enabled() is None


def test_ensure_object_access_auditing_enabled_returns_false_when_not_elevated():
    assert audit_policy.ensure_object_access_auditing_enabled() is False


def test_ensure_object_access_auditing_enabled_short_circuits_when_already_on(monkeypatch):
    monkeypatch.setattr(audit_policy, "is_object_access_auditing_enabled", lambda: True)
    called = []
    monkeypatch.setattr(
        audit_policy.subprocess, "run",
        lambda *a, **k: called.append(a) or (_ for _ in ()).throw(AssertionError("should not be called")),
    )
    assert audit_policy.ensure_object_access_auditing_enabled() is True
    assert called == []


def test_object_access_auditing_uses_its_own_subcategory_and_success_type(monkeypatch):
    # Regression guard for the refactor that generalized is_*/_ensure_*
    # to take subcategory + audit_type as parameters: the two
    # subcategories must never bleed into each other's auditpol calls.
    calls = []

    def fake_run(args, **kw):
        calls.append(args)

        class Result:
            returncode = 0
            stdout = f"{audit_policy.OBJECT_ACCESS_SUBCATEGORY}          Success\n"
            stderr = ""

        return Result()

    monkeypatch.setattr(audit_policy.subprocess, "run", fake_run)
    assert audit_policy.is_object_access_auditing_enabled() is True
    assert any(f"/subcategory:{audit_policy.OBJECT_ACCESS_SUBCATEGORY}" in a for a in calls[-1])
