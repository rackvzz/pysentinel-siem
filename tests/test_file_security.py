import tempfile
import os

import pytest

from siem import file_security


@pytest.fixture
def tmp_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


def test_returns_false_for_nonexistent_file():
    assert file_security.restrict_to_current_user(r"C:\definitely\does\not\exist.txt") is False


def test_calls_icacls_with_expected_flags(tmp_file, monkeypatch):
    calls = []

    def fake_run(args, **kw):
        calls.append(args)
        class R:
            returncode = 0
            stdout = "Successfully processed 1 files.\n"
            stderr = ""
        return R()

    monkeypatch.setattr(file_security.subprocess, "run", fake_run)
    monkeypatch.setattr(file_security.os.environ, "get", lambda k, d=None: {"USERNAME": "alice", "USERDOMAIN": "HOST"}.get(k, d))

    assert file_security.restrict_to_current_user(tmp_file) is True
    assert len(calls) == 1
    args = calls[0]
    assert tmp_file in args
    assert "/inheritance:r" in args
    assert any(a == "HOST\\alice:F" for a in args)


def test_returns_false_on_icacls_failure(tmp_file, monkeypatch):
    def fake_run(args, **kw):
        class R:
            returncode = 1
            stdout = ""
            stderr = "Access is denied."
        return R()

    monkeypatch.setattr(file_security.subprocess, "run", fake_run)
    assert file_security.restrict_to_current_user(tmp_file) is False


def test_never_raises_when_icacls_is_missing(tmp_file, monkeypatch):
    def fake_run(*a, **kw):
        raise OSError("icacls.exe not found")

    monkeypatch.setattr(file_security.subprocess, "run", fake_run)
    assert file_security.restrict_to_current_user(tmp_file) is False


def test_real_icacls_call_against_a_real_temp_file(tmp_file):
    # One real (unmocked) end-to-end call, matching the project's existing
    # pattern (audit_policy.py's tests do the same) of also exercising the
    # actual Windows tool at least once, not just the mocked paths.
    result = file_security.restrict_to_current_user(tmp_file)
    assert result is True
