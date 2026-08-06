import pytest

from siem import collector


class _StopLoop(Exception):
    """Raised from a mocked time.sleep to escape run_forever's infinite
    loop after a fixed number of iterations, so it's testable at all."""


def test_run_forever_survives_an_exception_in_poll_once(monkeypatch):
    """A poll_once failure must not kill the collector loop -- it should
    log and keep going, per siem/collector.py's own resilience comment."""
    calls = {"poll": 0, "sleep": 0}

    def fake_poll_once(conn, channels):
        calls["poll"] += 1
        if calls["poll"] == 1:
            raise RuntimeError("simulated transient failure")
        return 0

    def fake_sleep(seconds):
        calls["sleep"] += 1
        if calls["sleep"] >= 3:
            raise _StopLoop

    monkeypatch.setattr(collector, "poll_once", fake_poll_once)
    monkeypatch.setattr(collector.time, "sleep", fake_sleep)

    with pytest.raises(_StopLoop):
        collector.run_forever(conn=None, channels=["Security"], poll_interval_seconds=1)

    # First iteration raised and was caught; the loop still reached a
    # second and third poll_once call rather than stopping after the error.
    assert calls["poll"] >= 3


def test_run_forever_backs_off_after_repeated_failures(monkeypatch):
    """Five consecutive failures should trigger the longer backoff sleep
    (poll_interval * consecutive_failures, capped at 300s) instead of the
    normal per-cycle sleep."""
    sleep_durations = []

    def always_fails(conn, channels):
        raise RuntimeError("persistently broken")

    def fake_sleep(seconds):
        sleep_durations.append(seconds)
        if len(sleep_durations) >= 5:
            raise _StopLoop

    monkeypatch.setattr(collector, "poll_once", always_fails)
    monkeypatch.setattr(collector.time, "sleep", fake_sleep)

    with pytest.raises(_StopLoop):
        collector.run_forever(conn=None, channels=["Security"], poll_interval_seconds=2)

    # The 5th consecutive failure crosses the backoff threshold: sleep(min(2*5, 300)) = 10,
    # not the plain per-cycle interval (2).
    assert sleep_durations[4] == 10


def test_run_forever_resets_failure_count_on_success(monkeypatch):
    """A successful cycle between failures should reset the counter, so an
    occasional blip doesn't creep toward the backoff threshold."""
    calls = {"poll": 0, "sleep": 0}

    def flaky(conn, channels):
        calls["poll"] += 1
        if calls["poll"] % 2 == 1:
            raise RuntimeError("intermittent")
        return 0

    def fake_sleep(seconds):
        calls["sleep"] += 1
        # Every sleep here must be the plain per-cycle interval (1) -- if
        # the failure counter weren't resetting, repeated failures would
        # eventually trip the backoff branch and this would see a longer
        # sleep instead.
        assert seconds == 1
        if calls["sleep"] >= 8:
            raise _StopLoop

    monkeypatch.setattr(collector, "poll_once", flaky)
    monkeypatch.setattr(collector.time, "sleep", fake_sleep)

    with pytest.raises(_StopLoop):
        collector.run_forever(conn=None, channels=["Security"], poll_interval_seconds=1)
