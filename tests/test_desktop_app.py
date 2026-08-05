import datetime

import desktop_app
from desktop_app import apply_timezone, deep_merge_in_place, format_display_ts


def test_deep_merge_in_place_overwrites_scalars():
    base = {"a": 1, "b": 2}
    deep_merge_in_place(base, {"a": 99})
    assert base == {"a": 99, "b": 2}


def test_deep_merge_in_place_merges_nested_dicts():
    base = {"retention": {"enabled": True, "events_retention_days": 30}}
    deep_merge_in_place(base, {"retention": {"events_retention_days": 7}})
    assert base == {"retention": {"enabled": True, "events_retention_days": 7}}


def test_deep_merge_in_place_leaves_untouched_keys_alone():
    base = {"channels": ["Security", "System"], "poll_interval_seconds": 5}
    deep_merge_in_place(base, {"poll_interval_seconds": 10})
    assert base["channels"] == ["Security", "System"]
    assert base["poll_interval_seconds"] == 10


def test_deep_merge_in_place_mutates_the_same_object():
    base = {"x": 1}
    result = deep_merge_in_place(base, {"x": 2})
    assert result is None  # mutates in place, doesn't return a new dict
    assert base == {"x": 2}


def test_apply_timezone_accepts_valid_values():
    apply_timezone("Local")
    assert desktop_app.CURRENT_TIMEZONE == "Local"
    apply_timezone("UTC")
    assert desktop_app.CURRENT_TIMEZONE == "UTC"


def test_apply_timezone_falls_back_to_utc_for_unknown_value():
    apply_timezone("Mars/Olympus_Mons")
    assert desktop_app.CURRENT_TIMEZONE == "UTC"


def test_format_display_ts_in_utc_mode_keeps_the_instant_unchanged():
    apply_timezone("UTC")
    result = format_display_ts("2026-08-04T20:00:00.000Z")
    assert result == "2026-08-04 20:00:00"


def test_format_display_ts_in_local_mode_matches_manual_conversion():
    apply_timezone("Local")
    raw = "2026-08-04T20:00:00.000Z"
    result = format_display_ts(raw)
    # Compute the expected value the same way the app does, so this test
    # passes regardless of the machine's actual configured timezone/DST.
    expected_dt = datetime.datetime(2026, 8, 4, 20, 0, 0, tzinfo=datetime.timezone.utc).astimezone()
    assert result == expected_dt.strftime("%Y-%m-%d %H:%M:%S")
    apply_timezone("UTC")  # reset for other tests


def test_format_display_ts_returns_input_unchanged_on_unparseable_string():
    apply_timezone("UTC")
    assert format_display_ts("not-a-timestamp") == "not-a-timestamp"


def test_format_display_ts_passes_through_empty_string():
    assert format_display_ts("") == ""
