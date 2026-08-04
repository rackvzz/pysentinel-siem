from desktop_app import deep_merge_in_place


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
