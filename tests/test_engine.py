from siem import engine


def test_configure_registers_all_rules_by_default():
    engine.configure({})
    rule_ids = {r.id for r in engine.RULES}
    assert rule_ids == {
        "brute_force", "new_admin_account", "afterhours_logon",
        "encoded_powershell", "suspicious_parent_child", "threat_intel_match",
        "port_scan_detection", "powershell_scriptblock", "credential_access", "persistence",
    }


def test_configure_respects_disabled_flags_for_new_rules():
    config = {
        "detections": {
            "powershell_scriptblock": {"enabled": False},
            "credential_access": {"enabled": False},
            "persistence": {"enabled": False},
        }
    }
    engine.configure(config)
    rule_ids = {r.id for r in engine.RULES}
    assert "powershell_scriptblock" not in rule_ids
    assert "credential_access" not in rule_ids
    assert "persistence" not in rule_ids
    # everything else should still be on (defaults to enabled=True)
    assert "brute_force" in rule_ids

    engine.configure({})  # restore full defaults for any later test relying on them
