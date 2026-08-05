"""Runs each newly-stored event through the active detection rules.

`configure()` builds the rule set from config.yaml's `detections` section
once at startup; `evaluate_event()` is called by the collector for every
event it stores.
"""

import logging

from .rules.afterhours_logon import AfterHoursLogonRule
from .rules.brute_force import BruteForceRule
from .rules.encoded_powershell import EncodedPowerShellRule
from .rules.new_admin_account import NewAdminAccountRule
from .rules.port_scan_detection import PortScanDetectionRule
from .rules.suspicious_parent_child import SuspiciousParentChildRule
from .rules.threat_intel_match import ThreatIntelMatchRule

logger = logging.getLogger("siem.engine")

RULES: list = []


def configure(config: dict) -> None:
    global RULES
    detections = config.get("detections", {})
    rules = []

    bf = detections.get("brute_force", {})
    if bf.get("enabled", True):
        rules.append(
            BruteForceRule(
                event_id=bf.get("failed_logon_event_id", 4625),
                threshold=bf.get("threshold", 5),
                window_seconds=bf.get("window_seconds", 300),
            )
        )

    if detections.get("new_admin_account", {}).get("enabled", True):
        rules.append(NewAdminAccountRule())

    ah = detections.get("afterhours_logon", {})
    if ah.get("enabled", True):
        rules.append(
            AfterHoursLogonRule(
                event_id=ah.get("successful_logon_event_id", 4624),
                business_hours_start=ah.get("business_hours_start", 7),
                business_hours_end=ah.get("business_hours_end", 19),
            )
        )

    if detections.get("encoded_powershell", {}).get("enabled", True):
        rules.append(EncodedPowerShellRule())

    if detections.get("suspicious_parent_child", {}).get("enabled", True):
        rules.append(SuspiciousParentChildRule())

    # Always registered like the other rules -- naturally inert until the
    # threat_intel feed (separately opt-in, needs an API key) populates
    # the IOC cache it checks against.
    if detections.get("threat_intel_match", {}).get("enabled", True):
        rules.append(ThreatIntelMatchRule())

    ps = detections.get("port_scan_detection", {})
    if ps.get("enabled", True):
        rules.append(
            PortScanDetectionRule(
                distinct_ports_threshold=ps.get("distinct_ports_threshold", 10),
                window_seconds=ps.get("window_seconds", 30),
            )
        )

    RULES = rules
    logger.info(
        "Detection engine configured with %d active rule(s): %s",
        len(RULES),
        ", ".join(r.id for r in RULES) or "(none)",
    )


def evaluate_event(conn, event: dict, row_id: int) -> None:
    for rule in RULES:
        try:
            rule.evaluate(conn, event, row_id)
        except Exception:
            logger.exception("Rule %s raised an exception evaluating event id=%s", rule.id, row_id)
