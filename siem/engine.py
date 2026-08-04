"""Runs each newly-stored event through the active detection rules.

Phase 1 stub: no rules registered yet (see siem/rules/), so this is a
no-op. Phase 2 fills in RULES and the alert-raising logic.
"""

import logging

logger = logging.getLogger("siem.engine")

RULES: list = []


def evaluate_event(conn, event: dict, row_id: int) -> None:
    for rule in RULES:
        try:
            rule.evaluate(conn, event, row_id)
        except Exception:
            logger.exception("Rule %s raised an exception evaluating event id=%s", rule.id, row_id)
