"""Enables the 'Filtering Platform Connection' Advanced Audit Policy
subcategory (failure only) so blocked connection attempts show up as
event 5157 in the Security channel -- the signal
siem/rules/port_scan_detection.py watches for.

Failure-only (not success) keeps volume manageable: every *allowed*
connection (ordinary browsing, background app traffic, telemetry)
would otherwise also generate an event, and there are far more of
those than blocked ones on a typical machine. Failure-only mostly
captures unsolicited inbound attempts hitting closed/filtered ports
(exactly what a port scan produces) plus outbound connections an app
tried and got blocked -- both worth knowing about, without logging
every single successful connection on the machine.

Uses auditpol.exe (built into Windows) since there's no pywin32-wrapped
API for Advanced Audit Policy -- requires Administrator, same as the
Security/Sysmon channels the rest of this project already needs
elevation for.
"""

import logging
import subprocess

logger = logging.getLogger("siem.audit_policy")

SUBCATEGORY = "Filtering Platform Connection"


def is_failure_auditing_enabled() -> bool | None:
    """True/False, or None if the check itself failed (e.g. not elevated,
    or auditpol isn't on PATH)."""
    try:
        result = subprocess.run(
            ["auditpol", "/get", f"/subcategory:{SUBCATEGORY}"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    # auditpol's plain-text output has a line like:
    #   Filtering Platform Connection          Failure
    # (or "Success and Failure" / "No Auditing" / "Success").
    for line in result.stdout.splitlines():
        if SUBCATEGORY in line:
            return "Failure" in line
    return None


def ensure_failure_auditing_enabled() -> bool:
    """Enables failure auditing for Filtering Platform Connection if it
    isn't already on. Returns True if it ends up enabled (or already
    was), False if the attempt failed (e.g. not elevated) -- callers
    should treat False as "port scan detection won't see any events",
    not as a fatal error."""
    current = is_failure_auditing_enabled()
    if current:
        return True

    try:
        result = subprocess.run(
            ["auditpol", "/set", f"/subcategory:{SUBCATEGORY}", "/failure:enable"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        logger.warning("Could not run auditpol to enable port-scan detection auditing.")
        return False

    if result.returncode != 0:
        logger.warning(
            "auditpol failed to enable '%s' failure auditing: %s",
            SUBCATEGORY, (result.stdout or result.stderr).strip(),
        )
        return False

    logger.info("Enabled Windows Advanced Audit Policy: '%s' (failure) for port scan detection.", SUBCATEGORY)
    return True
