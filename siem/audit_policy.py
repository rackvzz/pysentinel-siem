"""Enables the specific Advanced Audit Policy subcategories this
project's detection rules need, when the rule that needs them is
enabled. Two subcategories, both off by default on most Windows
installs:

- 'Filtering Platform Connection' (failure only) -- blocked connection
  attempts show up as event 5157 in the Security channel, the signal
  siem/rules/port_scan_detection.py watches for. Failure-only (not
  success) keeps volume manageable: every *allowed* connection
  (ordinary browsing, background app traffic, telemetry) would
  otherwise also generate an event, and there are far more of those
  than blocked ones on a typical machine. Failure-only mostly captures
  unsolicited inbound attempts hitting closed/filtered ports (exactly
  what a port scan produces) plus outbound connections an app tried
  and got blocked.

- 'Other Object Access Events' (success) -- scheduled task creation
  shows up as event 4698 in the Security channel, half of what
  siem/rules/persistence.py watches for (the other half, service
  installation/7045, needs no audit policy at all -- the Service
  Control Manager logs it unconditionally).

Uses auditpol.exe (built into Windows) since there's no pywin32-wrapped
API for Advanced Audit Policy -- requires Administrator, same as the
Security/Sysmon channels the rest of this project already needs
elevation for.
"""

import logging
import os
import subprocess

logger = logging.getLogger("siem.audit_policy")

SUBCATEGORY = "Filtering Platform Connection"
OBJECT_ACCESS_SUBCATEGORY = "Other Object Access Events"

# Full path rather than a bare "auditpol" -- resolving via PATH means a
# malicious auditpol.exe earlier on PATH would run instead of the real
# one. This process is already elevated for every caller of this module,
# so that's worth closing off even though exploiting it would already
# require the attacker to have meaningful local write access.
AUDITPOL_EXE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "auditpol.exe")


def _is_auditing_enabled(subcategory: str, audit_type: str) -> bool | None:
    """True/False, or None if the check itself failed (e.g. not elevated,
    or auditpol isn't on PATH)."""
    try:
        result = subprocess.run(
            [AUDITPOL_EXE, "/get", f"/subcategory:{subcategory}"],
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
        if subcategory in line:
            return audit_type in line
    return None


def _set_auditing_enabled(subcategory: str, audit_type: str, purpose: str) -> bool:
    """The actual `auditpol /set` call, shared by both ensure_* wrappers
    below. Callers check is_*_auditing_enabled() themselves first (kept
    as a separate step, not folded in here) so each rule's own
    is_*_enabled() stays independently mockable in tests -- exactly the
    pattern the original single-subcategory version had."""
    try:
        result = subprocess.run(
            [AUDITPOL_EXE, "/set", f"/subcategory:{subcategory}", f"/{audit_type}:enable"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        logger.warning("Could not run auditpol to enable %s auditing.", purpose)
        return False

    if result.returncode != 0:
        logger.warning(
            "auditpol failed to enable '%s' %s auditing: %s",
            subcategory, audit_type, (result.stdout or result.stderr).strip(),
        )
        return False

    logger.info("Enabled Windows Advanced Audit Policy: '%s' (%s) for %s.", subcategory, audit_type, purpose)
    return True


def is_failure_auditing_enabled() -> bool | None:
    return _is_auditing_enabled(SUBCATEGORY, "Failure")


def ensure_failure_auditing_enabled() -> bool:
    """Enables failure auditing for Filtering Platform Connection if it
    isn't already on. Returns True if it ends up enabled (or already
    was), False if the attempt failed (e.g. not elevated)."""
    if is_failure_auditing_enabled():
        return True
    return _set_auditing_enabled(SUBCATEGORY, "failure", "port scan detection")


def is_object_access_auditing_enabled() -> bool | None:
    return _is_auditing_enabled(OBJECT_ACCESS_SUBCATEGORY, "Success")


def ensure_object_access_auditing_enabled() -> bool:
    """Same as ensure_failure_auditing_enabled(), for the 'Other Object
    Access Events' subcategory persistence.py's scheduled-task check
    (event 4698) needs."""
    if is_object_access_auditing_enabled():
        return True
    return _set_auditing_enabled(OBJECT_ACCESS_SUBCATEGORY, "success", "scheduled-task persistence detection")
