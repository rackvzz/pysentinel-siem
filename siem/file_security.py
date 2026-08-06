"""Restricts a file's NTFS permissions to the current Windows user only --
applied once, at startup, to secrets.yaml (the ThreatFox API key) and
siem.db (the full local telemetry history: usernames, source IPs,
command lines pulled through detection rules, etc.). Both hold data that
shouldn't be casually readable by another local account on a shared
machine, even though the default permissions inherited from the project
folder usually already restrict access to the owning user + Administrators.

Uses icacls.exe (built into Windows) via a full System32 path (same
PATH-hijacking hardening as siem/audit_policy.py's AUDITPOL_EXE) rather
than a pywin32 ACL API -- icacls is simpler to get right for "one user,
full control, nothing inherited" and this only needs to run once per
file, not on a hot path.

Best-effort throughout: a permissions tweak failing (e.g. the file is on
a filesystem that doesn't support NTFS ACLs, or this account somehow
doesn't own the file) should never block the app from starting or saving
a secret -- it degrades to "default OS permissions," not a crash.
"""

import logging
import os
import subprocess

logger = logging.getLogger("siem.file_security")

ICACLS_EXE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")


def restrict_to_current_user(path: str) -> bool:
    """Removes inherited permissions and grants only the current user
    Full Control. Returns True on success, False otherwise (logged, not
    raised)."""
    if not os.path.isfile(path):
        return False

    username = os.environ.get("USERNAME")
    if not username:
        logger.warning("Could not determine the current username -- skipping permission restriction for %s.", path)
        return False

    domain = os.environ.get("USERDOMAIN", "")
    account = f"{domain}\\{username}" if domain else username

    try:
        result = subprocess.run(
            [ICACLS_EXE, path, "/inheritance:r", "/grant:r", f"{account}:F"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Could not run icacls to restrict permissions on %s: %s", path, exc)
        return False

    if result.returncode != 0:
        logger.warning("icacls failed to restrict permissions on %s: %s", path, (result.stdout or result.stderr).strip())
        return False

    return True
