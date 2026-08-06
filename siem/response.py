"""Human-triggered response action: block or unblock an IP via a Windows
Firewall rule. Deliberately NOT wired into any detection rule or the
collector -- every call here traces back to a button click in one of the
UIs, never something the SIEM decides to do on its own. Requires
Administrator, same as everything else in this project that touches
Windows configuration (auditpol, Sysmon/Security channel access).

Safety: only a public/global-routable IP can ever be blocked (see
is_blockable_ip). That's not just a scoping choice -- it structurally
rules out the actual dangerous outcomes of a fat-fingered or
alert-description-parsing-error IP: you cannot use this to lock out your
own LAN, your router, localhost, or a multicast/broadcast range, because
none of those are "public" addresses. It's also the right scope for what
this feature is *for* -- blocking a known-malicious external source, not
managing internal network segmentation.

Uses netsh.exe (built into Windows) via an argument list (never
shell=True), so there's no shell-injection surface even before IP
validation is considered; the validation step is an independent second
layer, not the only one.
"""

import ipaddress
import logging
import os
import subprocess

from . import storage

logger = logging.getLogger("siem.response")

RULE_NAME_PREFIX = "pysentinel-siem-block-"

# Full path rather than a bare "netsh" -- see audit_policy.py's
# AUDITPOL_EXE for why (PATH-hijacking hardening).
NETSH_EXE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "netsh.exe")


def is_blockable_ip(ip: str) -> tuple[bool, str]:
    """Returns (True, "") if `ip` is safe and sensible to block, else
    (False, reason). Only public/global unicast addresses are blockable --
    see module docstring for why.

    Checks is_global explicitly alongside is_private/is_multicast rather
    than relying on is_global alone: multicast addresses (224.0.0.0/4)
    report is_global=True in Python's ipaddress module (they're not
    "private," so nothing about is_global's own definition excludes
    them) despite being nothing you'd ever sensibly firewall-block by
    remote IP -- confirmed against a live probe of the module's actual
    behavior, not assumed from the docs."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"'{ip}' is not a valid IP address"

    if not addr.is_global or addr.is_private or addr.is_multicast or addr.is_reserved or addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return False, (
            f"'{ip}' is not an ordinary public IP (private/loopback/link-local/reserved/multicast) -- "
            "refusing to block it to avoid cutting off your own network"
        )
    return True, ""


def _rule_name(ip: str) -> str:
    return f"{RULE_NAME_PREFIX}{ip}"


def block_ip(conn, ip: str, reason: str = "") -> tuple[bool, str]:
    """Adds a Windows Firewall rule blocking both inbound and outbound
    traffic to/from `ip`. Idempotent: blocking an already-blocked IP is a
    no-op success, not an error."""
    ok, why = is_blockable_ip(ip)
    if not ok:
        return False, why

    if storage.is_ip_blocked(conn, ip):
        return True, f"{ip} is already blocked"

    rule_name = _rule_name(ip)
    for direction in ("in", "out"):
        try:
            result = subprocess.run(
                [
                    NETSH_EXE, "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", f"dir={direction}", "action=block", f"remoteip={ip}",
                ],
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.error("Could not run netsh to block %s: %s", ip, exc)
            return False, "Could not run netsh (not elevated, or netsh missing)"

        if result.returncode != 0:
            logger.error("netsh failed to add %s rule for %s: %s", direction, ip, (result.stdout or result.stderr).strip())
            return False, (result.stdout or result.stderr or "netsh failed").strip()

    storage.add_blocked_ip(conn, ip, reason, rule_name)
    logger.info("Blocked IP %s (reason: %s)", ip, reason or "none given")
    return True, f"Blocked {ip}"


def unblock_ip(conn, ip: str) -> tuple[bool, str]:
    """Removes the firewall rule(s) for `ip` and clears it from the
    blocked_ips table. A single `delete rule name=X` call removes both
    the inbound and outbound rule, since block_ip() gives them the same
    name."""
    if not storage.is_ip_blocked(conn, ip):
        return False, f"{ip} is not currently blocked"

    rule_name = _rule_name(ip)
    try:
        result = subprocess.run(
            [NETSH_EXE, "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.error("Could not run netsh to unblock %s: %s", ip, exc)
        return False, "Could not run netsh (not elevated, or netsh missing)"

    if result.returncode != 0:
        logger.error("netsh failed to delete rule for %s: %s", ip, (result.stdout or result.stderr).strip())
        return False, (result.stdout or result.stderr or "netsh failed").strip()

    storage.remove_blocked_ip(conn, ip)
    logger.info("Unblocked IP %s", ip)
    return True, f"Unblocked {ip}"


def list_blocked_ips(conn):
    return storage.get_blocked_ips(conn)
