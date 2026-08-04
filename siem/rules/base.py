"""Shared base class + helpers for detection rules.

Each rule is a small, explainable, MITRE ATT&CK-tagged piece of logic
that inspects one newly-stored event at a time (siem/engine.py calls
`evaluate()` once per event) and raises an alert via siem/alerts.py
when its condition is met.
"""

import datetime
import ntpath
from abc import ABC, abstractmethod


class Rule(ABC):
    id: str
    name: str
    mitre_id: str
    severity: str  # "low" | "medium" | "high"

    @abstractmethod
    def evaluate(self, conn, event: dict, row_id: int) -> None:
        """Inspect one normalized event (siem/storage.py `events` row,
        as a dict) and raise an alert if the rule's condition fires."""
        raise NotImplementedError


def parse_ts(ts: str) -> datetime.datetime:
    """Parse a Windows Event Log TimeCreated `SystemTime` string (UTC,
    'Z' suffix, variable-precision fractional seconds, e.g.
    '2026-08-04T17:40:08.0978271Z') into an aware UTC datetime."""
    ts = ts.rstrip("Z")
    if "." in ts:
        base, frac = ts.split(".")
        frac = (frac + "000000")[:6]  # pad/truncate to microseconds
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
        ts = f"{base}.{frac}"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S"
    return datetime.datetime.strptime(ts, fmt).replace(tzinfo=datetime.timezone.utc)


def basename(path: str) -> str:
    """Basename of a Windows path (e.g. Sysmon's Image/ParentImage fields),
    regardless of the OS this code happens to run on -- ntpath rather than
    os.path so it's correct even if tests run on a non-Windows CI runner."""
    return ntpath.basename(path) if path else ""
