"""Quick diagnostic: confirms the Sysmon Windows Event Log channel is
readable before you rely on run_collector.py picking it up. Sysmon's
channel has the same restrictive ACL as Security -- only Administrators
and SYSTEM can read it -- so this must be run from an elevated terminal.

    (from an elevated terminal, with the venv active, from the project root)
    python sysmon\\check_access.py
"""

import sys

import win32evtlog
import pywintypes

CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def main() -> int:
    try:
        handle = win32evtlog.EvtQuery(
            CHANNEL, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
        )
    except pywintypes.error as exc:
        if exc.winerror == 5:
            print(f"Access denied reading '{CHANNEL}'. Re-run this from an elevated terminal.")
        else:
            print(f"Error querying '{CHANNEL}': {exc}")
        return 1

    events = win32evtlog.EvtNext(handle, 3)
    print(f"OK -- got {len(events)} recent Sysmon event(s):")
    for evt in events:
        xml = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
        print(" ", xml[:150])
    return 0


if __name__ == "__main__":
    sys.exit(main())
