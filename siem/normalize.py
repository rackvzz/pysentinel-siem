"""Turn a raw Windows Event Log XML blob into the common event schema
used everywhere else in the project (siem/storage.py's `events` table).
"""

import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

LEVEL_MAP = {
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}

# Human-readable one-liners for the event IDs the detection rules care about.
# Anything else falls back to a generic "<Provider> event <id>" message.
EVENT_DESCRIPTIONS = {
    4624: "Successful logon",
    4625: "Failed logon",
    4720: "User account created",
    4732: "Member added to a security-enabled local group",
    4740: "User account locked out",
}


def _find_text(node, tag):
    if node is None:
        return None
    return node.findtext(f"e:{tag}", namespaces=NS)


def parse_event_data(raw_xml: str) -> dict:
    """Return the <EventData><Data Name="...">value</Data>...</EventData>
    block as a plain {name: value} dict. Public because detection rules
    need fields the common schema doesn't carry (e.g. LogonType,
    MemberName) straight from the raw event.
    """
    root = ET.fromstring(raw_xml)
    event_data = {}
    data_node = root.find("e:EventData", NS)
    if data_node is not None:
        for d in data_node.findall("e:Data", NS):
            name = d.attrib.get("Name")
            if name:
                event_data[name] = d.text
    return event_data


def normalize_event(raw_xml: str, channel: str) -> dict:
    """Parse one <Event>...</Event> XML document into a flat dict matching
    the `events` table columns."""
    root = ET.fromstring(raw_xml)
    system = root.find("e:System", NS)

    event_id = int(_find_text(system, "EventID"))
    record_id = int(_find_text(system, "EventRecordID"))
    time_created_node = system.find("e:TimeCreated", NS)
    ts = time_created_node.attrib.get("SystemTime") if time_created_node is not None else None
    computer = _find_text(system, "Computer") or ""
    level_num = _find_text(system, "Level") or "4"
    level = LEVEL_MAP.get(level_num, "Information")
    provider_node = system.find("e:Provider", NS)
    provider = provider_node.attrib.get("Name", "") if provider_node is not None else ""

    event_data = parse_event_data(raw_xml)

    user = event_data.get("TargetUserName") or event_data.get("SubjectUserName") or ""
    source_ip = event_data.get("IpAddress") or event_data.get("WorkstationName") or ""

    message = EVENT_DESCRIPTIONS.get(event_id, f"{provider} event {event_id}")
    if user:
        message = f"{message} (user: {user})"
    if source_ip and source_ip not in ("-", ""):
        message = f"{message} from {source_ip}"

    return {
        "channel": channel,
        "record_id": record_id,
        "ts": ts,
        "event_id": event_id,
        "level": level,
        "computer": computer,
        "user": user,
        "source_ip": source_ip,
        "message": message,
        "raw_xml": raw_xml,
    }
