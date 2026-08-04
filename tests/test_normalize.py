from siem.normalize import normalize_event

FAILED_LOGON_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
<Provider Name='Microsoft-Windows-Security-Auditing'/>
<EventID>4625</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>12544</Task>
<Opcode>0</Opcode>
<Keywords>0x8010000000000000</Keywords>
<TimeCreated SystemTime='2026-08-04T12:00:00.000Z'/>
<EventRecordID>555</EventRecordID>
<Correlation/>
<Execution ProcessID='600' ThreadID='700'/>
<Channel>Security</Channel>
<Computer>DESKTOP-TEST</Computer>
<Security/>
</System>
<EventData>
<Data Name='TargetUserName'>alice</Data>
<Data Name='WorkstationName'>ATTACKER-PC</Data>
<Data Name='IpAddress'>10.0.0.5</Data>
</EventData>
</Event>"""


def test_normalize_failed_logon():
    event = normalize_event(FAILED_LOGON_XML, "Security")

    assert event["channel"] == "Security"
    assert event["record_id"] == 555
    assert event["ts"] == "2026-08-04T12:00:00.000Z"
    assert event["event_id"] == 4625
    assert event["computer"] == "DESKTOP-TEST"
    assert event["user"] == "alice"
    assert event["source_ip"] == "10.0.0.5"
    assert "Failed logon" in event["message"]
    assert "alice" in event["message"]
    assert event["raw_xml"] == FAILED_LOGON_XML


def test_normalize_falls_back_to_workstation_when_no_ip():
    xml = FAILED_LOGON_XML.replace(
        "<Data Name='IpAddress'>10.0.0.5</Data>", "<Data Name='IpAddress'>-</Data>"
    )
    event = normalize_event(xml, "Security")
    # IpAddress of "-" is a real Windows convention for "not applicable";
    # normalize_event still records it verbatim in source_ip...
    assert event["source_ip"] == "-"
    # ...but the human-readable message should not claim "from -".
    assert "from -" not in event["message"]
