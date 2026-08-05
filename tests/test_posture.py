from siem import posture

SAMPLE_NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1960
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       1960
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    127.0.0.1:6463         0.0.0.0:0              LISTENING       9952
  TCP    127.0.0.1:12025        0.0.0.0:0              LISTENING       4372
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       912
  TCP    0.0.0.0:50000          0.0.0.0:0              LISTENING       5555
  TCP    127.0.0.1:61999        127.0.0.1:35783        SYN_SENT        12656
  TCP    10.0.0.5:139           0.0.0.0:0              LISTENING       4
"""


def test_parse_netstat_only_returns_listening_tcp():
    parsed = posture._parse_netstat_listening(SAMPLE_NETSTAT)
    # SYN_SENT row must be excluded; 9 LISTENING TCP rows present.
    assert len(parsed) == 9
    assert all(isinstance(p["port"], int) for p in parsed)


def test_scan_flags_risky_exposed_port_as_high(monkeypatch):
    monkeypatch.setattr(posture, "_run_netstat", lambda: SAMPLE_NETSTAT)
    findings = posture.scan_listening_ports()
    smb = next(f for f in findings if "445" in f["title"])
    assert smb["severity"] == "high"
    assert smb["mitre_id"] == "T1021.002"
    rdp = next(f for f in findings if "3389" in f["title"])
    assert rdp["severity"] == "high"
    assert rdp["mitre_id"] == "T1021.001"


def test_scan_flags_risky_localhost_only_port_as_low(monkeypatch):
    monkeypatch.setattr(posture, "_run_netstat", lambda: SAMPLE_NETSTAT)
    findings = posture.scan_listening_ports()
    localhost_findings = [f for f in findings if "6463" in f["title"] or "12025" in f["title"]]
    # Neither 6463 nor 12025 is in RISKY_PORTS, so they shouldn't produce
    # a "listening (localhost-only)" finding at all -- only exposure on
    # all interfaces is worth flagging for non-risky ports.
    assert localhost_findings == []


def test_scan_dedupes_ipv4_ipv6_dual_stack(monkeypatch):
    monkeypatch.setattr(posture, "_run_netstat", lambda: SAMPLE_NETSTAT)
    findings = posture.scan_listening_ports()
    port_135_findings = [f for f in findings if "135" in f["title"]]
    # 0.0.0.0:135 and [::]:135 are the same underlying exposure -- one finding.
    assert len(port_135_findings) == 1


def test_scan_flags_non_risky_exposed_high_port_as_low_visibility(monkeypatch):
    monkeypatch.setattr(posture, "_run_netstat", lambda: SAMPLE_NETSTAT)
    findings = posture.scan_listening_ports()
    port_50000 = next(f for f in findings if "50000" in f["title"])
    assert port_50000["severity"] == "low"
    assert port_50000["mitre_id"] is None


def test_scan_treats_lan_bound_risky_port_as_exposed(monkeypatch):
    # 10.0.0.5 (a real LAN IP, not loopback) is just as reachable from
    # other machines as 0.0.0.0 -- should be flagged high, same as 0.0.0.0.
    monkeypatch.setattr(posture, "_run_netstat", lambda: SAMPLE_NETSTAT)
    findings = posture.scan_listening_ports()
    netbios = next(f for f in findings if "139" in f["title"])
    assert netbios["severity"] == "high"


def test_scan_returns_empty_list_on_netstat_failure(monkeypatch):
    def _raise():
        raise OSError("netstat not found")

    monkeypatch.setattr(posture, "_run_netstat", _raise)
    assert posture.scan_listening_ports() == []
