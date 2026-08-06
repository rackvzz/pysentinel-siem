import pytest

from siem import response, storage


@pytest.fixture
def conn():
    c = storage.connect(":memory:")
    storage.init_db(c)
    return c


class TestIsBlockableIp:
    def test_public_ip_is_blockable(self):
        ok, why = response.is_blockable_ip("8.8.8.8")
        assert ok is True
        assert why == ""

    def test_private_ip_is_rejected(self):
        ok, why = response.is_blockable_ip("192.168.1.50")
        assert ok is False
        assert "not an ordinary public IP" in why

    def test_loopback_is_rejected(self):
        ok, why = response.is_blockable_ip("127.0.0.1")
        assert ok is False

    def test_link_local_is_rejected(self):
        ok, why = response.is_blockable_ip("169.254.1.1")
        assert ok is False

    def test_multicast_is_rejected(self):
        ok, why = response.is_blockable_ip("224.0.0.1")
        assert ok is False

    def test_invalid_ip_is_rejected(self):
        ok, why = response.is_blockable_ip("not-an-ip")
        assert ok is False
        assert "not a valid IP" in why

    def test_ipv6_private_range_is_rejected(self):
        ok, why = response.is_blockable_ip("fc00::1")  # unique local address
        assert ok is False

    def test_ipv6_public_is_blockable(self):
        ok, why = response.is_blockable_ip("2001:db8::1")
        # 2001:db8::/32 is the documentation range -- not actually
        # globally routable in practice, but ipaddress correctly reports
        # it as not-global; use a real-looking global unicast instead.
        ok2, why2 = response.is_blockable_ip("2606:4700:4700::1111")
        assert ok2 is True


class TestBlockIp:
    def test_rejects_non_public_ip_without_calling_subprocess(self, conn, monkeypatch):
        called = []
        monkeypatch.setattr(response.subprocess, "run", lambda *a, **kw: called.append(a) or (_ for _ in ()).throw(AssertionError))
        ok, msg = response.block_ip(conn, "192.168.1.1")
        assert ok is False
        assert called == []
        assert not storage.is_ip_blocked(conn, "192.168.1.1")

    def test_blocks_successfully_with_both_directions(self, conn, monkeypatch):
        calls = []

        def fake_run(args, **kw):
            calls.append(args)
            class R:
                returncode = 0
                stdout = "Ok.\n"
                stderr = ""
            return R()

        monkeypatch.setattr(response.subprocess, "run", fake_run)
        ok, msg = response.block_ip(conn, "8.8.8.8", reason="brute force source")
        assert ok is True
        assert len(calls) == 2  # one 'in' rule, one 'out' rule
        assert any("dir=in" in a for a in calls[0])
        assert any("dir=out" in a for a in calls[1])
        assert storage.is_ip_blocked(conn, "8.8.8.8")

    def test_is_idempotent_for_already_blocked_ip(self, conn, monkeypatch):
        storage.add_blocked_ip(conn, "8.8.8.8", "reason", "pysentinel-siem-block-8.8.8.8")
        called = []
        monkeypatch.setattr(response.subprocess, "run", lambda *a, **kw: called.append(a) or (_ for _ in ()).throw(AssertionError))
        ok, msg = response.block_ip(conn, "8.8.8.8")
        assert ok is True
        assert "already blocked" in msg
        assert called == []

    def test_returns_false_on_netsh_failure(self, conn, monkeypatch):
        def fake_run(args, **kw):
            class R:
                returncode = 1
                stdout = ""
                stderr = "Access is denied."
            return R()

        monkeypatch.setattr(response.subprocess, "run", fake_run)
        ok, msg = response.block_ip(conn, "8.8.8.8")
        assert ok is False
        assert not storage.is_ip_blocked(conn, "8.8.8.8")


class TestUnblockIp:
    def test_rejects_ip_that_is_not_blocked(self, conn, monkeypatch):
        called = []
        monkeypatch.setattr(response.subprocess, "run", lambda *a, **kw: called.append(a) or (_ for _ in ()).throw(AssertionError))
        ok, msg = response.unblock_ip(conn, "8.8.8.8")
        assert ok is False
        assert called == []

    def test_unblocks_successfully(self, conn, monkeypatch):
        storage.add_blocked_ip(conn, "8.8.8.8", "reason", "pysentinel-siem-block-8.8.8.8")

        def fake_run(args, **kw):
            class R:
                returncode = 0
                stdout = "Ok.\n"
                stderr = ""
            return R()

        monkeypatch.setattr(response.subprocess, "run", fake_run)
        ok, msg = response.unblock_ip(conn, "8.8.8.8")
        assert ok is True
        assert not storage.is_ip_blocked(conn, "8.8.8.8")


def test_list_blocked_ips(conn):
    storage.add_blocked_ip(conn, "8.8.8.8", "brute force", "pysentinel-siem-block-8.8.8.8")
    storage.add_blocked_ip(conn, "198.51.100.7", "port scan", "pysentinel-siem-block-198.51.100.7")
    rows = response.list_blocked_ips(conn)
    assert {r["ip"] for r in rows} == {"8.8.8.8", "198.51.100.7"}
