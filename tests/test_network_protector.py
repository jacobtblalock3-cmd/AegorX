"""Tests for NetworkProtector (integration) and CLI network commands."""

from __future__ import annotations

import time

import pytest

from aegorx.network.dns_filter import DNSFilter
from aegorx.network.conn_monitor import Connection, ConnectionMonitor
from aegorx.network.protector import NetworkProtector


@pytest.fixture()
def dns(tmp_path):
    return DNSFilter(
        blocklist_path=str(tmp_path / "blocklist.json"),
        custom_blocklist_path=str(tmp_path / "custom.json"),
    )


@pytest.fixture()
def monitor(monkeypatch):
    def fake_get_conns():
        return []

    monkeypatch.setattr(
        "aegorx.network.conn_monitor._get_connections_platform", fake_get_conns
    )
    return ConnectionMonitor()


class TestNetworkProtector:
    def test_start_stop(self, dns, monitor):
        p = NetworkProtector(dns_filter=dns, conn_monitor=monitor, auto_update_interval=0)
        p.start()
        assert p.is_running()
        p.stop()
        assert not p.is_running()

    def test_block_unblock(self, dns, monitor):
        p = NetworkProtector(dns_filter=dns, conn_monitor=monitor, auto_update_interval=0)
        assert p.check_domain("evil.com") is False
        p.block_domain("evil.com")
        assert p.check_domain("evil.com") is True
        p.unblock_domain("evil.com")
        assert p.check_domain("evil.com") is False

    def test_status(self, dns, monitor):
        p = NetworkProtector(dns_filter=dns, conn_monitor=monitor, auto_update_interval=0)
        status = p.status()
        assert "running" in status
        assert "dns_filter" in status
        assert "connection_monitor" in status
        assert status["dns_filter"]["blocked_domains"] == 0

    def test_summary_text(self, dns, monitor):
        p = NetworkProtector(dns_filter=dns, conn_monitor=monitor, auto_update_interval=0)
        text = p.summary_text()
        assert "[network]" in text
        assert "dns:" in text

    def test_scan_connections(self, dns, monitor):
        p = NetworkProtector(dns_filter=dns, conn_monitor=monitor, auto_update_interval=0)
        results = p.scan_connections()
        assert isinstance(results, list)

    def test_scan_callback_invoked(self, dns, monkeypatch):
        def fake_get_conns():
            return [
                Connection("10.0.0.1", 12345, "10.0.0.1", 4444, "tcp", "LISTEN", None),
            ]

        monkeypatch.setattr(
            "aegorx.network.conn_monitor._get_connections_platform", fake_get_conns
        )

        events = []

        def callback(conn, reason):
            events.append((conn, reason))

        monitor = ConnectionMonitor(scan_callback=callback)
        p = NetworkProtector(dns_filter=dns, conn_monitor=monitor, auto_update_interval=0)
        p.scan_connections()
        assert len(events) >= 1

    def test_double_start_is_idempotent(self, dns, monitor):
        p = NetworkProtector(dns_filter=dns, conn_monitor=monitor, auto_update_interval=0)
        p.start()
        p.start()  # second call should be no-op
        assert p.is_running()
        p.stop()


class TestCLINetworkCommands:
    """Test the CLI entry points for network commands."""

    def test_network_no_subcommand(self):
        from aegorx.cli import main

        result = main(["network"])
        assert result == 3  # EXIT_ERROR

    def test_network_status(self):
        from aegorx.cli import main

        # Should not error
        main(["network", "status"])

    def test_network_block_and_check(self):
        from aegorx.cli import main

        main(["network", "block", "test-block-domain.xyz"])
        result = main(["network", "check", "test-block-domain.xyz"])
        # EXIT_MALICIOUS (2) means blocked
        assert result == 2

    def test_network_unblock(self):
        from aegorx.cli import main

        main(["network", "block", "test-unblock.xyz"])
        main(["network", "unblock", "test-unblock.xyz"])
        result = main(["network", "check", "test-unblock.xyz"])
        assert result == 0

    def test_network_domains(self):
        from aegorx.cli import main

        main(["network", "block", "test-domains.xyz"])
        # Should print the domain
        main(["network", "domains"])

    def test_network_connections(self, monkeypatch):
        from aegorx.cli import main

        def fake_get_conns():
            return []

        monkeypatch.setattr(
            "aegorx.network.conn_monitor._get_connections_platform", fake_get_conns
        )
        main(["network", "connections"])

    def test_network_scan(self, monkeypatch):
        from aegorx.cli import main

        def fake_get_conns():
            return []

        monkeypatch.setattr(
            "aegorx.network.conn_monitor._get_connections_platform", fake_get_conns
        )
        result = main(["network", "scan"])
        assert result == 0
