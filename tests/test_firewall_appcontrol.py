"""Tests for outbound firewall and application control."""

from __future__ import annotations

import os

import pytest

from aegorx.firewall import (
    OutboundFirewall,
    SUSPICIOUS_OUTBOUND_PORTS,
    SAFE_OUTBOUND_PORTS,
)
from aegorx.app_control import (
    ApplicationController,
    AppControlPolicy,
    AppRule,
    PolicyStore,
    file_sha256,
)


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

class TestOutboundFirewall:
    def test_start_stop(self):
        fw = OutboundFirewall()
        fw.start()
        assert fw.is_running()
        fw.stop()
        assert not fw.is_running()

    def test_stats_empty(self):
        fw = OutboundFirewall()
        stats = fw.stats()
        assert stats["connections_checked"] == 0
        assert stats["connections_blocked"] == 0

    def test_add_remove_ip(self):
        fw = OutboundFirewall()
        fw.add_blocked_ip("10.0.0.1")
        assert "10.0.0.1" in fw.blocked_ips
        fw.remove_blocked_ip("10.0.0.1")
        assert "10.0.0.1" not in fw.blocked_ips

    def test_add_remove_port(self):
        fw = OutboundFirewall()
        fw.add_blocked_port(9999)
        assert 9999 in fw.blocked_ports
        fw.remove_blocked_port(9999)
        assert 9999 not in fw.blocked_ports

    def test_check_connection_blocked_ip(self):
        from aegorx.network.conn_monitor import Connection
        fw = OutboundFirewall(blocked_ips={"10.0.0.1"})
        conn = Connection("192.168.1.1", 12345, "10.0.0.1", 80, "tcp", 0, "ESTABLISHED")
        verdict = fw._check_connection(conn)
        assert verdict is not None
        assert "blocked IP" in verdict

    def test_check_connection_allowed(self):
        from aegorx.network.conn_monitor import Connection
        fw = OutboundFirewall(blocked_ips={"10.0.0.1"})
        conn = Connection("192.168.1.1", 12345, "10.0.0.2", 443, "tcp", 0, "ESTABLISHED")
        verdict = fw._check_connection(conn)
        assert verdict is None

    def test_check_loopback_ignored(self):
        from aegorx.network.conn_monitor import Connection
        fw = OutboundFirewall()
        conn = Connection("127.0.0.1", 80, "127.0.0.1", 80, "tcp", 0, "ESTABLISHED")
        verdict = fw._check_connection(conn)
        assert verdict is None

    def test_suspicious_port_detected(self):
        from aegorx.network.conn_monitor import Connection
        fw = OutboundFirewall()
        conn = Connection("192.168.1.1", 12345, "10.0.0.1", 4444, "tcp", 0, "ESTABLISHED")
        verdict = fw._check_connection(conn)
        assert verdict is not None
        assert "suspicious port" in verdict

    def test_safe_port_allowed(self):
        from aegorx.network.conn_monitor import Connection
        fw = OutboundFirewall()
        conn = Connection("192.168.1.1", 12345, "10.0.0.1", 443, "tcp", 0, "ESTABLISHED")
        verdict = fw._check_connection(conn)
        assert verdict is None

    def test_strict_mode_blocks_safe_ports(self):
        from aegorx.network.conn_monitor import Connection
        fw = OutboundFirewall(strict_mode=True)
        conn = Connection("192.168.1.1", 12345, "10.0.0.1", 443, "tcp", 0, "ESTABLISHED")
        verdict = fw._check_connection(conn)
        assert verdict is not None

    def test_scan(self, monkeypatch):
        from aegorx.network.conn_monitor import Connection
        fake_conns = [
            Connection("192.168.1.1", 12345, "10.0.0.1", 80, "tcp", 0, "ESTABLISHED"),
            Connection("192.168.1.1", 12346, "10.0.0.1", 4444, "tcp", 0, "ESTABLISHED"),
        ]

        def fake_scan(self_inner):
            return fake_conns

        monkeypatch.setattr(
            "aegorx.firewall.ConnectionMonitor.scan_once",
            fake_scan,
        )
        fw = OutboundFirewall(blocked_ips={"10.0.0.1"})
        blocked = fw.scan()
        assert len(blocked) >= 1

    def test_suspicious_ports_defined(self):
        assert 4444 in SUSPICIOUS_OUTBOUND_PORTS
        assert 6667 in SUSPICIOUS_OUTBOUND_PORTS
        assert 31337 in SUSPICIOUS_OUTBOUND_PORTS

    def test_safe_ports_defined(self):
        assert 80 in SAFE_OUTBOUND_PORTS
        assert 443 in SAFE_OUTBOUND_PORTS
        assert 22 in SAFE_OUTBOUND_PORTS

    def test_reset_stats(self):
        fw = OutboundFirewall()
        fw.reset_stats()
        assert fw.stats()["connections_checked"] == 0


# ---------------------------------------------------------------------------
# Application Control
# ---------------------------------------------------------------------------

class TestFileSha256:
    def test_known_content(self, tmp_path):
        p = str(tmp_path / "test.exe")
        with open(p, "wb") as f:
            f.write(b"MZ" + b"\x00" * 100)
        h = file_sha256(p)
        assert len(h) == 64

    def test_nonexistent(self):
        assert file_sha256("/nonexistent/path") == ""


class TestAppRule:
    def test_defaults(self):
        rule = AppRule(rule_type="hash", value="abc123", action="block")
        assert rule.enabled is True
        assert rule.created_at > 0
        assert rule.name == "hash:abc123"

    def test_custom_name(self):
        rule = AppRule(rule_type="path", value="*.exe", action="block", name="Block EXEs")
        assert rule.name == "Block EXEs"


class TestPolicyStore:
    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "policy.json")
        store = PolicyStore(path=path)
        policy = AppControlPolicy(
            rules=[AppRule("hash", "abc123", "block", "test")],
            default_action="block",
        )
        store.save(policy)
        loaded = store.load()
        assert len(loaded.rules) == 1
        assert loaded.rules[0].value == "abc123"
        assert loaded.default_action == "block"

    def test_load_missing(self, tmp_path):
        store = PolicyStore(path=str(tmp_path / "nonexistent.json"))
        policy = store.load()
        assert len(policy.rules) == 0
        assert policy.default_action == "allow"


class TestApplicationController:
    def test_default_allow(self, tmp_path):
        store = PolicyStore(path=str(tmp_path / "policy.json"))
        ac = ApplicationController(store=store)
        p = str(tmp_path / "test.exe")
        with open(p, "wb") as f:
            f.write(b"test")
        assert ac.check(p) == "allow"

    def test_block_by_hash(self, tmp_path):
        store = PolicyStore(path=str(tmp_path / "policy.json"))
        ac = ApplicationController(store=store)
        p = str(tmp_path / "malware.exe")
        with open(p, "wb") as f:
            f.write(b"malicious content")
        ac.block_hash(p)
        assert ac.check(p) == "block"

    def test_block_by_extension(self, tmp_path):
        store = PolicyStore(path=str(tmp_path / "policy.json"))
        ac = ApplicationController(store=store)
        ac.block_extension(".scr")
        p = str(tmp_path / "test.scr")
        with open(p, "wb") as f:
            f.write(b"test")
        assert ac.check(p) == "block"

    def test_block_by_path_pattern(self, tmp_path):
        store = PolicyStore(path=str(tmp_path / "policy.json"))
        ac = ApplicationController(store=store)
        ac.block_path(str(tmp_path / "*.exe"))
        p = str(tmp_path / "test.exe")
        with open(p, "wb") as f:
            f.write(b"test")
        assert ac.check(p) == "block"

    def test_allow_overrides_block(self, tmp_path):
        store = PolicyStore(path=str(tmp_path / "policy.json"))
        ac = ApplicationController(store=store)
        ac.allow_path(str(tmp_path / "safe.exe"))
        ac.block_extension(".exe")
        p = str(tmp_path / "safe.exe")
        with open(p, "wb") as f:
            f.write(b"test")
        assert ac.check(p) == "allow"

    def test_delete_rule(self, tmp_path):
        store = PolicyStore(path=str(tmp_path / "policy.json"))
        ac = ApplicationController(store=store)
        ac.block_extension(".exe")
        rules = ac.list_rules()
        assert len(rules) == 1
        ac.remove_rule(0)
        assert len(ac.list_rules()) == 0

    def test_stats(self, tmp_path):
        store = PolicyStore(path=str(tmp_path / "policy.json"))
        ac = ApplicationController(store=store)
        p = str(tmp_path / "test.exe")
        with open(p, "wb") as f:
            f.write(b"test")
        ac.check(p)
        stats = ac.stats()
        assert stats["executables_checked"] == 1

    def test_reset_stats(self, tmp_path):
        store = PolicyStore(path=str(tmp_path / "policy.json"))
        ac = ApplicationController(store=store)
        p = str(tmp_path / "test.exe")
        with open(p, "wb") as f:
            f.write(b"test")
        ac.check(p)
        ac.reset_stats()
        assert ac.stats()["executables_checked"] == 0


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

class TestCLIFirewallCommands:
    def test_firewall_no_subcommand(self):
        from aegorx.cli import main
        result = main(["firewall"])
        assert result == 3

    def test_firewall_status(self):
        from aegorx.cli import main
        result = main(["firewall", "status"])
        assert result == 0

    def test_firewall_block_ip(self):
        from aegorx.cli import main
        result = main(["firewall", "block-ip", "10.0.0.1"])
        assert result == 0

    def test_firewall_scan(self):
        from aegorx.cli import main
        result = main(["firewall", "scan"])
        assert result in (0, 1)


class TestCLIAppControlCommands:
    def test_appcontrol_no_subcommand(self):
        from aegorx.cli import main
        result = main(["appcontrol"])
        assert result == 3

    def test_appcontrol_status(self):
        from aegorx.cli import main
        result = main(["appcontrol", "status"])
        assert result == 0

    def test_appcontrol_rules(self):
        from aegorx.cli import main
        result = main(["appcontrol", "rules"])
        assert result == 0
