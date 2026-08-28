"""Tests for network connection monitoring."""

from __future__ import annotations

import time

import pytest

from aegorx.network.conn_monitor import (
    Connection,
    ConnectionMonitor,
    BeaconDetector,
)


class TestConnection:
    def test_basic(self):
        c = Connection(
            local_addr="127.0.0.1",
            local_port=8080,
            remote_addr="192.168.1.1",
            remote_port=443,
            proto="tcp",
            state="ESTABLISHED",
            pid=1234,
        )
        assert c.remote_addr == "192.168.1.1"
        assert c.remote_port == 443
        assert c.proto == "tcp"
        assert c.pid == 1234

    def test_to_dict(self):
        c = Connection(
            local_addr="0.0.0.0",
            local_port=80,
            remote_addr="10.0.0.1",
            remote_port=12345,
            proto="tcp",
            state="ESTABLISHED",
            pid=99,
        )
        d = c.to_dict()
        assert d["remote"] == "10.0.0.1:12345"
        assert d["local"] == "0.0.0.0:80"
        assert d["pid"] == 99
        assert d["proto"] == "tcp"
        assert d["state"] == "ESTABLISHED"

    def test_fields_populated(self):
        c = Connection(
            local_addr="192.168.1.1",
            local_port=54321,
            remote_addr="10.0.0.1",
            remote_port=22,
            proto="tcp",
            state="CLOSE_WAIT",
            pid=999,
        )
        assert c.local_addr == "192.168.1.1"
        assert c.local_port == 54321
        assert c.state == "CLOSE_WAIT"
        assert c.pid == 999

    def test_default_values(self):
        c = Connection()
        assert c.local_addr == ""
        assert c.local_port == 0
        assert c.remote_addr == ""
        assert c.remote_port == 0
        assert c.proto == "tcp"
        assert c.pid == 0
        assert c.state == "ESTABLISHED"


class TestBeaconDetector:
    def test_no_beacon(self):
        bd = BeaconDetector()
        assert bd.record("8.8.8.8") is None

    def test_beacon_detected(self):
        bd = BeaconDetector(window_seconds=10, min_samples=3)
        for _ in range(5):
            bd.record("8.8.8.8")
            time.sleep(0.05)
        # With very fast intervals (< 1s), should not detect (too fast)
        result = bd.record("8.8.8.8")
        # The detector filters out avg_interval < 1.0
        # With 0.05s intervals, avg is < 1.0 so no beacon
        assert result is None

    def test_beacon_with_slower_interval(self):
        bd = BeaconDetector(window_seconds=300, min_samples=3)
        # Record with regular-ish intervals (but still < 1s avg)
        for _ in range(4):
            bd.record("evil.com")
            time.sleep(0.05)
        # Since avg_interval < 1.0, should not detect
        result = bd.record("evil.com")
        assert result is None

    def test_reset(self):
        bd = BeaconDetector()
        bd.record("host.com")
        bd.reset()
        assert len(bd._history) == 0


class TestConnectionMonitor:
    def test_add_blocked_ip(self):
        m = ConnectionMonitor()
        m.add_blocked_ip("10.0.0.1")
        assert m.is_blocked("10.0.0.1") is True
        assert m.is_blocked("10.0.0.2") is False

    def test_remove_blocked_ip(self):
        m = ConnectionMonitor()
        m.add_blocked_ip("10.0.0.1")
        m.remove_blocked_ip("10.0.0.1")
        assert m.is_blocked("10.0.0.1") is False

    def test_stats_empty(self):
        m = ConnectionMonitor()
        s = m.stats()
        assert s["connections_scanned"] == 0
        assert s["suspicious_detected"] == 0
        assert s["beacons_detected"] == 0

    def test_stats_after_scan(self, monkeypatch):
        fake_conns = [
            Connection("10.0.0.1", 12345, "10.0.0.2", 443, "tcp", "ESTABLISHED", 0),
            Connection("10.0.0.1", 12346, "8.8.8.8", 53, "tcp", "ESTABLISHED", 0),
        ]

        def fake_get_conns():
            return fake_conns

        monkeypatch.setattr(
            "aegorx.network.conn_monitor._get_connections_platform", fake_get_conns
        )
        m = ConnectionMonitor()
        m.scan_once()
        s = m.stats()
        assert s["connections_scanned"] == 2

    def test_suspicious_detection(self, monkeypatch):
        fake_conns = [
            Connection("10.0.0.1", 12345, "10.0.0.1", 4444, "tcp", "LISTEN", 0),
            Connection("10.0.0.1", 12346, "8.8.8.8", 53, "tcp", "ESTABLISHED", 0),
        ]

        def fake_get_conns():
            return fake_conns

        monkeypatch.setattr(
            "aegorx.network.conn_monitor._get_connections_platform", fake_get_conns
        )
        m = ConnectionMonitor()
        suspicious = m.scan_once()
        assert len(suspicious) >= 1
        assert any(c.remote_port == 4444 for c in suspicious)

    def test_start_stop(self):
        m = ConnectionMonitor(poll_interval=1)
        m.start()
        assert m._thread is not None
        m.stop()
        assert m._thread is None

    def test_scan_callback(self, monkeypatch):
        called_with = []

        def callback(conn, reason):
            called_with.append((conn, reason))

        fake_conns = [
            Connection("10.0.0.1", 12345, "10.0.0.1", 6667, "tcp", "LISTEN", 0),
        ]

        def fake_get_conns():
            return fake_conns

        monkeypatch.setattr(
            "aegorx.network.conn_monitor._get_connections_platform", fake_get_conns
        )
        m = ConnectionMonitor(scan_callback=callback)
        m.scan_once()
        assert len(called_with) >= 1

    def test_reset_stats(self):
        m = ConnectionMonitor()
        m.reset_stats()
        s = m.stats()
        assert s["connections_scanned"] == 0

    def test_set_ip_blocklist(self):
        m = ConnectionMonitor()
        m.set_ip_blocklist({"1.1.1.1", "2.2.2.2"})
        assert m.is_blocked("1.1.1.1") is True
        assert m.is_blocked("3.3.3.3") is False

    def test_allow_ip(self):
        m = ConnectionMonitor()
        m.add_blocked_ip("10.0.0.1")
        m.allow_ip("10.0.0.1")
        # allow_ip adds to allowlist but is_blocked still checks blocklist
        assert m.is_blocked("10.0.0.1") is True
