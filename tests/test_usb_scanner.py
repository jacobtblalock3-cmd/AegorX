"""Tests for USB auto-scan."""

from __future__ import annotations

import pytest

from aegorx.usb_scanner import USBScanner


class TestUSBScanner:
    def test_start_stop(self):
        scanner = USBScanner()
        scanner.start()
        assert scanner.is_running()
        scanner.stop()
        assert not scanner.is_running()

    def test_stats_empty(self):
        scanner = USBScanner()
        stats = scanner.stats()
        assert stats["mounts_detected"] == 0
        assert stats["scans_triggered"] == 0

    def test_scan_now(self):
        called = []

        def callback(path, reason):
            called.append((path, reason))

        scanner = USBScanner(scan_callback=callback)
        scanner.scan_now("/mnt/usb")
        assert len(called) == 1
        assert called[0] == ("/mnt/usb", "usb-manual")
        assert scanner.stats()["scans_triggered"] == 1

    def test_reset_stats(self):
        scanner = USBScanner()
        scanner.scan_now("/tmp")
        scanner.reset_stats()
        stats = scanner.stats()
        assert stats["scans_triggered"] == 0

    def test_double_start(self):
        scanner = USBScanner()
        scanner.start()
        scanner.start()  # should be no-op
        assert scanner.is_running()
        scanner.stop()
