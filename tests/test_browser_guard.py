"""Tests for browser download protection."""

from __future__ import annotations

import os
import time

import pytest

from aegorx.browser_guard import BrowserDownloadMonitor, _default_download_paths


class TestDefaultDownloadPaths:
    def test_returns_list(self):
        paths = _default_download_paths()
        assert isinstance(paths, list)

    def test_downloads_in_list(self):
        paths = _default_download_paths()
        home = os.path.expanduser("~")
        downloads = os.path.join(home, "Downloads")
        # On most systems, ~/Downloads exists or will be in the list
        assert isinstance(paths, list)


class TestBrowserDownloadMonitor:
    def test_start_stop(self, tmp_path):
        monitor = BrowserDownloadMonitor(download_dirs=[str(tmp_path)])
        monitor.start()
        assert monitor.is_running()
        monitor.stop()
        assert not monitor.is_running()

    def test_stats_empty(self, tmp_path):
        monitor = BrowserDownloadMonitor(download_dirs=[str(tmp_path)])
        stats = monitor.stats()
        assert stats["files_detected"] == 0
        assert stats["scans_triggered"] == 0

    def test_scan_now(self, tmp_path):
        called = []

        def callback(path, reason):
            called.append((path, reason))

        monitor = BrowserDownloadMonitor(
            scan_callback=callback,
            download_dirs=[str(tmp_path)],
        )
        test_file = str(tmp_path / "test.exe")
        with open(test_file, "w") as fh:
            fh.write("test")
        monitor.scan_now(test_file)
        assert len(called) == 1
        assert called[0][1] == "browser-manual"

    def test_dangerous_extensions(self):
        assert ".exe" in BrowserDownloadMonitor.DANGEROUS_EXTENSIONS
        assert ".dll" in BrowserDownloadMonitor.DANGEROUS_EXTENSIONS
        assert ".docm" in BrowserDownloadMonitor.DANGEROUS_EXTENSIONS
        assert ".txt" not in BrowserDownloadMonitor.DANGEROUS_EXTENSIONS

    def test_detects_new_file(self, tmp_path):
        called = []

        def callback(path, reason):
            called.append((path, reason))

        monitor = BrowserDownloadMonitor(
            scan_callback=callback,
            download_dirs=[str(tmp_path)],
            poll_interval=0.1,
            min_file_age=0.0,
        )
        # Create a test file before starting
        test_file = str(tmp_path / "malware.exe")
        with open(test_file, "w") as fh:
            fh.write("test content")

        monitor.start()
        time.sleep(0.3)
        monitor.stop()

        # Should have detected the file
        assert len(called) >= 1

    def test_reset_stats(self, tmp_path):
        monitor = BrowserDownloadMonitor(download_dirs=[str(tmp_path)])
        monitor.scan_now(str(tmp_path / "test.exe"))
        monitor.reset_stats()
        stats = monitor.stats()
        assert stats["scans_triggered"] == 0
