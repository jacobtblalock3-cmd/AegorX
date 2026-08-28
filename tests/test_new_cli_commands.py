"""Tests for new CLI commands (usb, schedule, browser, process)."""

from __future__ import annotations

import pytest


class TestCLIUSBCommands:
    def test_usb_no_subcommand(self):
        from aegorx.cli import main
        result = main(["usb"])
        assert result == 3  # EXIT_ERROR

    def test_usb_status(self):
        from aegorx.cli import main
        result = main(["usb", "status"])
        assert result == 0


class TestCLIScheduleCommands:
    def test_schedule_no_subcommand(self):
        from aegorx.cli import main
        result = main(["schedule"])
        assert result == 3  # EXIT_ERROR

    def test_schedule_status(self):
        from aegorx.cli import main
        result = main(["schedule", "status"])
        assert result == 0


class TestCLIBrowserCommands:
    def test_browser_no_subcommand(self):
        from aegorx.cli import main
        result = main(["browser"])
        assert result == 3  # EXIT_ERROR

    def test_browser_status(self):
        from aegorx.cli import main
        result = main(["browser", "status"])
        assert result == 0

    def test_browser_dirs(self):
        from aegorx.cli import main
        result = main(["browser", "dirs"])
        assert result == 0


class TestCLIProcessCommands:
    def test_process_no_subcommand(self):
        from aegorx.cli import main
        result = main(["process"])
        assert result == 3  # EXIT_ERROR

    def test_process_status(self):
        from aegorx.cli import main
        result = main(["process", "status"])
        assert result == 0

    def test_process_scan_pid(self):
        from aegorx.cli import main
        import os
        result = main(["process", "scan-pid", str(os.getpid())])
        # Should succeed (may find things or not)
        assert result in (0, 1)  # CLEAN or SUSPICIOUS

    def test_process_scan_name(self):
        from aegorx.cli import main
        result = main(["process", "scan-name", "nonexistent_xyz"])
        assert result == 0

    def test_process_scan_all(self):
        from aegorx.cli import main
        result = main(["process", "scan-all", "--skip-self"])
        # Should succeed
        assert result in (0, 1)
