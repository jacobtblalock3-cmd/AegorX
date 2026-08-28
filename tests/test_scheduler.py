"""Tests for scheduled scan management."""

from __future__ import annotations

import pytest

from aegorx.scheduler import get_scheduler, PythonScheduler


class TestSchedulerFactory:
    def test_returns_scheduler(self):
        scheduler = get_scheduler()
        assert scheduler is not None

    def test_python_scheduler(self):
        scheduler = PythonScheduler()
        assert not scheduler.is_running()
        scheduler.start(interval_hours=0.001)
        assert scheduler.is_running()
        scheduler.stop()
        assert not scheduler.is_running()

    def test_python_scheduler_stop_idempotent(self):
        scheduler = PythonScheduler()
        scheduler.stop()  # should be no-op
        assert not scheduler.is_running()

    def test_python_scheduler_double_start(self):
        scheduler = PythonScheduler()
        scheduler.start(interval_hours=24)
        scheduler.start()  # should be no-op
        assert scheduler.is_running()
        scheduler.stop()


class TestSystemdScheduler:
    def test_not_installed_by_default(self):
        pytest.importorskip("shutil", reason="needs shutil")
        from aegorx.scheduler import SystemdScheduler
        scheduler = SystemdScheduler()
        # Don't actually install, just check the interface
        assert hasattr(scheduler, "install")
        assert hasattr(scheduler, "uninstall")
        assert hasattr(scheduler, "is_installed")
        assert hasattr(scheduler, "status")


class TestLaunchdScheduler:
    def test_not_installed_by_default(self):
        from aegorx.scheduler import LaunchdScheduler
        scheduler = LaunchdScheduler()
        assert hasattr(scheduler, "install")
        assert hasattr(scheduler, "uninstall")
        assert hasattr(scheduler, "is_installed")
        assert hasattr(scheduler, "status")
