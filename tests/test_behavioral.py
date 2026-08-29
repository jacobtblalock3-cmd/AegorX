"""Tests for the behavioral analysis engine."""

import os
import signal
import time
import unittest
from unittest.mock import MagicMock, patch

from aegorx.behavioral.events import BehaviorEvent, EventBus, EventType, RiskLevel
from aegorx.behavioral.process_monitor import ProcessMonitor
from aegorx.behavioral.profiler import BehaviorProfiler, ProcessProfile
from aegorx.behavioral.persistence import PersistenceDetector, PersistenceEntry
from aegorx.behavioral.terminator import ProcessTerminator, KillRecord


class TestEventBus(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus(max_history=100)

    def test_emit_and_subscribe(self):
        handler = MagicMock()
        self.bus.subscribe(EventType.PROCESS_CREATED, handler)
        event = BehaviorEvent(event_type=EventType.PROCESS_CREATED, pid=1234)
        self.bus.emit(event)
        handler.assert_called_once_with(event)

    def test_subscribe_all(self):
        handler = MagicMock()
        self.bus.subscribe_all(handler)
        for et in EventType:
            self.bus.emit(BehaviorEvent(event_type=et, pid=1))
        self.assertEqual(handler.call_count, len(EventType))

    def test_unsubscribe(self):
        handler = MagicMock()
        self.bus.subscribe(EventType.FILE_MODIFIED, handler)
        self.bus.unsubscribe(EventType.FILE_MODIFIED, handler)
        self.bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=1))
        handler.assert_not_called()

    def test_handler_exception_does_not_propagate(self):
        def bad_handler(event):
            raise ValueError("boom")

        self.bus.subscribe(EventType.FILE_MODIFIED, bad_handler)
        # Should not raise
        self.bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=1))

    def test_history(self):
        self.bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=1))
        self.bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=2))
        self.bus.emit(BehaviorEvent(event_type=EventType.NETWORK_CONNECTION, pid=1))

        all_events = self.bus.get_history()
        self.assertEqual(len(all_events), 3)

        file_events = self.bus.get_history(event_type=EventType.FILE_MODIFIED)
        self.assertEqual(len(file_events), 2)

        pid_events = self.bus.get_history(pid=2)
        self.assertEqual(len(pid_events), 1)

    def test_stats(self):
        self.bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=1))
        self.bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=2))
        self.bus.emit(BehaviorEvent(event_type=EventType.NETWORK_CONNECTION, pid=1))
        stats = self.bus.stats
        self.assertEqual(stats["file_modified"], 2)
        self.assertEqual(stats["network_connection"], 1)

    def test_max_history(self):
        bus = EventBus(max_history=5)
        for i in range(10):
            bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=i))
        self.assertEqual(len(bus.get_history()), 5)

    def test_clear_history(self):
        self.bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=1))
        self.bus.clear_history()
        self.assertEqual(len(self.bus.get_history()), 0)


class TestProcessProfile(unittest.TestCase):
    def test_initial_risk_is_zero(self):
        profile = ProcessProfile(pid=1)
        self.assertAlmostEqual(profile.risk_score, 0.0)
        self.assertEqual(profile.risk_level, RiskLevel.INFO)

    def test_risk_increases_with_suspicious_events(self):
        profile = ProcessProfile(pid=1)
        profile.suspicious_events = 5
        score = profile.compute_risk()
        self.assertGreater(score, 0.0)
        self.assertGreater(profile.risk_level.value, RiskLevel.INFO.value)

    def test_risk_increases_with_malicious_events(self):
        profile = ProcessProfile(pid=1)
        profile.malicious_events = 1
        score = profile.compute_risk()
        self.assertGreater(score, 0.5)

    def test_risk_increases_with_high_velocity(self):
        profile = ProcessProfile(pid=1)
        now = time.time()
        for i in range(50):
            profile._file_timestamps.append(now - i * 0.1)
        score = profile.compute_risk()
        self.assertGreater(score, 0.0)

    def test_risk_increases_with_extension_changes(self):
        profile = ProcessProfile(pid=1)
        profile.extensions_changed = {".locked": 5, ".encrypted": 3}
        score = profile.compute_risk()
        self.assertGreater(score, 0.2)

    def test_risk_clamps_to_one(self):
        profile = ProcessProfile(pid=1)
        profile.suspicious_events = 1000
        profile.malicious_events = 1000
        profile.injection_events = 1000
        score = profile.compute_risk()
        self.assertLessEqual(score, 1.0)

    def test_file_velocity(self):
        profile = ProcessProfile(pid=1)
        now = time.time()
        for i in range(10):
            profile._file_timestamps.append(now - i * 0.5)
        self.assertGreaterEqual(profile.file_velocity, 10.0)

    def test_dns_velocity(self):
        profile = ProcessProfile(pid=1)
        now = time.time()
        for i in range(100):
            profile._dns_timestamps.append(now - i * 0.1)
        self.assertGreaterEqual(profile.dns_velocity, 100.0)


class TestBehaviorProfiler(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.profiler = BehaviorProfiler(self.bus, auto_subscribe=True)

    def test_creates_profile_on_event(self):
        self.bus.emit(BehaviorEvent(
            event_type=EventType.FILE_MODIFIED, pid=100,
            details={"name": "test.exe"},
        ))
        profile = self.profiler.get_profile(100)
        self.assertIsNotNone(profile)
        self.assertEqual(profile.pid, 100)

    def test_aggregates_file_modifications(self):
        for _ in range(5):
            self.bus.emit(BehaviorEvent(
                event_type=EventType.FILE_MODIFIED, pid=100,
            ))
        profile = self.profiler.get_profile(100)
        self.assertEqual(profile.file_modifications, 5)

    def test_aggregates_network_connections(self):
        for i in range(3):
            self.bus.emit(BehaviorEvent(
                event_type=EventType.NETWORK_CONNECTION, pid=100,
                details={"remote_host": f"192.168.1.{i}"},
            ))
        profile = self.profiler.get_profile(100)
        self.assertEqual(profile.network_connections, 3)
        self.assertEqual(len(profile.unique_remote_hosts), 3)

    def test_risk_callback_fires(self):
        callback = MagicMock()
        self.profiler.set_risk_callback(callback)

        # First emit to create profile
        self.bus.emit(BehaviorEvent(
            event_type=EventType.SUSPICIOUS_BEHAVIOR, pid=100,
            risk_level=RiskLevel.HIGH,
            details={"reasons": ["suspicious"]},
        ))

    def test_get_high_risk(self):
        self.bus.emit(BehaviorEvent(
            event_type=EventType.MALICIOUS_DETECTED, pid=100,
        ))
        high_risk = self.profiler.get_high_risk(min_score=0.5)
        self.assertTrue(any(p.pid == 100 for p in high_risk))

    def test_get_top_offenders(self):
        self.bus.emit(BehaviorEvent(
            event_type=EventType.MALICIOUS_DETECTED, pid=100,
        ))
        self.bus.emit(BehaviorEvent(
            event_type=EventType.SUSPICIOUS_BEHAVIOR, pid=200,
            risk_level=RiskLevel.MEDIUM,
            details={"reasons": ["test"]},
        ))
        top = self.profiler.get_top_offenders(n=5)
        self.assertTrue(len(top) >= 1)

    def test_profile_count(self):
        self.bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=1))
        self.bus.emit(BehaviorEvent(event_type=EventType.FILE_MODIFIED, pid=2))
        self.assertEqual(self.profiler.profile_count, 2)

    def test_extension_tracking(self):
        self.bus.emit(BehaviorEvent(
            event_type=EventType.FILE_RENAMED, pid=100,
            details={"new_extension": ".locked"},
        ))
        self.bus.emit(BehaviorEvent(
            event_type=EventType.FILE_RENAMED, pid=100,
            details={"new_extension": ".locked"},
        ))
        profile = self.profiler.get_profile(100)
        self.assertEqual(profile.extensions_changed[".locked"], 2)


class TestProcessTerminator(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.terminator = ProcessTerminator(self.bus, enabled=True)

    def test_refuses_protected_pid(self):
        result = self.terminator.kill_process(0, reason="test")
        self.assertFalse(result)

    def test_disabled_terminator_does_not_kill(self):
        self.terminator.enabled = False
        with patch("os.kill") as mock_kill:
            result = self.terminator.kill_process(99999, reason="test")
            self.assertFalse(result)
            mock_kill.assert_not_called()

    def test_kill_record_stored(self):
        with patch("os.kill", side_effect=OSError("no such process")):
            self.terminator.kill_process(99999, reason="test", risk_score=0.9)
        history = self.terminator.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].pid, 99999)
        self.assertFalse(history[0].success)

    def test_kill_callback(self):
        callback = MagicMock()
        self.terminator.set_kill_callback(callback)
        with patch("os.kill", side_effect=OSError("no such process")):
            self.terminator.kill_process(99999, reason="test")
        callback.assert_called_once()

    def test_unix_kill_sigterm(self):
        with patch("os.kill") as mock_kill, \
             patch("os.kill", side_effect=[None, OSError("no such process")]):
            # Simulate: first call succeeds, second (check) fails = process dead
            mock_kill.side_effect = [None, OSError("ProcessLookupError")]
            result = self.terminator.kill_process(12345, reason="test")


class TestPersistenceEntry(unittest.TestCase):
    def test_entry_creation(self):
        entry = PersistenceEntry(
            mechanism="windows_registry_run",
            name="TestApp",
            path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            command="C:\\test.exe",
        )
        self.assertEqual(entry.mechanism, "windows_registry_run")
        self.assertEqual(entry.name, "TestApp")
        self.assertGreater(entry.detected_at, 0)


class TestPersistenceDetector(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.detector = PersistenceDetector(self.bus, poll_interval=10)

    def test_entries_list_empty_initially(self):
        entries = self.detector.get_entries()
        self.assertEqual(len(entries), 0)

    def test_entries_by_mechanism(self):
        self.detector._known_entries["test"] = PersistenceEntry(
            mechanism="cron", name="test", path="/etc/cron.d/test"
        )
        entries = self.detector.get_entries_by_mechanism("cron")
        self.assertEqual(len(entries), 1)

    @patch("os.scandir")
    def test_scan_macos_launch_agents(self, mock_scandir):
        mock_entry = MagicMock()
        mock_entry.name = "com.test.plist"
        mock_entry.path = "/Library/LaunchAgents/com.test.plist"
        mock_entry.is_file.return_value = True
        mock_entry.is_dir.return_value = False
        mock_scandir.return_value = [mock_entry]

        with patch("os.path.isdir", return_value=True):
            self.detector._scan_macos_plist_dir(
                "/Library/LaunchAgents", "test_mechanism"
            )

        entries = self.detector.get_entries()
        self.assertTrue(any(e.name == "com.test.plist" for e in entries))


if __name__ == "__main__":
    unittest.main()
