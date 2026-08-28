"""Tests for ransomware canary detection."""

from __future__ import annotations

import math
import os
import time

import pytest

from aegorx.ransomware import (
    CanaryManager,
    CanaryFile,
    VelocityDetector,
    EntropyDetector,
    ExtensionMonitor,
    RansomwareDetector,
    RansomwareEvent,
    file_entropy,
    file_hash,
    is_ransomware_extension,
    is_ransom_note,
    CANARY_MARKER,
    RANSOMWARE_EXTENSIONS,
    RANSOM_NOTE_NAMES,
)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

class TestFileEntropy:
    def test_empty_file(self, tmp_path):
        p = str(tmp_path / "empty.bin")
        with open(p, "wb") as f:
            pass
        assert file_entropy(p) == 0.0

    def test_single_byte(self, tmp_path):
        p = str(tmp_path / "one.bin")
        with open(p, "wb") as f:
            f.write(b"\x00")
        assert file_entropy(p) == 0.0

    def test_random_data(self, tmp_path):
        p = str(tmp_path / "random.bin")
        # High entropy data
        data = bytes(range(256)) * 100
        with open(p, "wb") as f:
            f.write(data)
        assert file_entropy(p) > 7.0

    def test_repetitive_data(self, tmp_path):
        p = str(tmp_path / "repetitive.bin")
        with open(p, "wb") as f:
            f.write(b"\x41" * 10000)
        assert file_entropy(p) < 1.0

    def test_nonexistent_file(self):
        assert file_entropy("/nonexistent/path") == 0.0


class TestFileHash:
    def test_known_content(self, tmp_path):
        p = str(tmp_path / "test.txt")
        with open(p, "wb") as f:
            f.write(b"hello world")
        h = file_hash(p)
        assert len(h) == 64  # SHA-256 hex
        assert h == file_hash(p)  # deterministic

    def test_different_content(self, tmp_path):
        p1 = str(tmp_path / "a.txt")
        p2 = str(tmp_path / "b.txt")
        with open(p1, "wb") as f:
            f.write(b"aaa")
        with open(p2, "wb") as f:
            f.write(b"bbb")
        assert file_hash(p1) != file_hash(p2)

    def test_nonexistent_file(self):
        assert file_hash("/nonexistent/path") == ""


class TestRansomwareExtension:
    def test_known_extensions(self):
        assert is_ransomware_extension("file.locked")
        assert is_ransomware_extension("file.encrypted")
        assert is_ransomware_extension("file.crypto")
        assert is_ransomware_extension("file.wncry")
        assert is_ransomware_extension("file.ryuk")

    def test_unknown_extensions(self):
        assert not is_ransomware_extension("file.txt")
        assert not is_ransomware_extension("file.py")
        assert not is_ransomware_extension("file.pdf")

    def test_case_insensitive(self):
        assert is_ransomware_extension("file.LOCKED")
        assert is_ransomware_extension("file.Encrypted")


class TestRansomNote:
    def test_known_notes(self):
        assert is_ransom_note("readme.txt")
        assert is_ransom_note("how_to_decrypt.html")
        assert is_ransom_note("restore_files.txt")
        assert is_ransom_note("_readme.txt")

    def test_unknown_files(self):
        assert not is_ransom_note("normal_file.txt")
        assert not is_ransom_note("report.pdf")


# ---------------------------------------------------------------------------
# Canary Manager
# ---------------------------------------------------------------------------

class TestCanaryManager:
    def test_deploy_creates_files(self, tmp_path):
        mgr = CanaryManager(canary_dir=str(tmp_path / "canaries"))
        count = mgr.deploy([str(tmp_path)])
        assert count > 0
        canaries = mgr.list_canaries()
        assert len(canaries) > 0
        for c in canaries:
            assert os.path.exists(c.path)
            assert c.original_hash

    def test_deploy_idempotent(self, tmp_path):
        mgr = CanaryManager(canary_dir=str(tmp_path / "canaries"))
        count1 = mgr.deploy([str(tmp_path)])
        count2 = mgr.deploy([str(tmp_path)])
        assert count2 == 0  # no new canaries

    def test_check_clean(self, tmp_path):
        mgr = CanaryManager(canary_dir=str(tmp_path / "canaries"))
        mgr.deploy([str(tmp_path)])
        modified = mgr.check_all()
        assert len(modified) == 0

    def test_check_modified(self, tmp_path):
        mgr = CanaryManager(canary_dir=str(tmp_path / "canaries"))
        mgr.deploy([str(tmp_path)])
        canaries = mgr.list_canaries()
        # Modify a canary
        with open(canaries[0].path, "a") as f:
            f.write("MALICIOUS CONTENT")
        modified = mgr.check_all()
        assert len(modified) >= 1
        assert modified[0][1] == "modified"

    def test_check_deleted(self, tmp_path):
        mgr = CanaryManager(canary_dir=str(tmp_path / "canaries"))
        mgr.deploy([str(tmp_path)])
        canaries = mgr.list_canaries()
        os.unlink(canaries[0].path)
        modified = mgr.check_all()
        assert len(modified) >= 1
        assert modified[0][1] == "deleted"

    def test_remove_all(self, tmp_path):
        mgr = CanaryManager(canary_dir=str(tmp_path / "canaries"))
        mgr.deploy([str(tmp_path)])
        count = mgr.remove_all()
        assert count > 0
        assert len(mgr.list_canaries()) == 0

    def test_max_canaries_per_dir(self, tmp_path):
        mgr = CanaryManager(canary_dir=str(tmp_path / "canaries"), max_canaries_per_dir=2)
        count = mgr.deploy([str(tmp_path)])
        assert count == 2

    def test_persistence(self, tmp_path):
        canary_dir = str(tmp_path / "canaries")
        mgr1 = CanaryManager(canary_dir=canary_dir)
        mgr1.deploy([str(tmp_path)])
        count1 = len(mgr1.list_canaries())

        mgr2 = CanaryManager(canary_dir=canary_dir)
        count2 = len(mgr2.list_canaries())
        assert count1 == count2


# ---------------------------------------------------------------------------
# Velocity Detector
# ---------------------------------------------------------------------------

class TestVelocityDetector:
    def test_below_threshold(self):
        vd = VelocityDetector(window_seconds=10, threshold=5)
        for i in range(4):
            result = vd.record(f"file{i}.txt")
        assert result is None

    def test_above_threshold(self):
        vd = VelocityDetector(window_seconds=10, threshold=3)
        for i in range(5):
            result = vd.record(f"file{i}.txt")
        assert result is not None
        assert result >= 3

    def test_window_expiry(self):
        vd = VelocityDetector(window_seconds=0.1, threshold=5)
        vd.record("a.txt")
        time.sleep(0.15)
        # Old entry expired, only 1 new entry
        result = vd.record("b.txt")
        assert result is None  # below threshold

    def test_reset(self):
        vd = VelocityDetector(threshold=2)
        vd.record("a.txt")
        vd.record("b.txt")
        vd.reset()
        result = vd.record("c.txt")
        assert result is None


# ---------------------------------------------------------------------------
# Entropy Detector
# ---------------------------------------------------------------------------

class TestEntropyDetector:
    def test_no_spike(self, tmp_path):
        ed = EntropyDetector(spike_threshold=2.0)
        p = str(tmp_path / "file.bin")
        with open(p, "wb") as f:
            f.write(b"\x41" * 10000)  # low entropy
        ed.update_baseline(p)
        result = ed.check(p)
        assert result is None

    def test_spike_detected(self, tmp_path):
        ed = EntropyDetector(spike_threshold=1.0, min_entropy=5.0)
        p = str(tmp_path / "file.bin")
        # Write low entropy data as baseline
        with open(p, "wb") as f:
            f.write(b"\x41" * 10000)
        ed.update_baseline(p)
        # Overwrite with high entropy data
        with open(p, "wb") as f:
            f.write(bytes(range(256)) * 100)
        result = ed.check(p)
        assert result is not None
        baseline, current = result
        assert baseline < current


# ---------------------------------------------------------------------------
# Extension Monitor
# ---------------------------------------------------------------------------

class TestExtensionMonitor:
    def test_below_threshold(self):
        em = ExtensionMonitor(window_seconds=10, threshold=3)
        result = em.record_rename("old.txt", "new.locked")
        assert result is None

    def test_above_threshold(self):
        em = ExtensionMonitor(window_seconds=10, threshold=2)
        em.record_rename("a.txt", "a.locked")
        result = em.record_rename("b.txt", "b.locked")
        assert result is not None
        assert result >= 2

    def test_non_ransomware_extension(self):
        em = ExtensionMonitor(threshold=1)
        result = em.record_rename("old.txt", "new.txt")
        assert result is None

    def test_reset(self):
        em = ExtensionMonitor(window_seconds=10, threshold=3)
        em.record_rename("a.txt", "a.locked")
        em.record_rename("b.txt", "b.locked")
        em.reset()
        result = em.record_rename("c.txt", "c.locked")
        assert result is None


# ---------------------------------------------------------------------------
# Ransomware Detector (integration)
# ---------------------------------------------------------------------------

class TestRansomwareDetector:
    def test_deploy_and_check(self, tmp_path):
        canary_dir = str(tmp_path / "canaries")
        mgr = CanaryManager(canary_dir=canary_dir)
        det = RansomwareDetector(canary_manager=mgr)
        count = det.deploy_canaries([str(tmp_path)])
        assert count > 0
        events = det.check_canaries()
        assert len(events) == 0

    def test_canary_modification_event(self, tmp_path):
        canary_dir = str(tmp_path / "canaries")
        mgr = CanaryManager(canary_dir=canary_dir)
        det = RansomwareDetector(canary_manager=mgr)
        det.deploy_canaries([str(tmp_path)])
        canaries = det.canaries.list_canaries()
        with open(canaries[0].path, "a") as f:
            f.write("ENCRYPTED")
        events = det.check_canaries()
        assert len(events) >= 1
        assert events[0].detection_type == "canary"
        assert events[0].severity == 10

    def test_velocity_event(self):
        det = RansomwareDetector()
        event = det.on_file_modified("file1.txt")
        assert event is None  # below threshold
        for i in range(15):
            event = det.on_file_modified(f"file{i}.txt")
        assert event is not None
        assert event.detection_type == "velocity"

    def test_ransom_note_event(self):
        det = RansomwareDetector()
        event = det.on_new_file("/some/path/readme.txt")
        assert event is not None
        assert event.detection_type == "ransom_note"
        assert event.severity == 10

    def test_extension_event(self):
        det = RansomwareDetector()
        for i in range(5):
            det.on_file_renamed(f"file{i}.txt", f"file{i}.locked")
        # Last rename should trigger
        event = det.on_file_renamed("file5.txt", "file5.locked")
        assert event is not None
        assert event.detection_type == "extension"

    def test_stats(self, tmp_path):
        canary_dir = str(tmp_path / "canaries")
        mgr = CanaryManager(canary_dir=canary_dir)
        det = RansomwareDetector(canary_manager=mgr)
        det.deploy_canaries([str(tmp_path)])
        det.check_canaries()
        stats = det.stats()
        assert stats["canaries_deployed"] > 0
        assert stats["checks_performed"] == 1

    def test_events_list(self, tmp_path):
        canary_dir = str(tmp_path / "canaries")
        mgr = CanaryManager(canary_dir=canary_dir)
        det = RansomwareDetector(canary_manager=mgr)
        det.deploy_canaries([str(tmp_path)])
        canaries = det.canaries.list_canaries()
        with open(canaries[0].path, "a") as f:
            f.write("MALICIOUS")
        det.check_canaries()
        events = det.events()
        assert len(events) >= 1

    def test_response_callback(self, tmp_path):
        events_received = []

        def callback(event):
            events_received.append(event)

        canary_dir = str(tmp_path / "canaries")
        mgr = CanaryManager(canary_dir=canary_dir)
        det = RansomwareDetector(canary_manager=mgr, response_callback=callback)
        det.deploy_canaries([str(tmp_path)])
        canaries = det.canaries.list_canaries()
        with open(canaries[0].path, "a") as f:
            f.write("MALICIOUS")

        # Start background check which invokes the callback
        det.start_background_check(interval=0.05)
        time.sleep(0.3)
        det.stop_background_check()

        assert len(events_received) >= 1
        assert events_received[0].detection_type == "canary"

    def test_background_check(self, tmp_path):
        canary_dir = str(tmp_path / "canaries")
        mgr = CanaryManager(canary_dir=canary_dir)
        det = RansomwareDetector(canary_manager=mgr)
        det.deploy_canaries([str(tmp_path)])
        det.start_background_check(interval=0.1)
        assert det._thread is not None
        time.sleep(0.3)
        det.stop_background_check()
        assert det._thread is None

    def test_reset_stats(self, tmp_path):
        canary_dir = str(tmp_path / "canaries")
        mgr = CanaryManager(canary_dir=canary_dir)
        det = RansomwareDetector(canary_manager=mgr)
        det.deploy_canaries([str(tmp_path)])
        det.reset_stats()
        stats = det.stats()
        assert stats["checks_performed"] == 0


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

class TestCLIRansomwareCommands:
    def test_ransomware_no_subcommand(self):
        from aegorx.cli import main
        result = main(["ransomware"])
        assert result == 3  # EXIT_ERROR

    def test_ransomware_status(self):
        from aegorx.cli import main
        result = main(["ransomware", "status"])
        assert result == 0

    def test_ransomware_list(self):
        from aegorx.cli import main
        result = main(["ransomware", "list"])
        assert result == 0

    def test_ransomware_events(self):
        from aegorx.cli import main
        result = main(["ransomware", "events"])
        assert result == 0
