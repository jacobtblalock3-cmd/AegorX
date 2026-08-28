from __future__ import annotations

import json
import os
import platform
import struct
import sys
import time

import pytest

from aegorx.engine import ScanEngine
from aegorx.realtime.events import FileEvent, PathFilter, RealtimeUnavailableError
from aegorx.realtime.inotify_backend import EVENT_HEADER, parse_events
from aegorx.realtime.fanotify_backend import METADATA_STRUCT, parse_metadata
from aegorx.realtime.monitor import RealTimeMonitor, default_excludes, select_backend


class FakeBackend:
    name = "fake"

    def __init__(self, paths):
        self.paths = list(paths)
        self.on_event = None
        self.decide = None
        self.started = False
        self.stopped = False

    @staticmethod
    def available():
        return True

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def watched_count(self):
        return 0


@pytest.fixture
def monitor(tmp_home, rules_dir, monkeypatch):
    monkeypatch.setattr(
        "aegorx.realtime.monitor.select_backend",
        lambda name, paths, excludes=None: FakeBackend(paths),
    )
    engine = ScanEngine(rules_dirs=[rules_dir], enable_ml=False)
    log = os.path.join(tmp_home, "realtime.log")
    mon = RealTimeMonitor(
        engine,
        ["/tmp/watchme"],
        backend="auto",
        workers=2,
        quarantine=True,
        log_path=log,
    )
    return mon


def drain(monitor):
    monitor.pool.shutdown(wait=True)


def test_path_filter_matching():
    f = PathFilter(["/home/*/.aegorx/*", "/var/log/*.log"])
    assert f.excluded("/home/jacob/.aegorx/signatures.db")
    assert f.excluded("/var/log/app.log")
    assert not f.excluded("/var/log")
    assert not f.excluded("/etc/passwd")


def test_default_excludes_cover_state_dir(tmp_home):
    from aegorx.utils import state_dir

    excludes = default_excludes()
    filt = PathFilter(excludes)
    assert filt.excluded(os.path.join(state_dir(), "quarantine", "x.quar"))
    assert filt.excluded(os.path.join(state_dir(), "signatures.db"))
    assert not filt.excluded("/usr/bin/ls")


def test_inotify_parse_events_roundtrip():
    buf = bytearray()
    for wd, mask, name in [(3, 0x8, b"evil.exe"), (4, 0x40000100, b"newdir"), (3, 0x80, b"a b.txt")]:
        raw_name = name + b"\x00"
        buf += EVENT_HEADER.pack(wd, mask, 0, len(raw_name)) + raw_name
    events = parse_events(bytes(buf))
    assert [(e.wd, e.mask, e.name) for e in events] == [
        (3, 0x8, "evil.exe"),
        (4, 0x40000100, "newdir"),
        (3, 0x80, "a b.txt"),
    ]


def test_inotify_parse_events_empty_and_truncated():
    assert parse_events(b"") == []
    partial = EVENT_HEADER.pack(1, 2, 0, 64) + b"sho"
    assert parse_events(partial) == []


def test_fanotify_parse_metadata_roundtrip():
    buf = bytearray()
    masks_fds = [(0x10000, 7, 1234), (0x20, -1, 99)]
    for mask, fd, pid in masks_fds:
        buf += METADATA_STRUCT.pack(METADATA_STRUCT.size, 3, 0, METADATA_STRUCT.size, mask, fd, pid)
    events = parse_metadata(bytes(buf))
    assert [(e["mask"], e["fd"], e["pid"]) for e in events] == masks_fds


def test_fanotify_parse_metadata_stops_at_truncation():
    good = METADATA_STRUCT.pack(24, 3, 0, 24, 5, 6, 7)
    assert len(parse_metadata(good)) == 1
    bad = good[:-4]
    assert len(parse_metadata(bad)) == 0


def test_monitor_end_to_end_quarantine_and_log(monitor, tmp_home, eicar_file):
    mon = monitor
    mon.backend.start()
    assert mon.backend.started

    mon._dispatch(FileEvent(path=eicar_file, kind="close_write"))
    drain(mon)

    assert not os.path.exists(eicar_file)
    items = mon.vault.list_items()
    assert len(items) == 1
    assert items[0]["encrypted"] in (True, False)
    s = mon.summary()
    assert s["received"] == 1
    assert s["scanned"] == 1
    assert s["malicious"] == 1
    assert s["quarantined"] == 1

    with open(mon.log_path) as fh:
        records = [json.loads(line) for line in fh if line.strip()]
    hits = [r for r in records if r.get("verdict") == "malicious"]
    assert hits and hits[0]["path"] == eicar_file
    assert hits[0]["detections"][0]["detector"] in ("signature", "yara")

    mon.stop()
    assert mon.backend.stopped


def test_monitor_clean_file_no_quarantine(monitor, benign_file):
    mon = monitor
    mon.backend.start()
    mon._dispatch(FileEvent(path=benign_file, kind="moved_to"))
    drain(mon)
    assert os.path.exists(benign_file)
    assert mon.summary()["malicious"] == 0
    assert not os.path.exists(mon.log_path) or all(
        json.loads(l).get("verdict") != "malicious" for l in open(mon.log_path) if l.strip()
    )


def test_monitor_excludes_state_dir(monitor):
    from aegorx.utils import state_dir

    inside = os.path.join(state_dir(), "something.db")
    mon = monitor
    mon.backend.start()
    mon._dispatch(FileEvent(path=inside, kind="close_write"))
    drain(mon)
    assert mon.summary()["skipped"] == 1
    assert mon.summary()["scanned"] == 0


def test_fanotify_decide_denies_malicious(monitor, eicar_file):
    mon = monitor
    mon.backend.start()
    allowed = mon._decide_open(FileEvent(path=eicar_file, kind="open_perm", pid=42))
    drain(mon)
    assert allowed is False
    assert mon.summary()["malicious"] == 1


def test_select_backend_rejects_unknown():
    with pytest.raises(RealtimeUnavailableError):
        select_backend("bogus", [])


@pytest.mark.skipif(platform.system() == "Linux", reason="meaningful only off-Linux")
def test_backends_unavailable_off_linux():
    """On non-Linux, fanotify and inotify are unavailable; auto picks a cross-platform backend."""
    from aegorx.realtime.fanotify_backend import FanotifyBackend
    from aegorx.realtime.inotify_backend import InotifyBackend

    assert not FanotifyBackend.available()
    assert not InotifyBackend.available()
    # auto should now succeed on macOS/Windows via fswatch
    backend = select_backend("auto", ["/tmp" if platform.system() == "Darwin" else "C:\\"])
    assert backend.name in ("fswatch", "es", "minifilter")


def test_fswatch_backend_available():
    from aegorx.realtime.fswatch_backend import (
        FSwatchMacOSBackend,
        FSwatchWindowsBackend,
        create_fswatch_backend,
    )

    system = platform.system()
    if system == "Darwin":
        assert FSwatchMacOSBackend.available()
        backend = create_fswatch_backend(["/tmp"])
        assert backend.name == "fswatch"
        assert backend.watched_count() == 0
    elif system == "Windows":
        assert FSwatchWindowsBackend.available()
        backend = create_fswatch_backend(["C:\\"])
        assert backend.name == "fswatch"
    else:
        assert not FSwatchMacOSBackend.available()
        assert not FSwatchWindowsBackend.available()


def test_select_backend_fswatch():
    from aegorx.realtime.fswatch_backend import create_fswatch_backend

    system = platform.system()
    if system in ("Darwin", "Windows"):
        backend = select_backend("fswatch", ["/tmp" if system == "Darwin" else "C:\\"])
        assert backend.name == "fswatch"
        assert backend.watched_count() == 0  # /tmp is a dir but not watched yet


def test_select_backend_auto_cross_platform():
    """On any platform, 'auto' should either succeed or raise cleanly."""
    system = platform.system()
    try:
        backend = select_backend("auto", ["/tmp" if system != "Windows" else "C:\\"])
        assert backend.name in ("fanotify", "inotify", "fswatch", "es", "minifilter")
    except RealtimeUnavailableError:
        pass  # Acceptable on platforms with no backend


def test_non_linux_backend_selection_fails_cleanly():
    """On Windows/macOS, explicit Linux backends must raise a domain error."""
    system = platform.system()
    if system == "Linux":
        pytest.skip("Linux — Linux backends are available here")

    for name in ("fanotify", "inotify"):
        with pytest.raises(RealtimeUnavailableError):
            select_backend(name, ["/tmp"])


@pytest.mark.skipif(sys.platform == "linux", reason="exercises the non-Linux fallback path")
def test_non_linux_backend_selection_fails_cleanly():
    """On Windows/macOS, explicit Linux backends must raise a domain error,
    never AttributeError from os.geteuid or an import of Linux-only modules."""
    for name in ("fanotify", "inotify"):
        with pytest.raises(RealtimeUnavailableError):
            select_backend(name, ["/tmp"])
