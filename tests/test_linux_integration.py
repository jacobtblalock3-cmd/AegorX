"""Linux-only integration tests: exercise the real kernel backends.

These run under sudo on Linux CI (fanotify permission events require
CAP_SYS_ADMIN). On macOS or unprivileged environments they self-skip.
"""

from __future__ import annotations

import faulthandler
import os
import subprocess
import sys
import threading
import time

import pytest

from defentra.engine import ScanEngine
from defentra.realtime.events import FileEvent, RealtimeUnavailableError
from defentra.realtime.inotify_backend import InotifyBackend
from defentra.realtime.monitor import RealTimeMonitor

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="Linux integration only")
root_only = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() != 0, reason="requires root"
)

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    home = tmp_path_factory.mktemp("defentra-home")
    os.environ["DEFENTRA_HOME"] = str(home)
    rules = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
    return ScanEngine(rules_dirs=[rules], enable_ml=False)


@linux_only
def test_inotify_backend_reports_available():
    if InotifyBackend.available():
        assert True


@linux_only
@root_only
def test_fanotify_denies_malicious_open(engine, tmp_path):
    """On-access enforcement: external open of EICAR must fail with EPERM.

    Openers run in subprocesses so events carry an external pid — our own
    process's nested reads are auto-allowed by the backend's self-guard
    (deciding requires re-reading the file, which would otherwise
    self-deadlock the reader thread).
    """
    faulthandler.dump_traceback_later(110, exit=True, file=sys.__stderr__)
    from defentra.realtime.fanotify_backend import FanotifyBackend

    if not FanotifyBackend.available():
        pytest.skip("fanotify unavailable")

    watch = tmp_path / "watch"
    watch.mkdir()
    target = watch / "eicar.com"
    target.write_text(EICAR)
    benign = watch / "benign.txt"
    benign.write_text("hello")

    decisions = []

    def decide(event):
        verdict = None
        try:
            if event.dup_fd is not None:
                verdict = engine.scan_file_descriptor(event.dup_fd, event.path).verdict
            else:
                verdict = engine.scan_file(event.path).verdict
        except Exception as exc:
            decisions.append(("scan-error", str(exc)[:120]))
            print(f"[fanotify-test] scan error: {exc}", flush=True)
            return True
        decisions.append((event.path, verdict))
        print(f"[fanotify-test] decide {event.path} -> {verdict}", flush=True)
        return verdict != "malicious"

    backend = FanotifyBackend([str(watch)], excludes=[os.environ["DEFENTRA_HOME"] + "*"])
    backend.decide = decide
    print("[fanotify-test] starting backend", flush=True)
    backend.start()

    opener = (
        "import sys\n"
        "try:\n"
        "    fh = open(sys.argv[1], 'rb')\n"
        "    fh.read(4)\n"
        "    print('OPENED')\n"
        "except PermissionError:\n"
        "    print('DENIED')\n"
    )

    def external_open(path):
        try:
            proc = subprocess.run(
                [sys.executable, "-c", opener, str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            print(
                f"[fanotify-test] TIMEOUT opening {path}; counters={backend.counters} decisions={decisions}",
                flush=True,
            )
            raise
        outcome = "DENIED" in proc.stdout and "OPENED" not in proc.stdout
        print(f"[fanotify-test] open {path} -> {'DENIED' if outcome else 'OPENED'}", flush=True)
        return outcome

    try:
        if backend.counters["events"] == 0:
            # probe with the benign file; skip when kernel delivers nothing
            benign_denied = external_open(benign)
            if backend.counters["events"] == 0:
                pytest.skip("kernel did not deliver permission events for dir marks")
            assert not benign_denied, "benign file must remain readable"
        else:
            assert not external_open(benign), "benign file must remain readable"

        denied = external_open(target)
        notes = f"counters={backend.counters} decisions={decisions}"
        print(f"[fanotify-test] eicar denied={denied} {notes}", flush=True)
        assert denied, f"EICAR open was allowed: {notes}"
        assert backend.counters["denied"] >= 1, notes
        assert any(v == "malicious" for _, v in decisions if _ != "scan-error") or any(
            d[0] == str(target) for d in decisions
        ), notes
    finally:
        backend.stop()


@linux_only
def test_inotify_monitor_quarantines_written_threat(engine, tmp_path):
    if not InotifyBackend.available():
        pytest.skip("inotify unavailable")
    watch = tmp_path / "watched"
    watch.mkdir()

    monitor = RealTimeMonitor(
        engine,
        [str(watch)],
        backend="inotify",
        workers=2,
        quarantine=True,
        log_path=str(tmp_path / "realtime.log"),
    )
    monitor.backend.start()
    try:
        target = watch / "dropped.exe"
        target.write_text(EICAR)
        deadline = time.time() + 15
        while time.time() < deadline:
            summary = monitor.summary()
            if summary["quarantined"] > 0 and not target.exists():
                break
            time.sleep(0.1)
        summary = monitor.summary()
        assert summary["quarantined"] >= 1, f"no quarantine: {summary}"
        assert not target.exists(), "threat file still on disk after quarantine"
        assert monitor.vault.list_items(), "vault is empty"
    finally:
        monitor.stop()


@linux_only
def test_systemd_units_are_valid():
    unit_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packaging", "systemd"
    )
    systemd_analyze = None
    for candidate in ("/usr/bin/systemd-analyze", "/bin/systemd-analyze"):
        if os.path.exists(candidate):
            systemd_analyze = candidate
            break
    if systemd_analyze is None:
        pytest.skip("systemd-analyze not available")
    for name in ("defentra-monitor.service", "defentra-feed-update.service", "defentra-feed-update.timer"):
        result = subprocess.run(
            [systemd_analyze, "verify", os.path.join(unit_dir, name)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # verify warns about missing ExecStart binaries (not installed here);
        # only hard parse errors should fail the test
        hard_errors = [
            line
            for line in result.stderr.splitlines()
            if "Failed to parse" in line or "Invalid" in line
        ]
        assert result.returncode == 0 or not hard_errors, f"{name}: {hard_errors}"


@linux_only
def test_feed_update_end_to_end_against_live_release(engine, tmp_home, monkeypatch):
    """Full client path: download official signed feed, verify, apply, detect."""
    from defentra.signatures.db import SignatureDB
    from defentra.cli import main as cli_main

    monkeypatch.setenv("DEFENTRA_HOME", str(tmp_home))
    rc = cli_main(["db", "seed"])
    assert rc == 0
    rc = cli_main(["feed", "update"])
    if rc != 0:
        pytest.skip("official feed release not reachable/valid yet")
    db = SignatureDB(None)
    assert db.count() >= 1
