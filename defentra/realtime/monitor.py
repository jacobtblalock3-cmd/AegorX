"""Real-time monitor: wires a kernel backend to the scan engine and quarantine vault."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from defentra.engine import ScanEngine
from defentra.quarantine.vault import QuarantineVault
from defentra.realtime.events import (
    BackendBase,
    FileEvent,
    PathFilter,
    RealtimeUnavailableError,
)


def default_excludes() -> List[str]:
    from defentra.utils import state_dir

    return [os.path.join(state_dir(), "*")]


def select_backend(name: str, paths: List[str], excludes: Optional[List[str]] = None) -> BackendBase:
    if name == "inotify":
        from defentra.realtime.inotify_backend import InotifyBackend

        if not InotifyBackend.available():
            raise RealtimeUnavailableError("inotify backend requires Linux")
        return InotifyBackend(paths)
    if name == "fanotify":
        from defentra.realtime.fanotify_backend import FanotifyBackend

        if not FanotifyBackend.available():
            raise RealtimeUnavailableError("fanotify backend requires Linux")
        return FanotifyBackend(paths, excludes=excludes)
    if name != "auto":
        raise RealtimeUnavailableError(f"unknown backend: {name}")

    from defentra.realtime.fanotify_backend import FanotifyBackend
    from defentra.realtime.inotify_backend import InotifyBackend

    if FanotifyBackend.available() and os.geteuid() == 0:
        return FanotifyBackend(paths, excludes=excludes)
    if InotifyBackend.available():
        return InotifyBackend(paths)
    raise RealtimeUnavailableError(
        "no realtime backend available on this platform (requires Linux)"
    )


class RealTimeMonitor:
    """Long-running service: kernel events -> scan -> quarantine/audit log."""

    def __init__(
        self,
        engine: ScanEngine,
        paths: List[str],
        backend: str = "auto",
        workers: int = 4,
        excludes: Optional[List[str]] = None,
        quarantine: bool = True,
        log_path: Optional[str] = None,
    ):
        self.engine = engine
        self.paths = [os.path.abspath(p) for p in paths]
        self.quarantine_enabled = quarantine
        self.log_path = log_path
        self.vault = QuarantineVault()
        all_excludes = default_excludes() + list(excludes or [])
        if log_path:
            all_excludes.append(os.path.abspath(log_path))
        self.filter = PathFilter(all_excludes)
        self.backend = select_backend(backend, self.paths, excludes=all_excludes)
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="defentra-scan")
        self.stats: Dict[str, int] = {
            "received": 0,
            "scanned": 0,
            "malicious": 0,
            "suspicious": 0,
            "quarantined": 0,
            "errors": 0,
            "skipped": 0,
        }
        self._stats_lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._started_at = 0.0

    @property
    def backend_name(self) -> str:
        return self.backend.name

    def run(self) -> None:
        if self.log_path:
            parent = os.path.dirname(os.path.abspath(self.log_path))
            os.makedirs(parent, exist_ok=True)
        self.backend.on_event = self._dispatch
        self.backend.decide = self._decide_open
        self.backend.start()
        self._started_at = time.time()
        print(
            f"[realtime] backend={self.backend.name} pid={os.getpid()} "
            f"watching={len(self.paths)} path(s): {', '.join(self.paths)}",
            flush=True,
        )
        print(
            f"[realtime] signatures={self.engine.db.count()} "
            f"yara={'on' if self.engine.yara.available else 'off'} "
            f"ml={'on' if self.engine.classifier and self.engine.classifier.available else 'off'} "
            f"quarantine={'on' if self.quarantine_enabled else 'off'}",
            flush=True,
        )
        try:
            while not self._stop_evt.wait(timeout=3600.0):
                pass
        except KeyboardInterrupt:
            print("\n[realtime] shutting down...", file=sys.stderr, flush=True)
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop_evt.set()
        try:
            self.backend.stop()
        except Exception:
            pass
        self.pool.shutdown(wait=False)

    def summary(self) -> Dict[str, int]:
        with self._stats_lock:
            stats = dict(self.stats)
        stats["uptime_seconds"] = int(time.time() - self._started_at) if self._started_at else 0
        stats["watched"] = self.backend.watched_count()
        return stats

    def _bump(self, key: str, n: int = 1) -> None:
        with self._stats_lock:
            self.stats[key] += n

    def _dispatch(self, event: FileEvent) -> None:
        self._bump("received")
        path = event.path
        if not path or self.filter.excluded(os.path.abspath(path)):
            self._bump("skipped")
            return
        try:
            if not os.path.isfile(path):
                return
        except OSError:
            return
        self.pool.submit(self._process, event)

    def _process(self, event: FileEvent) -> None:
        result = self._scan_and_log(event)
        if result is None:
            return
        if result.verdict == "malicious":
            self._bump("malicious")
            action = "detected"
            if self.quarantine_enabled:
                entry = self._try_quarantine(event.path, result)
                if entry:
                    action = f"quarantined id={entry['id']}"
                    self._bump("quarantined")
            names = ", ".join(d.name for d in result.detections) or "ml"
            print(
                f"[THREAT] {event.path} ({names}) -> {action}",
                flush=True,
            )
        elif result.verdict == "suspicious":
            self._bump("suspicious")
            names = ", ".join(d.name for d in result.detections) or "ml"
            print(f"[suspicious] {event.path} ({names})", flush=True)

    def _decide_open(self, event: FileEvent) -> bool:
        result = self._scan_and_log(event)
        if result is None:
            return True
        if result.verdict == "malicious":
            self._bump("malicious")
            names = ", ".join(d.name for d in result.detections) or "ml"
            print(f"[BLOCKED] {event.path} ({names}) open denied", flush=True)
            if self.quarantine_enabled:
                entry = self._try_quarantine(event.path, result)
                if entry:
                    self._bump("quarantined")
            return False
        if result.verdict == "suspicious":
            self._bump("suspicious")
        return True

    def _scan_and_log(self, event: FileEvent):
        try:
            result = self.engine.scan_file(event.path)
        except Exception as exc:
            self._bump("errors")
            self._log({"ts": time.time(), "path": event.path, "kind": event.kind, "error": str(exc)})
            return None
        if result.verdict == "error":
            self._bump("errors")
            self._log(
                {
                    "ts": time.time(),
                    "path": event.path,
                    "kind": event.kind,
                    "error": result.error,
                }
            )
            return None
        self._bump("scanned")
        record = {
            "ts": time.time(),
            "pid": event.pid,
            "path": event.path,
            "kind": event.kind,
            "verdict": result.verdict,
            "sha256": result.sha256,
            "detections": [
                {"detector": d.detector, "name": d.name, "severity": d.severity}
                for d in result.detections
            ],
            "ml_probability": result.ml_probability,
        }
        if record["verdict"] != "clean" or record["detections"]:
            self._log(record)
        return result

    def _try_quarantine(self, path: str, result):
        try:
            reason = "; ".join(d.name for d in result.detections) or result.verdict
            return self.vault.quarantine(path, reason=reason)
        except (OSError, FileNotFoundError):
            return None

    def _log(self, record: dict) -> None:
        if not self.log_path:
            return
        line = json.dumps(record, separators=(",", ":"))
        with self._log_lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
