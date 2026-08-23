"""Real-time monitor: wires a kernel backend to the scan engine and quarantine vault."""

from __future__ import annotations

import hashlib
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
from defentra.report import sanitize


class AuditLog:
    """Append-only JSONL audit log with SHA256 hash chaining and size rotation.

    Each record carries seq/prev/hash so any deletion or modification breaks
    the chain detectably (verify_audit_log).
    """

    def __init__(self, path: str, max_bytes: int = 10 * 1024 * 1024, backups: int = 3):
        self.path = os.path.abspath(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = ""
        self._load_chain_state()

    def _load_chain_state(self) -> None:
        try:
            with open(self.path, "rb") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        rec = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(rec.get("seq"), int) and rec.get("hash"):
                        self._seq = max(self._seq, rec["seq"])
                        self._prev_hash = rec["hash"]
        except OSError:
            pass

    def _rotate(self) -> None:
        if os.path.exists(self.path) and os.path.getsize(self.path) < self.max_bytes:
            return
        for i in range(self.backups - 1, 0, -1):
            src, dst = f"{self.path}.{i}", f"{self.path}.{i + 1}"
            if os.path.exists(src):
                os.replace(src, dst)
        if os.path.exists(self.path):
            os.replace(self.path, f"{self.path}.1")

    def write(self, record: dict) -> str:
        line_hash = ""
        with self._lock:
            self._seq += 1
            record = dict(record)
            record["seq"] = self._seq
            record["prev"] = self._prev_hash
            payload = json.dumps(record, separators=(",", ":"), sort_keys=True)
            line_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            record["hash"] = line_hash
            self._rotate()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._prev_hash = line_hash
        return line_hash


def verify_audit_log(path: str) -> tuple:
    """Validate the full hash chain; returns (ok, first_broken_seq)."""
    expected_prev = ""
    expected_seq = 0
    try:
        fh = open(path, "r", encoding="utf-8")
    except OSError:
        return False, 0
    with fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                return False, expected_seq + 1
            stored_hash = rec.pop("hash", None)
            if rec.get("prev") != expected_prev or rec.get("seq") != expected_seq + 1:
                return False, rec.get("seq", expected_seq + 1)
            payload = json.dumps(rec, separators=(",", ":"), sort_keys=True)
            actual = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if stored_hash != actual:
                return False, rec.get("seq", expected_seq + 1)
            expected_prev = stored_hash
            expected_seq = rec["seq"]
    return True, expected_seq


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
        self._inflight = threading.BoundedSemaphore(max(16, workers * 4))
        self.audit = AuditLog(log_path) if log_path else None
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
        self._stop_evt = threading.Event()
        self._started_at = 0.0
        self.backend.on_event = self._dispatch
        self.backend.decide = self._decide_open

    @property
    def backend_name(self) -> str:
        return self.backend.name

    def run(self) -> None:
        if self.log_path:
            parent = os.path.dirname(os.path.abspath(self.log_path))
            os.makedirs(parent, exist_ok=True)
        self.backend.start()
        self._started_at = time.time()
        from defentra.shield import Heartbeat, install_signal_handlers

        self._heartbeat = Heartbeat()
        self._heartbeat.start()
        install_signal_handlers(on_stop=self._stop_evt.set, audit=(self._log if self.audit else None))
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
            if getattr(self, "_heartbeat", None) is not None:
                self._heartbeat.stop()
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
        if not self._inflight.acquire(blocking=False):
            self._bump("skipped")
            if self.audit is not None:
                self._log({"ts": time.time(), "path": sanitize(path), "kind": event.kind, "dropped": "queue_saturated"})
            return
        self.pool.submit(self._process, event)

    def _process(self, event: FileEvent) -> None:
        try:
            self._process_inner(event)
        finally:
            self._inflight.release()

    def _process_inner(self, event: FileEvent) -> None:
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
                f"[THREAT] {sanitize(event.path)} ({names}) -> {action}",
                flush=True,
            )
        elif result.verdict == "suspicious":
            self._bump("suspicious")
            names = ", ".join(d.name for d in result.detections) or "ml"
            print(f"[suspicious] {sanitize(event.path)} ({names})", flush=True)

    def _decide_open(self, event: FileEvent) -> bool:
        result = self._scan_and_log(event)
        if result is None:
            return True
        if result.verdict == "malicious":
            self._bump("malicious")
            names = ", ".join(d.name for d in result.detections) or "ml"
            print(f"[BLOCKED] {sanitize(event.path)} ({names}) open denied", flush=True)
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
        if self.audit is not None:
            self.audit.write(record)
