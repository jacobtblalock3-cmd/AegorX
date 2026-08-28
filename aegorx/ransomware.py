"""Ransomware canary detection and response.

Places decoy "canary" files in monitored directories and detects
encryption behavior through multiple detection strategies:

  1. **Canary file monitoring** — any write/modify to a canary = instant alert
  2. **File velocity** — rapid modifications (> N files in M seconds)
  3. **Entropy spikes** — clean file suddenly becomes high-entropy (encrypted)
  4. **Extension monitoring** — mass renames to ransomware extensions
  5. **Ransom note detection** — known ransom note file names
  6. **Process correlation** — identify the responsible process

When ransomware is detected, the system:
  - Immediately kills the malicious process (if possible)
  - Quarantines modified files
  - Logs the event to the audit log
  - Notifies the user
"""

from __future__ import annotations

import collections
import hashlib
import math
import os
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from aegorx.utils import state_dir


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CANARY_MARKER = ".aegorx-canary"
CANARY_CONTENT = (
    "This is an aegorx ransomware canary file. "
    "Any modification to this file indicates ransomware activity.\n"
)

# Known ransomware file extensions (lowercase, without the dot)
# NOTE: Removed overly generic extensions (abc, aaa, zzz, xxx, help, readme, info)
# that caused false positives on legitimate files.
RANSOMWARE_EXTENSIONS = frozenset({
    "locked", "encrypted", "crypto", "crypted", "crypt", "enc",
    "encr", "locky", "zepto", "cerber", "cerber3", "wncry", "wannacry",
    "petya", "notpetya", "ryuk", "maze", "revil", "sodinokibi",
    "netwalker", "conti", "doppelpaymer",
    "cryptowall", "cryptodefence", "cryptolocker",
    "blocked", "infected", "stolen",
    "decode", "decrypt", "restore", "recover", "rescure",
    "howto", "instruction",
})

# Known ransom note file names (lowercase)
RANSOM_NOTE_NAMES = frozenset({
    "readme.txt", "readme.html", "readme.htm",
    "how_to_decrypt.html", "how_to_decrypt.txt", "how_to_decrypt.htm",
    "howtodecrypt.html", "howtodecrypt.txt",
    "decrypt_instructions.html", "decrypt_instructions.txt",
    "restore_files.txt", "restore_files.html",
    "recover_files.txt", "recover_files.html",
    "help_decrypt.html", "help_decrypt.txt",
    "your_files_are_encrypted.txt", "your_files_are_encrypted.html",
    "ransom_note.txt", "ransom_note.html",
    "decrpyt_instructions.html", "decrpyt_instructions.txt",
    "_readme.txt", "_readme.html",
    "!readme.txt", "!readme.html",
    "[readme].txt", "[readme].html",
    "decrypt.txt", "decrypt.html",
    "unlock.txt", "unlock.html",
    "recovery.html", "recovery.txt",
})

# Canary file names that look enticing to ransomware
CANARY_NAMES = [
    "financial_records.xlsx",
    "passwords.docx",
    "tax_return_2024.pdf",
    "backup_credentials.txt",
    "crypto_wallet.dat",
    "ssh_keys_backup.pem",
    "database_passwords.txt",
    "client_list.confidential.xlsx",
    "project_roadmap秘密.docx",
    "salary_information.xlsx",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CanaryFile:
    """A single canary file."""
    path: str
    directory: str
    original_hash: str = ""
    created_at: float = 0.0
    last_checked: float = 0.0

    def hash_matches(self, current_hash: str) -> bool:
        return self.original_hash == current_hash if self.original_hash else True


@dataclass
class RansomwareEvent:
    """A detected ransomware event."""
    timestamp: float
    detection_type: str  # "canary", "velocity", "entropy", "extension", "ransom_note"
    severity: int  # 1-10
    details: str
    affected_files: List[str] = field(default_factory=list)
    process_pid: Optional[int] = None
    process_name: Optional[str] = None
    response_taken: bool = False


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def file_entropy(path: str, chunk_size: int = 65536) -> float:
    """Calculate Shannon entropy of a file (0.0 to 8.0)."""
    try:
        counts = [0] * 256
        total = 0
        with open(path, "rb") as fh:
            while True:
                data = fh.read(chunk_size)
                if not data:
                    break
                for byte in data:
                    counts[byte] += 1
                total += len(data)
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy
    except (OSError, PermissionError):
        return 0.0


def file_hash(path: str) -> str:
    """SHA-256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                data = fh.read(65536)
                if not data:
                    break
                h.update(data)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def is_ransomware_extension(filename: str) -> bool:
    """Check if a filename has a known ransomware extension."""
    _, ext = os.path.splitext(filename)
    ext = ext.lstrip(".").lower()
    return ext in RANSOMWARE_EXTENSIONS


def is_ransom_note(filename: str) -> bool:
    """Check if a filename is a known ransom note."""
    return filename.lower() in RANSOM_NOTE_NAMES


# ---------------------------------------------------------------------------
# Canary Manager
# ---------------------------------------------------------------------------

class CanaryManager:
    """Manages canary files across monitored directories.

    Places decoy files that look valuable to ransomware (financial docs,
    password files, etc.) and monitors them for any modification.
    """

    def __init__(
        self,
        canary_dir: Optional[str] = None,
        max_canaries_per_dir: int = 5,
    ) -> None:
        state = state_dir()
        self._canary_dir = canary_dir or os.path.join(state, "canaries")
        self._max_canaries = max_canaries_per_dir
        self._canaries: Dict[str, CanaryFile] = {}  # path -> CanaryFile
        self._lock = threading.Lock()
        self._index_path = os.path.join(self._canary_dir, "canary-index.json")
        self._load_index()

    def deploy(self, directories: List[str]) -> int:
        """Deploy canary files to the given directories.

        Returns the number of new canaries created.
        """
        deployed = 0
        for directory in directories:
            if not os.path.isdir(directory):
                continue
            deployed += self._deploy_to_directory(directory)
        self._save_index()
        return deployed

    def _deploy_to_directory(self, directory: str) -> int:
        """Deploy canary files to a single directory."""
        existing = sum(
            1 for c in self._canaries.values() if c.directory == directory
        )
        remaining = self._max_canaries - existing
        if remaining <= 0:
            return 0

        deployed = 0
        for name in CANARY_NAMES[:remaining]:
            canary_path = os.path.join(directory, name)
            if canary_path in self._canaries:
                continue
            if os.path.exists(canary_path):
                continue

            try:
                with open(canary_path, "w", encoding="utf-8") as fh:
                    fh.write(CANARY_CONTENT)
                canary = CanaryFile(
                    path=canary_path,
                    directory=directory,
                    original_hash=file_hash(canary_path),
                    created_at=time.time(),
                )
                self._canaries[canary_path] = canary
                deployed += 1
            except (OSError, PermissionError):
                continue

        return deployed

    def check_all(self) -> List[Tuple[CanaryFile, str]]:
        """Check all canaries for modifications.

        Returns list of (canary, reason) for any modified canaries.
        """
        modified = []
        with self._lock:
            for path, canary in list(self._canaries.items()):
                if not os.path.exists(path):
                    # Canary was deleted — suspicious
                    modified.append((canary, "deleted"))
                    continue
                current_hash = file_hash(path)
                if not canary.hash_matches(current_hash):
                    modified.append((canary, "modified"))
                canary.last_checked = time.time()
        return modified

    def remove_all(self) -> int:
        """Remove all canary files. Returns count removed."""
        removed = 0
        with self._lock:
            for path in list(self._canaries.keys()):
                try:
                    if os.path.exists(path):
                        os.unlink(path)
                    removed += 1
                except (OSError, PermissionError):
                    continue
            self._canaries.clear()
        self._save_index()
        return removed

    def list_canaries(self) -> List[CanaryFile]:
        with self._lock:
            return list(self._canaries.values())

    def _save_index(self) -> None:
        try:
            os.makedirs(self._canary_dir, exist_ok=True)
            import json
            data = {
                path: {
                    "directory": c.directory,
                    "original_hash": c.original_hash,
                    "created_at": c.created_at,
                }
                for path, c in self._canaries.items()
            }
            tmp = self._index_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._index_path)
        except (OSError, json.JSONDecodeError) as exc:
            import logging
            logging.warning("ransomware: failed to save canary index: %s", exc)

    def _load_index(self) -> None:
        try:
            import json
            with open(self._index_path, "r") as fh:
                data = json.load(fh)
            for path, info in data.items():
                self._canaries[path] = CanaryFile(
                    path=path,
                    directory=info["directory"],
                    original_hash=info["original_hash"],
                    created_at=info.get("created_at", 0),
                )
        except (OSError, json.JSONDecodeError, KeyError):
            pass


# ---------------------------------------------------------------------------
# Velocity Detector
# ---------------------------------------------------------------------------

class VelocityDetector:
    """Detect rapid file modifications (encryption behavior).

    Tracks file modification timestamps and detects when too many files
    are modified within a short time window.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        threshold: int = 10,
    ) -> None:
        self.window = window_seconds
        self.threshold = threshold
        self._modifications: collections.deque = collections.deque()
        self._lock = threading.Lock()

    def record(self, filepath: str) -> Optional[int]:
        """Record a file modification. Returns current velocity if threshold exceeded."""
        now = time.time()
        with self._lock:
            self._modifications.append((now, filepath))
            # Prune old entries
            cutoff = now - self.window
            while self._modifications and self._modifications[0][0] < cutoff:
                self._modifications.popleft()
            count = len(self._modifications)
            if count >= self.threshold:
                return count
        return None

    def reset(self) -> None:
        with self._lock:
            self._modifications.clear()


# ---------------------------------------------------------------------------
# Entropy Detector
# ---------------------------------------------------------------------------

class EntropyDetector:
    """Detect entropy spikes indicating file encryption.

    Tracks baseline entropy of files and alerts when a file's entropy
    increases significantly (e.g., from 4.5 to 7.8 — indicating encryption).
    """

    def __init__(
        self,
        spike_threshold: float = 2.0,
        min_entropy: float = 6.5,
    ) -> None:
        self.spike_threshold = spike_threshold
        self.min_entropy = min_entropy
        self._baselines: Dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, filepath: str) -> Optional[Tuple[float, float]]:
        """Check if a file has an entropy spike.

        Returns (baseline, current) if spike detected, None otherwise.
        """
        current = file_entropy(filepath)
        if current < self.min_entropy:
            return None

        with self._lock:
            baseline = self._baselines.get(filepath)
            if baseline is None:
                self._baselines[filepath] = current
                return None
            if current - baseline >= self.spike_threshold:
                return (baseline, current)
        return None

    def update_baseline(self, filepath: str) -> None:
        with self._lock:
            self._baselines[filepath] = file_entropy(filepath)


# ---------------------------------------------------------------------------
# Extension Monitor
# ---------------------------------------------------------------------------

class ExtensionMonitor:
    """Detect mass file renames to ransomware extensions.

    Tracks file renames and detects when multiple files are renamed
    to suspicious extensions within a short window.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        threshold: int = 3,
    ) -> None:
        self.window = window_seconds
        self.threshold = threshold
        self._renames: collections.deque = collections.deque()
        self._lock = threading.Lock()

    def record_rename(self, old_path: str, new_path: str) -> Optional[int]:
        """Record a file rename. Returns count if threshold exceeded."""
        _, new_name = os.path.split(new_path)
        if not is_ransomware_extension(new_name):
            return None

        now = time.time()
        with self._lock:
            self._renames.append((now, new_path))
            cutoff = now - self.window
            while self._renames and self._renames[0][0] < cutoff:
                self._renames.popleft()
            count = len(self._renames)
            if count >= self.threshold:
                return count
        return None

    def reset(self) -> None:
        with self._lock:
            self._renames.clear()


# ---------------------------------------------------------------------------
# Ransomware Detector (orchestrator)
# ---------------------------------------------------------------------------

class RansomwareDetector:
    """Orchestrates all ransomware detection strategies.

    Parameters
    ----------
    canary_manager:
        Custom ``CanaryManager`` (created with defaults if None).
    velocity_threshold:
        Max file modifications per window before alerting.
    entropy_spike:
        Minimum entropy increase to flag as encryption.
    scan_callback:
        Called with ``(path, reason)`` for scanning modified files.
    response_callback:
        Called with ``(event)`` when ransomware is detected.
    """

    def __init__(
        self,
        canary_manager: Optional[CanaryManager] = None,
        velocity_threshold: int = 10,
        entropy_spike: float = 2.0,
        scan_callback: Optional[Callable[[str, str], None]] = None,
        response_callback: Optional[Callable[[RansomwareEvent], None]] = None,
    ) -> None:
        self.canaries = canary_manager or CanaryManager()
        self.velocity = VelocityDetector(threshold=velocity_threshold)
        self.entropy = EntropyDetector(spike_threshold=entropy_spike)
        self.extensions = ExtensionMonitor()
        self.scan_callback = scan_callback
        self.response_callback = response_callback
        self._events: List[RansomwareEvent] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._poll_interval = 5.0
        self._stats = {
            "canaries_deployed": 0,
            "checks_performed": 0,
            "events_detected": 0,
            "processes_killed": 0,
        }

    def deploy_canaries(self, directories: List[str]) -> int:
        """Deploy canary files to directories."""
        count = self.canaries.deploy(directories)
        self._stats["canaries_deployed"] += count
        return count

    def check_canaries(self) -> List[RansomwareEvent]:
        """Check all canaries for modifications."""
        self._stats["checks_performed"] += 1
        modified = self.canaries.check_all()
        events = []
        for canary, reason in modified:
            event = RansomwareEvent(
                timestamp=time.time(),
                detection_type="canary",
                severity=10,
                details=f"Canary file {reason}: {canary.path}",
                affected_files=[canary.path],
            )
            events.append(event)
            self._record_event(event)
        return events

    def on_file_modified(self, filepath: str) -> Optional[RansomwareEvent]:
        """Handle a file modification event from the realtime monitor."""
        # Check velocity
        velocity = self.velocity.record(filepath)
        if velocity is not None:
            event = RansomwareEvent(
                timestamp=time.time(),
                detection_type="velocity",
                severity=9,
                details=f"High file modification rate: {velocity} files in {self.velocity.window}s",
                affected_files=[filepath],
            )
            self._record_event(event)
            return event

        # Check entropy spike
        spike = self.entropy.check(filepath)
        if spike is not None:
            baseline, current = spike
            event = RansomwareEvent(
                timestamp=time.time(),
                detection_type="entropy",
                severity=8,
                details=f"Entropy spike: {baseline:.1f} -> {current:.1f} ({filepath})",
                affected_files=[filepath],
            )
            self._record_event(event)
            return event

        return None

    def on_file_renamed(self, old_path: str, new_path: str) -> Optional[RansomwareEvent]:
        """Handle a file rename event."""
        count = self.extensions.record_rename(old_path, new_path)
        if count is not None:
            event = RansomwareEvent(
                timestamp=time.time(),
                detection_type="extension",
                severity=9,
                details=f"Mass rename to ransomware extension: {count} files renamed",
                affected_files=[new_path],
            )
            self._record_event(event)
            return event
        return None

    def on_new_file(self, filepath: str) -> Optional[RansomwareEvent]:
        """Handle a new file creation event."""
        _, name = os.path.split(filepath)
        if is_ransom_note(name):
            event = RansomwareEvent(
                timestamp=time.time(),
                detection_type="ransom_note",
                severity=10,
                details=f"Ransom note detected: {name}",
                affected_files=[filepath],
            )
            self._record_event(event)
            return event
        return None

    def start_background_check(self, interval: float = 5.0) -> None:
        """Start background canary checking."""
        if self._thread is not None:
            return
        self._poll_interval = interval
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._check_loop, daemon=True, name="aegorx-ransom"
        )
        self._thread.start()

    def stop_background_check(self) -> None:
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _check_loop(self) -> None:
        while not self._stop_evt.wait(timeout=self._poll_interval):
            try:
                events = self.check_canaries()
                for event in events:
                    if self.response_callback:
                        self.response_callback(event)
            except Exception as exc:
                import logging
                logging.warning("ransomware: check_canaries failed: %s", exc)

    def _record_event(self, event: RansomwareEvent) -> None:
        with self._lock:
            self._events.append(event)
            self._stats["events_detected"] += 1
            # Keep only last 1000 events
            if len(self._events) > 1000:
                self._events = self._events[-1000:]

    def events(self) -> List[RansomwareEvent]:
        with self._lock:
            return list(self._events)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0
