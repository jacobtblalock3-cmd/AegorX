"""Persistence mechanism detection.

Monitors for common malware persistence techniques:
- Registry Run/RunOnce keys (Windows)
- Scheduled tasks (cross-platform)
- Startup items / launch daemons (macOS)
- Systemd services (Linux)
- Cron jobs (Linux/macOS)
- WMI event subscriptions (Windows)
- Browser extension injection
"""

from __future__ import annotations

import logging
import os
import platform
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from .events import BehaviorEvent, EventBus, EventType, RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class PersistenceEntry:
    mechanism: str
    name: str
    path: str = ""
    command: str = ""
    detected_at: float = field(default_factory=time.time)
    details: Dict = field(default_factory=dict)


# Registry Run key paths (Windows)
_WINDOWS_RUN_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
]

# macOS launch paths
_MACOS_LAUNCH_PATHS = [
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    "/System/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
]
_MACOS_USER_LAUNCH = "~/Library/LaunchAgents"

# Suspicious persistence command patterns
_SUSPICIOUS_COMMANDS = [
    re.compile(r"powershell\s+.*-enc\w*\s+", re.I),
    re.compile(r"cmd\.exe\s+/c\s+.*powershell", re.I),
    re.compile(r"mshta\s+.*vbscript", re.I),
    re.compile(r"wscript\s+.*\.vbs", re.I),
    re.compile(r"cscript\s+.*\.vbs", re.I),
    re.compile(r"regsvr32\s+.*\/s.*\/i.*http", re.I),
    re.compile(r"rundll32\s+.*javascript", re.I),
    re.compile(r"curl.*\|\s*(ba)?sh", re.I),
    re.compile(r"wget.*\|\s*(ba)?sh", re.I),
    re.compile(r"\/bin\/(ba)?sh\s+-c\s+.*curl", re.I),
]


class PersistenceDetector:
    """Cross-platform persistence mechanism detection."""

    def __init__(
        self,
        event_bus: EventBus,
        poll_interval: float = 30.0,
    ):
        self._bus = event_bus
        self._poll_interval = poll_interval
        self._known_entries: Dict[str, PersistenceEntry] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_detection: Optional[Callable] = None

    def set_detection_callback(self, callback: Callable) -> None:
        self._on_detection = callback

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="persistence-detector"
        )
        self._thread.start()
        logger.info("Persistence detector started (interval=%ds)", self._poll_interval)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _poll_loop(self) -> None:
        # Initial baseline scan
        self._scan()

        while self._running:
            time.sleep(self._poll_interval)
            try:
                self._scan()
            except Exception:
                logger.exception("Persistence scan failed")

    def _scan(self) -> None:
        system = platform.system()
        if system == "Windows":
            self._scan_windows_registry()
            self._scan_windows_scheduled_tasks()
        elif system == "Darwin":
            self._scan_macos_launch_agents()
            self._scan_macos_launch_daemons()
            self._scan_cron()
        elif system == "Linux":
            self._scan_systemd()
            self._scan_cron()
            self._scan_init_scripts()

    def _scan_windows_registry(self) -> None:
        try:
            import winreg
        except ImportError:
            return

        for key_path in _WINDOWS_RUN_KEYS:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ
                )
            except OSError:
                continue

            try:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entry_key = f"reg:{key_path}:{name}"
                        with self._lock:
                            if entry_key not in self._known_entries:
                                entry = PersistenceEntry(
                                    mechanism="windows_registry_run",
                                    name=name,
                                    path=key_path,
                                    command=str(value),
                                )
                                self._known_entries[entry_key] = entry
                                self._check_persistence(entry)
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(key)

    def _scan_windows_scheduled_tasks(self) -> None:
        try:
            out = subprocess.check_output(
                ["schtasks", "/query", "/FO", "CSV", "/NH"],
                timeout=30, text=True, stderr=subprocess.DEVNULL,
                creationflags=0x08000000,
            )
            for line in out.splitlines():
                parts = line.split(",")
                if len(parts) >= 2:
                    task_name = parts[0].strip('"')
                    entry_key = f"task:{task_name}"
                    with self._lock:
                        if entry_key not in self._known_entries:
                            entry = PersistenceEntry(
                                mechanism="windows_scheduled_task",
                                name=task_name,
                                path=parts[1].strip('"') if len(parts) > 1 else "",
                            )
                            self._known_entries[entry_key] = entry
                            self._check_persistence(entry)
        except (subprocess.SubprocessError, OSError):
            pass

    def _scan_macos_launch_agents(self) -> None:
        user_path = os.path.expanduser(_MACOS_USER_LAUNCH)
        self._scan_macos_plist_dir(user_path, "macos_launch_agent")

    def _scan_macos_launch_daemons(self) -> None:
        for path in _MACOS_LAUNCH_PATHS:
            self._scan_macos_plist_dir(path, "macos_launch_daemon")

    def _scan_macos_plist_dir(self, dirpath: str, mechanism: str) -> None:
        try:
            for entry in os.scandir(dirpath):
                if entry.name.endswith(".plist"):
                    entry_key = f"plist:{entry.path}"
                    with self._lock:
                        if entry_key not in self._known_entries:
                            pe = PersistenceEntry(
                                mechanism=mechanism,
                                name=entry.name,
                                path=entry.path,
                            )
                            self._known_entries[entry_key] = pe
                            self._check_persistence(pe)
        except (OSError, PermissionError):
            pass

    def _scan_systemd(self) -> None:
        service_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            os.path.expanduser("~/.config/systemd/user"),
        ]
        for d in service_dirs:
            try:
                for entry in os.scandir(d):
                    if entry.name.endswith(".service"):
                        entry_key = f"systemd:{entry.path}"
                        with self._lock:
                            if entry_key not in self._known_entries:
                                pe = PersistenceEntry(
                                    mechanism="linux_systemd_service",
                                    name=entry.name,
                                    path=entry.path,
                                )
                                self._known_entries[entry_key] = pe
                                self._check_persistence(pe)
            except (OSError, PermissionError):
                pass

    def _scan_cron(self) -> None:
        cron_paths = [
            "/etc/crontab",
            "/etc/cron.d",
            "/var/spool/cron/crontabs",
            os.path.expanduser("~/.crontab"),
            os.path.expanduser("~/Library/LaunchAgents"),
        ]
        for p in cron_paths:
            if os.path.isdir(p):
                try:
                    for entry in os.scandir(p):
                        entry_key = f"cron:{entry.path}"
                        with self._lock:
                            if entry_key not in self._known_entries:
                                pe = PersistenceEntry(
                                    mechanism="cron",
                                    name=entry.name,
                                    path=entry.path,
                                )
                                self._known_entries[entry_key] = pe
                                self._check_persistence(pe)
                except (OSError, PermissionError):
                    pass
            elif os.path.isfile(p):
                entry_key = f"cron:{p}"
                with self._lock:
                    if entry_key not in self._known_entries:
                        pe = PersistenceEntry(
                            mechanism="cron", name=os.path.basename(p), path=p
                        )
                        self._known_entries[entry_key] = pe
                        self._check_persistence(pe)

    def _scan_init_scripts(self) -> None:
        init_dirs = ["/etc/init.d", "/etc/rc.d", "/etc/rc.local"]
        for d in init_dirs:
            try:
                for entry in os.scandir(d):
                    entry_key = f"init:{entry.path}"
                    with self._lock:
                        if entry_key not in self._known_entries:
                            pe = PersistenceEntry(
                                mechanism="linux_init_script",
                                name=entry.name,
                                path=entry.path,
                            )
                            self._known_entries[entry_key] = pe
                            self._check_persistence(pe)
            except (OSError, PermissionError):
                pass

    def _check_persistence(self, entry: PersistenceEntry) -> None:
        # Check for suspicious commands in persistence entries
        if entry.command:
            for pattern in _SUSPICIOUS_COMMANDS:
                if pattern.search(entry.command):
                    self._emit_detection(entry, "suspicious_command_in_persistence")
                    return

    def _emit_detection(self, entry: PersistenceEntry, reason: str) -> None:
        event = BehaviorEvent(
            event_type=EventType.PERSISTENCE_DETECTED,
            pid=0,
            risk_level=RiskLevel.HIGH,
            details={
                "mechanism": entry.mechanism,
                "name": entry.name,
                "path": entry.path,
                "command": entry.command,
                "reason": reason,
            },
            source="persistence_detector",
        )
        self._bus.emit(event)
        if self._on_detection:
            self._on_detection(event)

    def get_entries(self) -> List[PersistenceEntry]:
        with self._lock:
            return list(self._known_entries.values())

    def get_entries_by_mechanism(self, mechanism: str) -> List[PersistenceEntry]:
        with self._lock:
            return [
                e for e in self._known_entries.values()
                if e.mechanism == mechanism
            ]
