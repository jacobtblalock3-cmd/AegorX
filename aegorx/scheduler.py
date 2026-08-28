"""Scheduled scan management.

Provides OS-native scheduled scanning via:
  Linux:   systemd timer + service unit
  macOS:   launchd plist
  Windows: Task Scheduler (schtasks.exe)

Also provides a fallback Python-level scheduler for environments
where OS-level scheduling is unavailable.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
import xml.sax.saxutils
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Schedule configuration
# ---------------------------------------------------------------------------

DEFAULT_SCHEDULE = {
    "interval_hours": 24,
    "scan_paths": ["/"],
    "max_file_size_mb": 512,
    "enable_ml": True,
    "enable_yara": True,
}


# ---------------------------------------------------------------------------
# Systemd (Linux)
# ---------------------------------------------------------------------------

_SYSTEMD_SERVICE = """\
[Unit]
Description=Defentra scheduled scan
After=network.target

[Service]
Type=oneshot
ExecStart={python} -m aegorx.cli scan {paths} --max-size-mb {max_size_mb} {ml_flag} {yara_flag} --json --log {log_path}
Nice=19
IOSchedulingClass=idle
"""

_SYSTEMD_TIMER = """\
[Unit]
Description=Defentra scheduled scan timer

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
"""


class SystemdScheduler:
    """Install scheduled scans via systemd timer."""

    def __init__(self) -> None:
        self._unit_dir = os.path.expanduser("~/.config/systemd/user")

    @staticmethod
    def _validate_path(path: str) -> bool:
        """Validate a scan path is safe (no shell metacharacters)."""
        dangerous = set('|;&$`\\!{}()<>')
        return bool(path) and not any(c in path for c in dangerous)

    def install(self, scan_paths: List[str], interval_hours: int = 24) -> bool:
        try:
            os.makedirs(self._unit_dir, exist_ok=True)
            python = sys.executable
            # Validate and shell-escape paths to prevent injection
            paths = " ".join(shlex.quote(p) for p in scan_paths if self._validate_path(p))
            if not paths:
                return False
            log_path = os.path.join(os.path.expanduser("~"), ".aegorx", "scheduled-scan.log")
            log_path = shlex.quote(log_path)

            service = _SYSTEMD_SERVICE.format(
                python=shlex.quote(python),
                paths=paths,
                max_size_mb=DEFAULT_SCHEDULE["max_file_size_mb"],
                ml_flag="" if DEFAULT_SCHEDULE["enable_ml"] else "--no-ml",
                yara_flag="",
                log_path=log_path,
            )
            timer = _SYSTEMD_TIMER

            with open(os.path.join(self._unit_dir, "aegorx-scan.service"), "w") as fh:
                fh.write(service)
            with open(os.path.join(self._unit_dir, "aegorx-scan.timer"), "w") as fh:
                fh.write(timer)

            subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=10)
            subprocess.run(["systemctl", "--user", "enable", "aegorx-scan.timer"], capture_output=True, timeout=10)
            subprocess.run(["systemctl", "--user", "start", "aegorx-scan.timer"], capture_output=True, timeout=10)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def uninstall(self) -> bool:
        try:
            subprocess.run(["systemctl", "--user", "stop", "aegorx-scan.timer"], capture_output=True, timeout=10)
            subprocess.run(["systemctl", "--user", "disable", "aegorx-scan.timer"], capture_output=True, timeout=10)
            for name in ("aegorx-scan.service", "aegorx-scan.timer"):
                path = os.path.join(self._unit_dir, name)
                if os.path.exists(path):
                    os.unlink(path)
            subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=10)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def is_installed(self) -> bool:
        try:
            result = subprocess.run(
                ["systemctl", "--user", "is-enabled", "aegorx-scan.timer"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def status(self) -> Dict:
        try:
            result = subprocess.run(
                ["systemctl", "--user", "status", "aegorx-scan.timer", "--no-pager"],
                capture_output=True, timeout=5,
            )
            return {"installed": self.is_installed(), "output": result.stdout.decode()}
        except (OSError, subprocess.SubprocessError):
            return {"installed": False, "output": ""}


# ---------------------------------------------------------------------------
# Launchd (macOS)
# ---------------------------------------------------------------------------

_PLIST_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegorx.scheduled-scan</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>-m</string>
        <string>aegorx.cli</string>
        <string>scan</string>
        {scan_paths_xml}
        <string>--max-size-mb</string>
        <string>{max_size_mb}</string>
        <string>--json</string>
        <string>--log</string>
        <string>{log_path}</string>
    </array>
    <key>StartInterval</key>
    <integer>{interval_seconds}</integer>
    <key>StandardOutPath</key>
    <string>{log_path}</string>
    <key>StandardErrorPath</key>
    <string>{error_log}</string>
    <key>LowPriorityIO</key>
    <true/>
    <key>Nice</key>
    <integer>20</integer>
</dict>
</plist>
"""


class LaunchdScheduler:
    """Install scheduled scans via launchd."""

    LABEL = "com.aegorx.scheduled-scan"

    def __init__(self) -> None:
        self._plist_dir = os.path.expanduser("~/Library/LaunchAgents")
        self._plist_path = os.path.join(self._plist_dir, f"{self.LABEL}.plist")

    @staticmethod
    def _validate_path(path: str) -> bool:
        """Validate a scan path is safe (no shell metacharacters)."""
        dangerous = set('|;&$`\\!{}()<>')
        return bool(path) and not any(c in path for c in dangerous)

    def install(self, scan_paths: List[str], interval_hours: int = 24) -> bool:
        try:
            os.makedirs(self._plist_dir, exist_ok=True)
            python = sys.executable
            log_path = os.path.join(os.path.expanduser("~"), ".aegorx", "scheduled-scan.log")
            error_log = os.path.join(os.path.expanduser("~"), ".aegorx", "scheduled-scan-error.log")

            # XML-escape paths to prevent injection
            scan_paths_xml = "\n        ".join(
                f"<string>{xml.sax.saxutils.escape(p)}</string>"
                for p in scan_paths if self._validate_path(p)
            )
            if not scan_paths_xml:
                return False

            plist = _PLIST_TEMPLATE.format(
                python=xml.sax.saxutils.escape(python),
                scan_paths_xml=scan_paths_xml,
                max_size_mb=DEFAULT_SCHEDULE["max_size_mb"],
                interval_seconds=int(interval_hours * 3600),
                log_path=xml.sax.saxutils.escape(log_path),
                error_log=xml.sax.saxutils.escape(error_log),
            )

            with open(self._plist_path, "w") as fh:
                fh.write(plist)

            # Unload first if already loaded
            subprocess.run(["launchctl", "unload", self._plist_path], capture_output=True, timeout=10)
            subprocess.run(["launchctl", "load", self._plist_path], capture_output=True, timeout=10)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def uninstall(self) -> bool:
        try:
            subprocess.run(["launchctl", "unload", self._plist_path], capture_output=True, timeout=10)
            if os.path.exists(self._plist_path):
                os.unlink(self._plist_path)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def is_installed(self) -> bool:
        return os.path.exists(self._plist_path)

    def status(self) -> Dict:
        try:
            result = subprocess.run(
                ["launchctl", "list", self.LABEL],
                capture_output=True, timeout=5,
            )
            return {"installed": self.is_installed(), "output": result.stdout.decode()}
        except (OSError, subprocess.SubprocessError):
            return {"installed": self.is_installed(), "output": ""}


# ---------------------------------------------------------------------------
# Task Scheduler (Windows)
# ---------------------------------------------------------------------------

class TaskScheduler:
    """Install scheduled scans via Windows Task Scheduler (schtasks.exe)."""

    TASK_NAME = "AegorXScheduledScan"

    def install(self, scan_paths: List[str], interval_hours: int = 24) -> bool:
        try:
            python = sys.executable
            # Validate paths and build command safely
            validated = [p for p in scan_paths if self._validate_path(p)]
            if not validated:
                return False
            paths_str = " ".join(f'"{p}"' for p in validated)
            log_path = os.path.join(os.path.expanduser("~"), ".aegorx", "scheduled-scan.log")

            # Use list args instead of shell=True to prevent injection
            cmd = [
                "schtasks", "/create",
                "/tn", self.TASK_NAME,
                "/tr", f'"{python} -m aegorx.cli scan {paths_str} --json --log {log_path}"',
                "/sc", "daily", "/st", "02:00",
                "/rl", "LOW", "/f",
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=15)
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def uninstall(self) -> bool:
        try:
            result = subprocess.run(
                ["schtasks", "/delete", "/tn", self.TASK_NAME, "/f"],
                capture_output=True, timeout=10,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def is_installed(self) -> bool:
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/tn", self.TASK_NAME],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def status(self) -> Dict:
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/tn", self.TASK_NAME, "/fo", "LIST"],
                capture_output=True, timeout=5,
            )
            return {"installed": self.is_installed(), "output": result.stdout.decode()}
        except (OSError, subprocess.SubprocessError):
            return {"installed": self.is_installed(), "output": ""}

    @staticmethod
    def _validate_path(path: str) -> bool:
        """Validate a scan path is safe (no shell metacharacters)."""
        # Reject paths with dangerous characters
        dangerous = set('|;&$`\\!{}()<>')
        return bool(path) and not any(c in path for c in dangerous)


# ---------------------------------------------------------------------------
# Python-level fallback scheduler
# ---------------------------------------------------------------------------

class PythonScheduler:
    """Fallback scheduler using a background thread.

    Used when OS-level scheduling is unavailable.
    Runs scans in-process at the specified interval.
    """

    def __init__(self, scan_fn=None) -> None:
        self._scan_fn = scan_fn
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._interval = 86400  # 24 hours default
        self._last_run = 0.0

    def start(self, interval_hours: float = 24) -> None:
        if self._thread is not None:
            return
        self._interval = int(interval_hours * 3600)
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="aegorx-sched")
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop_evt.wait(timeout=60):
            if time.time() - self._last_run >= self._interval:
                self._last_run = time.time()
                if self._scan_fn:
                    try:
                        self._scan_fn()
                    except Exception:
                        pass

    def is_running(self) -> bool:
        return self._thread is not None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_scheduler():
    """Return the appropriate platform-specific scheduler."""
    if sys.platform == "linux":
        if shutil.which("systemctl"):
            return SystemdScheduler()
    if sys.platform == "darwin":
        return LaunchdScheduler()
    if sys.platform == "win32":
        return TaskScheduler()
    return PythonScheduler()
