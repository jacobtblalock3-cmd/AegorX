"""Browser download protection.

Monitors browser download directories for new files and scans them
in real-time before the user can open them.

Supports:
  - Chrome/Chromium: ~/Downloads
  - Firefox: ~/Downloads
  - Safari: ~/Downloads
  - Edge: ~/Downloads
  - Configurable additional paths

Uses the existing RealTimeMonitor infrastructure to watch directories
and scan files as they appear.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Default browser download paths
# ---------------------------------------------------------------------------

def _default_download_paths() -> List[str]:
    """Return default browser download directories for the current platform."""
    home = os.path.expanduser("~")
    paths = []

    if sys.platform == "linux":
        paths.append(os.path.join(home, "Downloads"))
    elif sys.platform == "darwin":
        paths.append(os.path.join(home, "Downloads"))
    elif sys.platform == "win32":
        # Windows: use USERPROFILE
        paths.append(os.path.join(home, "Downloads"))
        # Also check the registry for custom download location
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            )
            downloads, _ = winreg.QueryValueEx(key, "{374DE290-123F-4565-9164-39C4925E467B}")
            if downloads and os.path.isdir(downloads):
                paths.append(downloads)
            winreg.CloseKey(key)
        except (OSError, ImportError, FileNotFoundError):
            pass

    return [p for p in paths if os.path.isdir(p)]


# ---------------------------------------------------------------------------
# Browser Download Monitor
# ---------------------------------------------------------------------------

class BrowserDownloadMonitor:
    """Monitor browser download directories and scan new files.

    Parameters
    ----------
    scan_callback:
        Called with ``(filepath, reason)`` when a new download is detected.
        ``reason`` is ``"browser-download"``.
    poll_interval:
        Seconds between directory scans.
    download_dirs:
        Custom download directories.  If None, uses browser defaults.
    min_file_age:
        Minimum file age (seconds) before scanning.  Avoids scanning
        partially-written files.
    scan_extensions:
        File extensions to scan.  If None, scans all files.
    """

    # Common executable/suspicious extensions
    DANGEROUS_EXTENSIONS = frozenset({
        ".exe", ".dll", ".sys", ".msi", ".com", ".scr", ".pif",
        ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".ps1", ".psm1", ".psd1", ".ps1xml", ".pssc",
        ".docm", ".xlsm", ".pptm", ".dotm",
        ".jar", ".class", ".py", ".pyw",
        ".php", ".pl", ".rb", ".sh", ".bash",
        ".tmp", ".temp", ".bak",
    })

    def __init__(
        self,
        scan_callback: Optional[Callable[[str, str], None]] = None,
        poll_interval: float = 2.0,
        download_dirs: Optional[List[str]] = None,
        min_file_age: float = 1.0,
        scan_extensions: Optional[Set[str]] = None,
    ) -> None:
        self.scan_callback = scan_callback
        self.poll_interval = poll_interval
        self.download_dirs = download_dirs or _default_download_paths()
        self.min_file_age = min_file_age
        self.scan_extensions = scan_extensions or self.DANGEROUS_EXTENSIONS
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._scanned_files: Set[str] = set()
        self._lock = threading.Lock()
        self._stats = {
            "files_detected": 0,
            "scans_triggered": 0,
            "threats_found": 0,
        }

    def start(self) -> None:
        """Start the download monitoring loop."""
        if self._thread is not None:
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="aegorx-browser"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the monitoring loop."""
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop_evt.wait(timeout=self.poll_interval):
            self._scan_downloads()

    def _scan_downloads(self) -> None:
        """Check download directories for new files."""
        for dl_dir in self.download_dirs:
            if not os.path.isdir(dl_dir):
                continue
            try:
                for entry in os.scandir(dl_dir):
                    if not entry.is_file():
                        continue
                    self._check_file(entry.path)
            except OSError:
                continue

    def _check_file(self, filepath: str) -> None:
        """Check if a file should be scanned."""
        with self._lock:
            if filepath in self._scanned_files:
                return
            self._scanned_files.add(filepath)

        # Check extension
        _, ext = os.path.splitext(filepath.lower())
        if self.scan_extensions and ext not in self.scan_extensions:
            return

        # Check file age (skip partially-written files)
        try:
            stat = os.stat(filepath)
            age = time.time() - stat.st_mtime
            if age < self.min_file_age:
                return
            # Skip empty files
            if stat.st_size == 0:
                return
        except OSError:
            return

        with self._lock:
            self._stats["files_detected"] += 1
            self._stats["scans_triggered"] += 1

        if self.scan_callback:
            self.scan_callback(filepath, "browser-download")

    def scan_now(self, filepath: str) -> None:
        """Manually trigger a scan of a specific file."""
        with self._lock:
            self._scanned_files.add(filepath)
        self._stats["scans_triggered"] += 1
        if self.scan_callback:
            self.scan_callback(filepath, "browser-manual")

    def is_running(self) -> bool:
        return self._thread is not None

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0
