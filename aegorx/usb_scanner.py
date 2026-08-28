"""USB / removable media auto-scan.

Monitors for newly mounted removable media and triggers a scan:

  Linux:  polls /proc/mounts for removable block devices
  macOS:  polls /Volumes/ for new mount points
  Windows: polls drive letters for removable drives via ctypes

When a new mount is detected, the engine scans the entire mount point
and quarantines any threats found.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Platform detection helpers
# ---------------------------------------------------------------------------

def _is_removable_linux(mount_point: str) -> bool:
    """Check if a Linux mount point is a removable device by reading /proc/mounts."""
    try:
        with open("/proc/mounts", "r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == mount_point:
                    dev = parts[0]
                    # Removable devices are typically /dev/sdX1, /dev/mmcblk0p1, etc.
                    # Non-removable: /dev/sda1 (internal), /dev/nvme0n1p1
                    if dev.startswith("/dev/sd") or dev.startswith("/dev/mmcblk"):
                        # Check /sys/block/*/removable
                        base_dev = dev.split("/")[-1]
                        # Strip partition number to get base device
                        base = re.sub(r"p?\d+$", "", base_dev)
                        removable_path = f"/sys/block/{base}/removable"
                        if os.path.exists(removable_path):
                            with open(removable_path, "r") as rf:
                                return rf.read().strip() == "1"
                    return False
    except (OSError, PermissionError):
        pass
    return False


def _get_mounted_volumes_darwin() -> List[str]:
    """Get mounted volumes on macOS via /Volumes."""
    volumes = []
    try:
        for entry in os.listdir("/Volumes"):
            path = os.path.join("/Volumes", entry)
            if os.path.ismount(path):
                volumes.append(path)
    except OSError:
        pass
    return volumes


def _get_mounted_drives_windows() -> List[str]:
    """Get mounted drive letters on Windows."""
    drives = []
    try:
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(ord("A") + i)
                drive_path = f"{letter}:\\"
                # Check if removable
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                # DRIVE_REMOVABLE = 2
                if drive_type == 2:
                    drives.append(drive_path)
    except (AttributeError, OSError):
        pass
    return drives


def _get_removable_mounts() -> Set[str]:
    """Get current set of removable mount points for the current platform."""
    mounts: Set[str] = set()
    if sys.platform == "linux":
        # Read /proc/mounts for removable devices
        try:
            with open("/proc/mounts", "r") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2:
                        mount_point = parts[1]
                        if mount_point.startswith("/media/") or mount_point.startswith("/mnt/"):
                            if _is_removable_linux(mount_point):
                                mounts.add(mount_point)
        except (OSError, PermissionError):
            pass
    elif sys.platform == "darwin":
        for vol in _get_mounted_volumes_darwin():
            # Skip system volumes
            if not vol.endswith(("Macintosh HD", "Macintosh HD - Data")):
                mounts.add(vol)
    elif sys.platform == "win32":
        mounts.update(_get_mounted_drives_windows())
    return mounts


# ---------------------------------------------------------------------------
# USB Scanner
# ---------------------------------------------------------------------------

class USBScanner:
    """Monitors for removable media and scans on mount.

    Parameters
    ----------
    scan_callback:
        Called with ``(path, reason)`` for each scan result.
        ``reason`` is ``"usb-mount"`` for newly detected media.
    poll_interval:
        Seconds between mount-point checks.
    scan_callback_on_result:
        Called with ``(path, verdict)`` when a scan completes.
    """

    def __init__(
        self,
        scan_callback: Optional[Callable[[str, str], None]] = None,
        poll_interval: float = 5.0,
    ) -> None:
        self.scan_callback = scan_callback
        self.poll_interval = poll_interval
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._known_mounts: Set[str] = set()
        self._scanned: Set[str] = set()
        self._lock = threading.Lock()
        self._stats = {
            "mounts_detected": 0,
            "scans_triggered": 0,
            "threats_found": 0,
        }

    def start(self) -> None:
        """Start the USB monitoring loop in a background thread."""
        if self._thread is not None:
            return
        self._stop_evt.clear()
        # Snapshot current mounts so we don't re-scan already-connected media
        self._known_mounts = _get_removable_mounts()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="aegorx-usb"
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
            self._check()

    def _check(self) -> None:
        """Check for new mounts and trigger scans."""
        current = _get_removable_mounts()
        with self._lock:
            new_mounts = current - self._known_mounts
            self._known_mounts = current

        for mount in new_mounts:
            if mount in self._scanned:
                continue
            with self._lock:
                self._scanned.add(mount)
                self._stats["mounts_detected"] += 1
                self._stats["scans_triggered"] += 1
            if self.scan_callback:
                self.scan_callback(mount, "usb-mount")

    def scan_now(self, path: str) -> None:
        """Manually trigger a scan of a mount point."""
        with self._lock:
            self._scanned.add(path)
        self._stats["scans_triggered"] += 1
        if self.scan_callback:
            self.scan_callback(path, "usb-manual")

    def is_running(self) -> bool:
        return self._thread is not None

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0
