"""Process creation and termination monitoring.

Cross-platform process monitoring that tracks new process creation,
command-line arguments, parent-child relationships, and termination.
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
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    cmdline: str = ""
    username: str = ""
    start_time: float = 0.0
    exe_path: str = ""
    children: List[int] = field(default_factory=list)


# Suspicious process name patterns
SUSPICIOUS_NAMES = frozenset([
    "mimikatz", "lazagne", "bloodhound", "cobaltstrike",
    "empire", "metasploit", "meterpreter", "msfconsole",
    "nc", "ncat", "netcat", "socat", "ncat",
    "reverse", "tunnel", "rat",
])

# Suspicious parent-child relationships
SUSPICIOUS_HIERARCHY = {
    # shell spawned by office app
    "winword.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "excel.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "powerpnt.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "outlook.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    # script engines spawning shells
    "wscript.exe": {"cmd.exe", "powershell.exe"},
    "cscript.exe": {"cmd.exe", "powershell.exe"},
    "mshta.exe": {"cmd.exe", "powershell.exe", "wscript.exe"},
    # linux suspicious
    "python": {"nc", "ncat", "bash", "sh", "dash", "zsh"},
    "perl": {"nc", "ncat", "bash", "sh"},
    "ruby": {"nc", "ncat", "bash", "sh"},
}

# Dangerous command-line patterns
DANGEROUS_CMDLINE = [
    (re.compile(r"powershell\s+.*-enc\w*\s+", re.I), "encoded powershell"),
    (re.compile(r"powershell\s+.*downloadstring", re.I), "download cradle"),
    (re.compile(r"cmd\.exe\s+/c\s+.*\|", re.I), "cmd pipe"),
    (re.compile(r"bash\s+-c\s+.*curl.*\|.*sh", re.I), "curl pipe sh"),
    (re.compile(r"bash\s+-c\s+.*wget.*\|.*sh", re.I), "wget pipe sh"),
    (re.compile(r"/bin/(ba)?sh\s+-i", re.I), "reverse shell"),
    (re.compile(r"nc\s+-.*-e\s+/bin/(ba)?sh", re.I), "netcat shell"),
    (re.compile(r"python.*socket.*connect", re.I), "python socket"),
    (re.compile(r"base64\s+-d", re.I), "base64 decode"),
    (re.compile(r"chmod\s+777", re.I), "chmod 777"),
    (re.compile(r"rm\s+-rf\s+/", re.I), "rm -rf /"),
]


class ProcessMonitor:
    """Background process monitoring with parent-child tracking."""

    def __init__(
        self,
        event_bus: EventBus,
        poll_interval: float = 1.0,
        scan_children: bool = True,
    ):
        self._bus = event_bus
        self._poll_interval = poll_interval
        self._scan_children = scan_children
        self._processes: Dict[int, ProcessInfo] = {}
        self._known_pids: Set[int] = set()
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_detection: Optional[Callable[[BehaviorEvent], None]] = None

    def set_detection_callback(self, callback: Callable[[BehaviorEvent], None]) -> None:
        self._on_detection = callback

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="process-monitor"
        )
        self._thread.start()
        logger.info("Process monitor started (interval=%.1fs)", self._poll_interval)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _poll_loop(self) -> None:
        while self._running:
            try:
                self._snapshot()
            except Exception:
                logger.exception("Process snapshot failed")
            time.sleep(self._poll_interval)

    def _snapshot(self) -> None:
        current_pids = self._get_all_pids()
        new_pids = current_pids - self._known_pids
        dead_pids = self._known_pids - current_pids

        for pid in new_pids:
            info = self._get_process_info(pid)
            if info is None:
                continue
            with self._lock:
                self._processes[pid] = info
            self._analyze_new_process(info)

        for pid in dead_pids:
            with self._lock:
                info = self._processes.pop(pid, None)
            if info:
                self._bus.emit(BehaviorEvent(
                    event_type=EventType.PROCESS_TERMINATED,
                    pid=pid,
                    details={"name": info.name, "ppid": info.ppid},
                    source="process_monitor",
                ))

        with self._lock:
            self._known_pids = current_pids

    def _get_all_pids(self) -> Set[int]:
        if platform.system() == "Linux":
            return self._get_pids_linux()
        elif platform.system() == "Darwin":
            return self._get_pids_macos()
        else:
            return self._get_pids_windows()

    def _get_pids_linux(self) -> Set[int]:
        pids = set()
        try:
            for entry in os.scandir("/proc"):
                if entry.name.isdigit():
                    pids.add(int(entry.name))
        except OSError:
            pass
        return pids

    def _get_pids_macos(self) -> Set[int]:
        pids = set()
        try:
            out = subprocess.check_output(
                ["ps", "-eo", "pid="], timeout=5, text=True
            )
            for line in out.splitlines():
                line = line.strip()
                if line.isdigit():
                    pids.add(int(line))
        except (subprocess.SubprocessError, OSError):
            pass
        return pids

    def _get_pids_windows(self) -> Set[int]:
        pids = set()
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                timeout=5, text=True, creationflags=0x08000000,
            )
            for line in out.splitlines():
                parts = line.split(",")
                if parts and parts[0].strip('"').isdigit():
                    pids.add(int(parts[0].strip('"')))
        except (subprocess.SubprocessError, OSError):
            pass
        return pids

    def _get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        if platform.system() == "Linux":
            return self._get_info_linux(pid)
        elif platform.system() == "Darwin":
            return self._get_info_macos(pid)
        else:
            return self._get_info_windows(pid)

    def _get_info_linux(self, pid: int) -> Optional[ProcessInfo]:
        try:
            stat_path = f"/proc/{pid}/stat"
            cmdline_path = f"/proc/{pid}/cmdline"
            exe_path = f"/proc/{pid}/exe"

            with open(stat_path, "r") as f:
                stat = f.read()
            # Parse: pid (comm) state ppid ...
            match = re.match(r"(\d+) \((.+?)\) .+? (\d+)", stat)
            if not match:
                return None
            ppid = int(match.group(3))
            name = match.group(2)

            cmdline = ""
            try:
                with open(cmdline_path, "rb") as f:
                    cmdline = f.read().decode("utf-8", errors="replace").replace("\x00", " ")
            except (OSError, PermissionError):
                pass

            exe = ""
            try:
                exe = os.readlink(exe_path)
            except (OSError, PermissionError):
                pass

            return ProcessInfo(
                pid=pid, ppid=ppid, name=name,
                cmdline=cmdline, exe_path=exe,
                start_time=os.path.getctime(f"/proc/{pid}") if os.path.exists(f"/proc/{pid}") else time.time(),
            )
        except (OSError, PermissionError):
            return None

    def _get_info_macos(self, pid: int) -> Optional[ProcessInfo]:
        try:
            out = subprocess.check_output(
                ["ps", "-o", "pid=,ppid=,comm=,args=", "-p", str(pid)],
                timeout=3, text=True, stderr=subprocess.DEVNULL,
            )
            parts = out.strip().split(None, 3)
            if len(parts) < 3:
                return None
            return ProcessInfo(
                pid=int(parts[0]),
                ppid=int(parts[1]),
                name=parts[2],
                cmdline=parts[3] if len(parts) > 3 else "",
            )
        except (subprocess.SubprocessError, ValueError, OSError):
            return None

    def _get_info_windows(self, pid: int) -> Optional[ProcessInfo]:
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                timeout=3, text=True, creationflags=0x08000000,
            )
            for line in out.splitlines():
                parts = line.split(",")
                if len(parts) >= 2 and parts[0].strip('"') == str(pid):
                    return ProcessInfo(
                        pid=pid, ppid=0, name=parts[0].strip('"'),
                    )
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    def _analyze_new_process(self, info: ProcessInfo) -> None:
        # Emit creation event
        self._bus.emit(BehaviorEvent(
            event_type=EventType.PROCESS_CREATED,
            pid=info.pid,
            details={
                "name": info.name,
                "ppid": info.ppid,
                "cmdline": info.cmdline,
                "exe_path": info.exe_path,
            },
            source="process_monitor",
        ))

        risk = RiskLevel.INFO
        reasons = []

        # Check suspicious process names
        name_lower = info.name.lower()
        if name_lower in SUSPICIOUS_NAMES:
            risk = RiskLevel.HIGH
            reasons.append(f"suspicious process name: {info.name}")

        # Check dangerous command-line patterns
        if info.cmdline:
            for pattern, desc in DANGEROUS_CMDLINE:
                if pattern.search(info.cmdline):
                    if risk.value < RiskLevel.HIGH.value:
                        risk = RiskLevel.HIGH
                    reasons.append(f"dangerous cmdline: {desc}")

        # Check suspicious parent-child relationships
        if info.ppid and self._scan_children:
            with self._lock:
                parent = self._processes.get(info.ppid)
            if parent:
                parent_name = parent.name.lower()
                children = SUSPICIOUS_HIERARCHY.get(parent_name, set())
                if name_lower in children:
                    if risk.value < RiskLevel.MEDIUM.value:
                        risk = RiskLevel.MEDIUM
                    reasons.append(
                        f"suspicious parent-child: {parent.name} -> {info.name}"
                    )

        if reasons:
            event = BehaviorEvent(
                event_type=EventType.SUSPICIOUS_BEHAVIOR,
                pid=info.pid,
                risk_level=risk,
                details={
                    "name": info.name,
                    "cmdline": info.cmdline,
                    "reasons": reasons,
                },
                source="process_monitor",
            )
            self._bus.emit(event)
            if self._on_detection:
                self._on_detection(event)

    def get_process(self, pid: int) -> Optional[ProcessInfo]:
        with self._lock:
            return self._processes.get(pid)

    def get_children(self, pid: int) -> List[ProcessInfo]:
        with self._lock:
            return [p for p in self._processes.values() if p.ppid == pid]

    def get_process_tree(self, pid: int, depth: int = 5) -> Dict[int, List[int]]:
        tree: Dict[int, List[int]] = {}
        queue = [(pid, 0)]
        while queue:
            current, d = queue.pop(0)
            if d >= depth:
                continue
            children = self.get_children(current)
            tree[current] = [c.pid for c in children]
            for c in children:
                queue.append((c.pid, d + 1))
        return tree

    @property
    def process_count(self) -> int:
        with self._lock:
            return len(self._processes)
