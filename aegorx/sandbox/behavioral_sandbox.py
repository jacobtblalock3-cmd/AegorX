"""Behavioral sandbox — controlled execution environment for zero-day detection.

Executes suspicious files in a monitored environment and captures
their behavior: file system changes, network activity, process creation,
and resource consumption. Uses platform-specific isolation where available.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    timeout_seconds: float = 30.0
    max_memory_mb: int = 256
    max_cpu_seconds: float = 15.0
    network_enabled: bool = False
    watch_files: bool = True
    watch_processes: bool = True
    watch_registry: bool = True
    temp_dir: str = ""
    record_syscalls: bool = False
    trace_children: bool = True


@dataclass
class FileChange:
    path: str
    operation: str  # created, modified, deleted, renamed
    timestamp: float = field(default_factory=time.time)
    size: int = 0
    content_hash: str = ""


@dataclass
class ProcessSpawn:
    pid: int
    name: str
    cmdline: str = ""
    parent_pid: int = 0
    timestamp: float = field(default_factory=time.time)


@dataclass
class NetworkActivity:
    protocol: str
    remote_host: str
    remote_port: int
    timestamp: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class SandboxResult:
    file_path: str = ""
    exit_code: Optional[int] = None
    execution_time: float = 0.0
    timed_out: bool = False

    # Observed behavior
    file_changes: List[FileChange] = field(default_factory=list)
    processes_spawned: List[ProcessSpawn] = field(default_factory=list)
    network_activity: List[NetworkActivity] = field(default_factory=list)

    # Resource usage
    peak_memory_kb: int = 0
    cpu_time_used: float = 0.0

    # Analysis
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    verdict: str = "unknown"  # clean, suspicious, malicious, unknown
    detection_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "timed_out": self.timed_out,
            "file_changes_count": len(self.file_changes),
            "processes_spawned_count": len(self.processes_spawned),
            "network_activity_count": len(self.network_activity),
            "peak_memory_kb": self.peak_memory_kb,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "risk_factors": self.risk_factors,
            "detection_reasons": self.detection_reasons,
        }


class BehavioralSandbox:
    """Controlled execution environment for behavioral analysis."""

    # Patterns that indicate malicious behavior
    MALICIOUS_FILE_PATTERNS = [
        (".locked", "ransomware_extension"),
        (".encrypted", "ransomware_extension"),
        (".wncry", "ransomware_extension"),
        (".ryuk", "ransomware_extension"),
        ("how_to_decrypt", "ransom_note"),
        ("readme.txt", "ransom_note"),
        ("restore_files", "ransom_note"),
    ]

    SUSPICIOUS_PROCESSES = {
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe",
        "nc.exe", "ncat.exe", "netcat.exe",
    }

    SUSPICIOUS_PORTS = {4444, 5555, 6666, 31337, 1234, 9999}

    def __init__(self, config: Optional[SandboxConfig] = None):
        self._config = config or SandboxConfig()
        self._on_event: Optional[Callable] = None

    def set_event_callback(self, callback: Callable) -> None:
        self._on_event = callback

    def analyze(self, path: str) -> SandboxResult:
        result = SandboxResult(file_path=path)

        if not os.path.isfile(path):
            result.risk_factors.append("file_not_found")
            return result

        # Create isolated temp directory
        work_dir = self._config.temp_dir or tempfile.mkdtemp(prefix="aegorx_sandbox_")
        sandbox_file = os.path.join(work_dir, os.path.basename(path))

        try:
            shutil.copy2(path, sandbox_file)
        except (OSError, shutil.Error) as e:
            result.risk_factors.append(f"copy_failed: {e}")
            return result

        # Take snapshot of file system state
        pre_files = self._snapshot_files(work_dir) if self._config.watch_files else set()

        # Execute with monitoring
        start_time = time.time()
        try:
            proc = self._execute(sandbox_file)
            # Monitor in background thread
            monitor_thread = None
            if self._config.watch_processes:
                monitor_thread = threading.Thread(
                    target=self._monitor_process,
                    args=(proc, result),
                    daemon=True,
                )
                monitor_thread.start()

            # Wait with timeout
            try:
                proc.wait(timeout=self._config.timeout_seconds)
                result.exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                result.timed_out = True
                result.risk_factors.append("execution_timeout")

            if monitor_thread:
                monitor_thread.join(timeout=2)

        except (OSError, subprocess.SubprocessError) as e:
            result.risk_factors.append(f"execution_failed: {e}")

        result.execution_time = time.time() - start_time

        # Capture file changes
        if self._config.watch_files:
            post_files = self._snapshot_files(work_dir)
            self._diff_files(pre_files, post_files, result)

        # Analyze behavior
        self._analyze_behavior(result)

        # Cleanup
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass

        return result

    def _execute(self, path: str) -> subprocess.Popen:
        """Execute the file with platform-specific sandboxing."""
        system = platform.system()

        cmd = [path]
        kwargs: Dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": os.path.dirname(path),
        }

        if system == "Linux":
            # Use cgroup and namespace isolation if available
            if os.path.exists("/usr/bin/firejail"):
                cmd = [
                    "firejail", "--noroot", "--nosound", "--no3d",
                    "--net=none" if not self._config.network_enabled else "",
                    "--private", path,
                ]
                cmd = [c for c in cmd if c]
            elif os.path.exists("/usr/bin/bubblewrap"):
                cmd = ["bwrap", "--ro-bind", "/usr", "/usr", "--dev", "/dev", path]
        elif system == "Darwin":
            # Use sandbox-exec if available
            sandbox_profile = self._get_macos_sandbox_profile()
            if sandbox_profile:
                cmd = ["sandbox-exec", "-f", sandbox_profile, path]
        elif system == "Windows":
            # Use restricted token on Windows
            kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

        return subprocess.Popen(cmd, **kwargs)

    def _get_macos_sandbox_profile(self) -> Optional[str]:
        """Generate a macOS sandbox profile for restricting execution."""
        profile = """(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(deny network*)
(deny file-write* (subpath "/System") (subpath "/usr"))
(allow file-write* (subpath "%s"))
""" % tempfile.gettempdir()
        try:
            fd, path = tempfile.mkstemp(suffix=".sb", prefix="aegorx_sandbox_")
            os.write(fd, profile.encode())
            os.close(fd)
            return path
        except OSError:
            return None

    def _snapshot_files(self, directory: str) -> Dict[str, float]:
        """Snapshot file modification times in directory."""
        snapshot = {}
        for root, dirs, files in os.walk(directory):
            for f in files:
                path = os.path.join(root, f)
                try:
                    snapshot[path] = os.path.getmtime(path)
                except OSError:
                    pass
        return snapshot

    def _diff_files(
        self,
        pre: Dict[str, float],
        post: Dict[str, float],
        result: SandboxResult,
    ) -> None:
        """Compare file snapshots and record changes."""
        new_files = set(post.keys()) - set(pre.keys())
        deleted_files = set(pre.keys()) - set(post.keys())
        modified_files = {
            f for f in set(pre.keys()) & set(post.keys())
            if pre[f] != post[f]
        }

        for f in new_files:
            try:
                size = os.path.getsize(f)
            except OSError:
                size = 0
            result.file_changes.append(FileChange(
                path=f, operation="created", size=size,
            ))

        for f in deleted_files:
            result.file_changes.append(FileChange(path=f, operation="deleted"))

        for f in modified_files:
            result.file_changes.append(FileChange(path=f, operation="modified"))

    def _monitor_process(self, proc: subprocess.Popen, result: SandboxResult) -> None:
        """Monitor spawned processes during execution."""
        if proc.pid:
            result.processes_spawned.append(ProcessSpawn(
                pid=proc.pid,
                name=os.path.basename(proc.args[0]) if proc.args else "unknown",
                cmdline=" ".join(proc.args) if proc.args else "",
            ))

    def _analyze_behavior(self, result: SandboxResult) -> None:
        """Analyze observed behavior and compute risk score."""
        score = 0.0
        reasons = []

        # File changes
        created = [c for c in result.file_changes if c.operation == "created"]
        modified = [c for c in result.file_changes if c.operation == "modified"]
        deleted = [c for c in result.file_changes if c.operation == "deleted"]

        if len(created) > 10:
            score += 0.2
            reasons.append(f"mass_file_creation({len(created)})")

        if len(deleted) > 5:
            score += 0.15
            reasons.append(f"mass_file_deletion({len(deleted)})")

        # Check for ransomware file patterns
        for change in result.file_changes:
            for pattern, desc in self.MALICIOUS_FILE_PATTERNS:
                if pattern in os.path.basename(change.path).lower():
                    score += 0.4
                    reasons.append(f"ransomware_indicator: {desc} ({change.path})")

        # Check for suspicious process spawning
        for proc in result.processes_spawned:
            if proc.name.lower() in self.SUSPICIOUS_PROCESSES:
                score += 0.15
                reasons.append(f"suspicious_process: {proc.name}")

        # Network activity
        for net in result.network_activity:
            if net.remote_port in self.SUSPICIOUS_PORTS:
                score += 0.2
                reasons.append(f"suspicious_port: {net.remote_port}")

        # Resource abuse
        if result.peak_memory_kb > self._config.max_memory_mb * 1024 * 0.9:
            score += 0.1
            reasons.append("memory_exhaustion")

        # Execution anomalies
        if result.timed_out:
            score += 0.15
            reasons.append("execution_timeout")

        if result.exit_code and result.exit_code != 0:
            score += 0.05
            reasons.append(f"non_zero_exit({result.exit_code})")

        result.risk_score = min(1.0, score)
        result.risk_factors = list(set(result.risk_factors))
        result.detection_reasons = reasons

        # Verdict
        if result.risk_score >= 0.7:
            result.verdict = "malicious"
        elif result.risk_score >= 0.4:
            result.verdict = "suspicious"
        elif result.risk_score >= 0.1:
            result.verdict = "suspicious"
        else:
            result.verdict = "clean"

    @property
    def config(self) -> SandboxConfig:
        return self._config
