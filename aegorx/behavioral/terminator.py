"""Process termination for detected malicious activity.

Provides safe process killing with confirmation, audit logging,
and escalation (SIGTERM -> SIGKILL).
"""

from __future__ import annotations

import logging
import os
import platform
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .events import BehaviorEvent, EventBus, EventType, RiskLevel

logger = logging.getLogger(__name__)

# PIDs we never kill (system critical)
_PROTECTED_PIDS = frozenset({0, 1, 2})

# Minimum risk level that triggers auto-kill
_AUTO_KILL_THRESHOLD = RiskLevel.CRITICAL


@dataclass
class KillRecord:
    pid: int
    name: str
    risk_score: float
    reason: str
    timestamp: float
    method: str  # "sigterm", "sigkill", "taskkill"
    success: bool


class ProcessTerminator:
    """Kills malicious processes with audit trail."""

    def __init__(
        self,
        event_bus: EventBus,
        enabled: bool = True,
        auto_kill: bool = False,
        escalation_delay: float = 3.0,
    ):
        self._bus = event_bus
        self._enabled = enabled
        self._auto_kill = auto_kill
        self._escalation_delay = escalation_delay
        self._lock = threading.Lock()
        self._kill_history: List[KillRecord] = []
        self._allowed_pids: Optional[set] = None
        self._on_kill: Optional[Callable] = None

    def set_kill_callback(self, callback: Callable) -> None:
        self._on_kill = callback

    def set_allowed_pids(self, pids: set) -> None:
        self._allowed_pids = pids

    def kill_process(
        self,
        pid: int,
        reason: str = "",
        risk_score: float = 0.0,
        force: bool = False,
    ) -> bool:
        if not self._enabled:
            logger.warning("Process termination disabled, skipping pid %d", pid)
            return False

        if pid in _PROTECTED_PIDS:
            logger.warning("Refusing to kill protected pid %d", pid)
            return False

        if self._allowed_pids and pid in self._allowed_pids:
            logger.info("PID %d is in allowlist, skipping kill", pid)
            return False

        # Get process name for logging
        name = self._get_process_name(pid)

        # Emit pre-kill event
        self._bus.emit(BehaviorEvent(
            event_type=EventType.MALICIOUS_DETECTED,
            pid=pid,
            risk_level=_AUTO_KILL_THRESHOLD,
            details={
                "name": name,
                "action": "terminate",
                "reason": reason,
                "risk_score": risk_score,
            },
            source="process_terminator",
        ))

        success = False
        method = ""

        if platform.system() == "Windows":
            success = self._kill_windows(pid, force)
            method = "taskkill"
        else:
            success = self._kill_unix(pid, force)
            method = "sigkill" if force else "sigterm"

            # Escalation: if SIGTERM didn't work, try SIGKILL
            if not success and not force and self._escalation_delay > 0:
                time.sleep(self._escalation_delay)
                success = self._kill_unix(pid, force=True)
                method = "sigkill_escalated"

        record = KillRecord(
            pid=pid,
            name=name,
            risk_score=risk_score,
            reason=reason,
            timestamp=time.time(),
            method=method,
            success=success,
        )

        with self._lock:
            self._kill_history.append(record)
            if len(self._kill_history) > 1000:
                self._kill_history = self._kill_history[-1000:]

        if success:
            logger.info(
                "Killed process %d (%s) [reason=%s, score=%.2f]",
                pid, name, reason, risk_score,
            )
        else:
            logger.warning(
                "Failed to kill process %d (%s) [reason=%s]",
                pid, name, reason,
            )

        if self._on_kill:
            self._on_kill(record)

        return success

    def _kill_unix(self, pid: int, force: bool = False) -> bool:
        sig = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.kill(pid, sig)
            # Wait briefly to check if process died
            for _ in range(10):
                try:
                    os.kill(pid, 0)  # Check if alive
                    time.sleep(0.1)
                except OSError:
                    return True
            return not self._is_alive(pid)
        except OSError:
            return False

    def _kill_windows(self, pid: int, force: bool = False) -> bool:
        cmd = ["taskkill", "/PID", str(pid)]
        if force:
            cmd.append("/F")
        try:
            result = subprocess.run(
                cmd, timeout=10, capture_output=True, text=True,
                creationflags=0x08000000,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def _is_alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _get_process_name(self, pid: int) -> str:
        if platform.system() == "Linux":
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    return f.read().strip()
            except (OSError, PermissionError):
                pass
        elif platform.system() == "Darwin":
            try:
                out = subprocess.check_output(
                    ["ps", "-o", "comm=", "-p", str(pid)],
                    timeout=3, text=True, stderr=subprocess.DEVNULL,
                )
                return out.strip()
            except (subprocess.SubprocessError, OSError):
                pass
        return "unknown"

    def get_history(self, limit: int = 100) -> List[KillRecord]:
        with self._lock:
            return list(self._kill_history[-limit:])

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value
