"""Per-process behavior profiling and risk scoring.

Aggregates behavioral signals from the event bus into per-process
profiles and computes composite risk scores using a weighted model.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .events import BehaviorEvent, EventBus, EventType, RiskLevel

logger = logging.getLogger(__name__)

# Risk weights for composite scoring
_RISK_WEIGHTS = {
    EventType.SUSPICIOUS_BEHAVIOR: 0.30,
    EventType.MALICIOUS_DETECTED: 1.00,
    EventType.MEMORY_INJECTION: 0.35,
    EventType.FILE_MODIFIED: 0.05,
    EventType.FILE_RENAMED: 0.10,
    EventType.NETWORK_CONNECTION: 0.05,
    EventType.DNS_QUERY: 0.03,
    EventType.REGISTRY_MODIFIED: 0.08,
    EventType.PERSISTENCE_DETECTED: 0.40,
    EventType.PROCESS_CREATED: 0.02,
    EventType.PROCESS_TERMINATED: 0.00,
}

# Thresholds for behavioral indicators
_VELOCITY_THRESHOLD = 10  # files modified per minute
_DNS_VELOCITY_THRESHOLD = 50  # DNS queries per minute
_NETWORK_VELOCITY_THRESHOLD = 20  # new connections per minute
_ENTROPY_SPIKE_THRESHOLD = 1.5  # entropy increase indicating encryption
_EXTENSIONS_CHANGED_THRESHOLD = 3  # mass renames in window


@dataclass
class ProcessProfile:
    pid: int
    name: str = ""
    cmdline: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    file_modifications: int = 0
    file_renames: int = 0
    files_modified_pids: List[int] = field(default_factory=list)

    network_connections: int = 0
    dns_queries: int = 0
    unique_remote_hosts: set = field(default_factory=set)

    registry_modifications: int = 0
    persistence_events: int = 0
    injection_events: int = 0
    suspicious_events: int = 0
    malicious_events: int = 0

    extensions_changed: Dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.INFO

    # Rolling windows for velocity calculation
    _file_timestamps: deque = field(default_factory=lambda: deque(maxlen=200))
    _dns_timestamps: deque = field(default_factory=lambda: deque(maxlen=200))
    _network_timestamps: deque = field(default_factory=lambda: deque(maxlen=200))
    _event_history: deque = field(default_factory=lambda: deque(maxlen=500))

    @property
    def file_velocity(self) -> float:
        return self._velocity(self._file_timestamps, window=60.0)

    @property
    def dns_velocity(self) -> float:
        return self._velocity(self._dns_timestamps, window=60.0)

    @property
    def network_velocity(self) -> float:
        return self._velocity(self._network_timestamps, window=60.0)

    @staticmethod
    def _velocity(timestamps: deque, window: float = 60.0) -> float:
        if not timestamps:
            return 0.0
        now = time.time()
        cutoff = now - window
        count = sum(1 for t in timestamps if t > cutoff)
        return count / window * 60.0  # events per minute

    def compute_risk(self) -> float:
        """Compute composite risk score [0.0, 1.0]."""
        score = 0.0

        # Base score from event counts (logarithmic scaling)
        indicators = [
            (self.suspicious_events, 0.30),
            (self.malicious_events, 1.00),
            (self.injection_events, 0.35),
            (self.persistence_events, 0.40),
            (self.file_renames, 0.10),
            (self.registry_modifications, 0.08),
        ]
        for count, weight in indicators:
            if count > 0:
                score += weight * math.log1p(count)

        # Velocity bonuses (abnormally high activity)
        if self.file_velocity > _VELOCITY_THRESHOLD:
            score += 0.20 * math.log1p(self.file_velocity / _VELOCITY_THRESHOLD)
        if self.dns_velocity > _DNS_VELOCITY_THRESHOLD:
            score += 0.15 * math.log1p(self.dns_velocity / _DNS_VELOCITY_THRESHOLD)
        if self.network_velocity > _NETWORK_VELOCITY_THRESHOLD:
            score += 0.15 * math.log1p(self.network_velocity / _NETWORK_VELOCITY_THRESHOLD)

        # Mass extension changes (strong ransomware indicator)
        total_ext_changes = sum(self.extensions_changed.values())
        if total_ext_changes >= _EXTENSIONS_CHANGED_THRESHOLD:
            score += 0.25 * math.log1p(total_ext_changes)

        # Unique remote hosts (C2 communication pattern)
        if len(self.unique_remote_hosts) > 10:
            score += 0.10 * math.log1p(len(self.unique_remote_hosts) - 10)

        # Clamp to [0, 1]
        score = min(1.0, max(0.0, score))
        self.risk_score = score

        if score >= 0.80:
            self.risk_level = RiskLevel.CRITICAL
        elif score >= 0.60:
            self.risk_level = RiskLevel.HIGH
        elif score >= 0.35:
            self.risk_level = RiskLevel.MEDIUM
        elif score >= 0.10:
            self.risk_level = RiskLevel.LOW
        else:
            self.risk_level = RiskLevel.INFO

        return score


class BehaviorProfiler:
    """Aggregates events from the EventBus into per-process profiles."""

    def __init__(
        self,
        event_bus: EventBus,
        auto_subscribe: bool = True,
        prune_interval: float = 300.0,
        max_process_age: float = 3600.0,
    ):
        self._bus = event_bus
        self._profiles: Dict[int, ProcessProfile] = {}
        self._lock = threading.Lock()
        self._prune_interval = prune_interval
        self._max_process_age = max_process_age
        self._last_prune = time.time()
        self._on_risk_change: Optional[callable] = None

        if auto_subscribe:
            for et in EventType:
                self._bus.subscribe(et, self._on_event)

    def set_risk_callback(self, callback) -> None:
        self._on_risk_change = callback

    def _on_event(self, event: BehaviorEvent) -> None:
        with self._lock:
            profile = self._profiles.get(event.pid)
            if profile is None:
                profile = ProcessProfile(pid=event.pid)
                self._profiles[event.pid] = profile

            profile.last_seen = event.timestamp
            profile._event_history.append(event)

            old_level = profile.risk_level

            if event.event_type == EventType.PROCESS_CREATED:
                profile.name = event.details.get("name", profile.name)
                profile.cmdline = event.details.get("cmdline", profile.cmdline)
            elif event.event_type == EventType.FILE_MODIFIED:
                profile.file_modifications += 1
                profile._file_timestamps.append(event.timestamp)
            elif event.event_type == EventType.FILE_RENAMED:
                profile.file_renames += 1
                profile._file_timestamps.append(event.timestamp)
                ext = event.details.get("new_extension", "")
                if ext:
                    profile.extensions_changed[ext] = (
                        profile.extensions_changed.get(ext, 0) + 1
                    )
            elif event.event_type == EventType.NETWORK_CONNECTION:
                profile.network_connections += 1
                profile._network_timestamps.append(event.timestamp)
                host = event.details.get("remote_host", "")
                if host:
                    profile.unique_remote_hosts.add(host)
            elif event.event_type == EventType.DNS_QUERY:
                profile.dns_queries += 1
                profile._dns_timestamps.append(event.timestamp)
            elif event.event_type == EventType.REGISTRY_MODIFIED:
                profile.registry_modifications += 1
            elif event.event_type == EventType.PERSISTENCE_DETECTED:
                profile.persistence_events += 1
            elif event.event_type == EventType.MEMORY_INJECTION:
                profile.injection_events += 1
            elif event.event_type == EventType.SUSPICIOUS_BEHAVIOR:
                profile.suspicious_events += 1
            elif event.event_type == EventType.MALICIOUS_DETECTED:
                profile.malicious_events += 1

            profile.compute_risk()

            if (
                self._on_risk_change
                and profile.risk_level.value != old_level.value
                and profile.risk_level.value >= RiskLevel.HIGH.value
            ):
                self._on_risk_change(profile)

        # Periodic prune
        now = time.time()
        if now - self._last_prune > self._prune_interval:
            self._last_prune = now
            self._prune_stale()

    def _prune_stale(self) -> None:
        now = time.time()
        with self._lock:
            stale = [
                pid for pid, p in self._profiles.items()
                if now - p.last_seen > self._max_process_age
            ]
            for pid in stale:
                del self._profiles[pid]
            if stale:
                logger.debug("Pruned %d stale process profiles", len(stale))

    def get_profile(self, pid: int) -> Optional[ProcessProfile]:
        with self._lock:
            return self._profiles.get(pid)

    def get_all_profiles(self) -> List[ProcessProfile]:
        with self._lock:
            return list(self._profiles.values())

    def get_high_risk(self, min_score: float = 0.60) -> List[ProcessProfile]:
        with self._lock:
            return [
                p for p in self._profiles.values()
                if p.risk_score >= min_score
            ]

    def get_top_offenders(self, n: int = 10) -> List[ProcessProfile]:
        with self._lock:
            profiles = list(self._profiles.values())
        profiles.sort(key=lambda p: p.risk_score, reverse=True)
        return profiles[:n]

    def get_event_timeline(
        self, pid: int, limit: int = 100
    ) -> List[BehaviorEvent]:
        with self._lock:
            profile = self._profiles.get(pid)
            if not profile:
                return []
            return list(profile._event_history)[-limit:]

    @property
    def profile_count(self) -> int:
        with self._lock:
            return len(self._profiles)
