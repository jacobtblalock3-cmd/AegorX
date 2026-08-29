"""Behavioral event types and the central event bus."""

from __future__ import annotations

import enum
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class EventType(enum.Enum):
    PROCESS_CREATED = "process_created"
    PROCESS_TERMINATED = "process_terminated"
    FILE_MODIFIED = "file_modified"
    FILE_RENAMED = "file_renamed"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    REGISTRY_MODIFIED = "registry_modified"
    PERSISTENCE_DETECTED = "persistence_detected"
    MEMORY_INJECTION = "memory_injection"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    MALICIOUS_DETECTED = "malicious_detected"


class RiskLevel(enum.Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class BehaviorEvent:
    event_type: EventType
    pid: int
    timestamp: float = field(default_factory=time.time)
    risk_level: RiskLevel = RiskLevel.INFO
    details: Dict[str, Any] = field(default_factory=dict)
    source: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    @property
    def age_seconds(self) -> float:
        return time.time() - self.timestamp


class EventBus:
    """Thread-safe pub/sub event bus for behavioral events.

    Events are dispatched synchronously to all registered handlers.
    Handlers are invoked in registration order. If a handler raises,
    the error is logged and processing continues.
    """

    def __init__(self, max_history: int = 10000):
        self._handlers: Dict[EventType, List[Callable]] = {}
        self._global_handlers: List[Callable] = []
        self._lock = threading.Lock()
        self._history: List[BehaviorEvent] = []
        self._max_history = max_history
        self._stats: Dict[str, int] = {}

    def subscribe(
        self, event_type: EventType, handler: Callable[[BehaviorEvent], None]
    ) -> None:
        with self._lock:
            self._handlers.setdefault(event_type, []).append(handler)

    def subscribe_all(self, handler: Callable[[BehaviorEvent], None]) -> None:
        with self._lock:
            self._global_handlers.append(handler)

    def unsubscribe(self, event_type: EventType, handler: Callable) -> None:
        with self._lock:
            handlers = self._handlers.get(event_type, [])
            if handler in handlers:
                handlers.remove(handler)

    def emit(self, event: BehaviorEvent) -> None:
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
            key = event.event_type.value
            self._stats[key] = self._stats.get(key, 0) + 1

        handlers = []
        with self._lock:
            handlers = list(self._handlers.get(event.event_type, []))
            handlers.extend(self._global_handlers)

        for handler in handlers:
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "Handler %s failed for event %s", handler, event.event_type
                )

    def get_history(
        self,
        event_type: Optional[EventType] = None,
        pid: Optional[int] = None,
        limit: int = 100,
    ) -> List[BehaviorEvent]:
        with self._lock:
            events = self._history
            if event_type is not None:
                events = [e for e in events if e.event_type == event_type]
            if pid is not None:
                events = [e for e in events if e.pid == pid]
            return events[-limit:]

    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()
            self._stats.clear()
