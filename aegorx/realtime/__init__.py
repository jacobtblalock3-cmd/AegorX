"""Real-time protection subsystem (inotify / fanotify)."""

from aegorx.realtime.events import (
    FileEvent,
    PathFilter,
    RealtimeUnavailableError,
)
from aegorx.realtime.monitor import RealTimeMonitor, select_backend

__all__ = [
    "FileEvent",
    "PathFilter",
    "RealTimeMonitor",
    "RealtimeUnavailableError",
    "select_backend",
]
