"""Real-time protection subsystem (inotify / fanotify)."""

from defentra.realtime.events import (
    FileEvent,
    PathFilter,
    RealtimeUnavailableError,
)
from defentra.realtime.monitor import RealTimeMonitor, select_backend

__all__ = [
    "FileEvent",
    "PathFilter",
    "RealTimeMonitor",
    "RealtimeUnavailableError",
    "select_backend",
]
