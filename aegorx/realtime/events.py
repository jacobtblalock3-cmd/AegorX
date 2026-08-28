"""Shared primitives for real-time protection: events, filtering, backend contract."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional


class RealtimeUnavailableError(RuntimeError):
    pass


@dataclass
class FileEvent:
    path: str
    kind: str
    pid: int = 0
    # fanotify permission events carry a kernel-provided open descriptor.
    # Deciders should scan via this fd (engine.scan_file_descriptor) instead
    # of re-opening the path, which would self-deadlock the reader thread.
    dup_fd: Optional[int] = None


class PathFilter:
    """fnmatch-based exclusion filter applied to absolute paths."""

    def __init__(self, patterns: Optional[Iterable[str]] = None):
        self.patterns: List[str] = [str(p) for p in (patterns or [])]

    def excluded(self, path: str) -> bool:
        for pattern in self.patterns:
            if fnmatch.fnmatchcase(path, pattern):
                return True
        return False

    def __len__(self) -> int:
        return len(self.patterns)


class BackendBase:
    """Contract shared by fanotify/inotify backends.

    Subclasses notify via one of the two callbacks set by the monitor:
      on_event   : async notification backends (inotify)
      decide     : blocking backends (fanotify); return True to allow the open
    """

    name = "base"

    def __init__(self, paths: List[str]):
        self.paths = list(paths)
        self.on_event: Optional[Callable[[FileEvent], None]] = None
        self.decide: Optional[Callable[[FileEvent], bool]] = None

    @staticmethod
    def available() -> bool:
        return False

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def watched_count(self) -> int:
        return 0
