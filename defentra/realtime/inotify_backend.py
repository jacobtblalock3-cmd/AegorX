"""inotify backend: recursive directory watches, async notifications (unprivileged)."""

from __future__ import annotations

import ctypes
import os
import platform
import struct
import threading
from typing import Dict, List, Optional

from defentra.realtime.events import BackendBase, FileEvent, RealtimeUnavailableError

IN_CLOSE_WRITE = 0x8
IN_MOVED_TO = 0x80
IN_CREATE = 0x100
IN_DELETE_SELF = 0x400
IN_MOVE_SELF = 0x800
IN_Q_OVERFLOW = 0x4000
IN_IGNORED = 0x8000
IN_ISDIR = 0x40000000

WATCH_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE_SELF | IN_MOVE_SELF
EVENT_HEADER = struct.Struct("iIII")
READ_BUFFER = 1024 * 1024


class InotifyEvent:
    __slots__ = ("wd", "mask", "cookie", "name")

    def __init__(self, wd: int, mask: int, cookie: int, name: str):
        self.wd = wd
        self.mask = mask
        self.cookie = cookie
        self.name = name


def parse_events(buffer: bytes) -> List[InotifyEvent]:
    """Parse a raw kernel inotify read buffer into events (pure function)."""
    events: List[InotifyEvent] = []
    offset = 0
    size = len(buffer)
    while offset + EVENT_HEADER.size <= size:
        wd, mask, cookie, name_len = EVENT_HEADER.unpack_from(buffer, offset)
        offset += EVENT_HEADER.size
        if offset + name_len > size:
            break
        raw_name = buffer[offset : offset + name_len]
        offset += name_len
        if name_len:
            name = raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        else:
            name = ""
        events.append(InotifyEvent(wd, mask, cookie, name))
    return events


class InotifyBackend(BackendBase):
    name = "inotify"

    def __init__(self, paths: List[str]):
        super().__init__(paths)
        self._fd: int = -1
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._watches: Dict[int, str] = {}
        self._watch_lock = threading.Lock()
        self._libc = None

    @staticmethod
    def available() -> bool:
        return platform.system() == "Linux"

    def _ensure_fd(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.inotify_init1(0o4000)
        if fd < 0:
            raise RealtimeUnavailableError(
                f"inotify_init1 failed: {os.strerror(ctypes.get_errno())}"
            )
        self._fd = fd
        os.set_blocking(fd, False)
        self._libc = libc

    def add_watch_recursive(self, root: str) -> int:
        added = 0
        for dirpath, dirnames, _files in os.walk(root):
            if self._stop_evt.is_set():
                break
            added += self.add_watch(dirpath)
        return added

    def add_watch(self, path: str) -> int:
        if self._fd < 0:
            return 0
        wd = self._libc.inotify_add_watch(self._fd, path.encode(), WATCH_MASK)
        if wd < 0:
            return 0
        with self._watch_lock:
            self._watches[wd] = path
        return 1

    def start(self) -> None:
        if not self.available():
            raise RealtimeUnavailableError("inotify requires Linux")
        self._ensure_fd()
        watched = 0
        for p in self.paths:
            if os.path.isdir(p):
                watched += self.add_watch_recursive(p)
            elif os.path.isfile(p):
                parent = os.path.dirname(p) or "."
                watched += self.add_watch(parent)
        self._thread = threading.Thread(target=self._read_loop, daemon=True, name="defentra-inotify")
        self._thread.start()

    def _read_loop(self) -> None:
        while not self._stop_evt.is_set():
            try:
                ready, _, _ = __import__("select").select([self._fd], [], [], 0.5)
            except OSError:
                break
            if not ready:
                continue
            try:
                buf = os.read(self._fd, READ_BUFFER)
            except BlockingIOError:
                continue
            except OSError:
                break
            if not buf:
                continue
            for ev in parse_events(buf):
                self._handle(ev)

    def _handle(self, ev: InotifyEvent) -> None:
        with self._watch_lock:
            base = self._watches.get(ev.wd)
        if ev.mask & IN_IGNORED or base is None:
            if ev.mask & IN_IGNORED:
                with self._watch_lock:
                    self._watches.pop(ev.wd, None)
            return
        if ev.mask & IN_Q_OVERFLOW:
            with self._watch_lock:
                self._watches.clear()
            for root in self.paths:
                if os.path.isdir(root):
                    self.add_watch_recursive(root)
            return
        full = os.path.join(base, ev.name) if ev.name else base
        if ev.mask & IN_CREATE and ev.mask & IN_ISDIR:
            self.add_watch_recursive(full)
            return
        if ev.mask & IN_ISDIR:
            return
        if ev.mask & IN_CLOSE_WRITE:
            kind = "close_write"
        elif ev.mask & IN_MOVED_TO:
            kind = "moved_to"
        else:
            return
        if self.on_event is not None:
            self.on_event(FileEvent(path=full, kind=kind))

    def stop(self) -> None:
        self._stop_evt.set()
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def watched_count(self) -> int:
        with self._watch_lock:
            return len(self._watches)
