"""fanotify backend: blocking on-access scanning with allow/deny (requires root)."""

from __future__ import annotations

import ctypes
import os
import platform
import stat
import struct
import threading
from typing import List, Optional

from defentra.realtime.events import BackendBase, FileEvent, RealtimeUnavailableError

FAN_ACCESS = 0x1
FAN_OPEN = 0x20
FAN_OPEN_PERM = 0x10000
FAN_ACCESS_PERM = 0x20000
FAN_EVENT_ON_CHILD = 0x8000000
FAN_ONDIR = 0x40000000
FAN_CLOSE_WRITE = 0x8

FAN_CLASS_CONTENT = 0x8
FAN_UNLIMITED_QUEUE = 0x10
FAN_CLOEXEC = 0x1

FAN_MARK_ADD = 0x1
FAN_MARK_MOUNT = 0x10
FAN_MARK_IGNORED_MASK = 0x20
FAN_MARK_IGNORED_SURV_MODIFY = 0x40

FAN_ALLOW = 1
FAN_DENY = 2
FAN_Q_OVERFLOW = 0x4000

AT_FDCWD = -100
O_RDONLY = 0
O_CLOEXEC = 0x80000

METADATA_STRUCT = struct.Struct("IBBHQii")
RESPONSE_STRUCT = struct.Struct("iI")
READ_BUFFER = 64 * 1024


def parse_metadata(buffer: bytes) -> List[dict]:
    """Parse a raw fanotify read buffer into event dicts (pure function)."""
    events: List[dict] = []
    offset = 0
    size = len(buffer)
    while offset + METADATA_STRUCT.size <= size:
        event_len, vers, _res, metadata_len, mask, fd, pid = METADATA_STRUCT.unpack_from(
            buffer, offset
        )
        if event_len < METADATA_STRUCT.size or offset + event_len > size:
            break
        events.append({"mask": mask, "fd": fd, "pid": pid, "event_len": event_len})
        offset += event_len
    return events


class FanotifyBackend(BackendBase):
    """Permission-event backend: file opens block until the engine answers.

    Malicious files are denied (the open fails for the accessing process);
    everything else is allowed. Excluded paths should be marked ignored to
    prevent feedback loops into the engine's own state.
    """

    name = "fanotify"

    def __init__(self, paths: List[str], excludes: Optional[List[str]] = None):
        super().__init__(paths)
        self.excludes = list(excludes or [])
        self._fd: int = -1
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._libc = None
        self.counters = {"events": 0, "responses": 0, "denied": 0, "allowed": 0, "self_allowed": 0}
        self._pid = os.getpid()
        self._trusted_pids: set = set()

    def trust_pid(self, pid: int) -> None:
        """Register a helper process whose I/O must never be re-scanned."""
        self._trusted_pids.add(int(pid))

    @staticmethod
    def available() -> bool:
        if platform.system() != "Linux":
            return False
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            return hasattr(libc, "fanotify_init") and hasattr(libc, "fanotify_mark")
        except OSError:
            return False

    def _ensure_fd(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fanotify_init.restype = ctypes.c_int
        libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        flags = FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE
        fd = libc.fanotify_init(flags, O_RDONLY | O_CLOEXEC)
        if fd < 0:
            errno = ctypes.get_errno()
            hint = ""
            if errno == 1:
                hint = " (run as root: permission events require CAP_SYS_ADMIN)"
            raise RealtimeUnavailableError(
                f"fanotify_init failed: {os.strerror(errno)}{hint}"
            )
        libc.fanotify_mark.restype = ctypes.c_int
        libc.fanotify_mark.argtypes = [
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_uint64,
            ctypes.c_int,
            ctypes.c_char_p,
        ]
        self._fd = fd
        os.set_blocking(fd, False)
        self._libc = libc

    def _mark(self, path: str, flags: int, mask: int) -> None:
        rc = self._libc.fanotify_mark(
            self._fd, flags, mask, AT_FDCWD, os.fsencode(path)
        )
        if rc != 0:
            raise RealtimeUnavailableError(
                f"fanotify_mark({path}) failed: {os.strerror(ctypes.get_errno())}"
            )

    def start(self) -> None:
        if not self.available():
            raise RealtimeUnavailableError("fanotify requires Linux with glibc >= 2.12")
        self._ensure_fd()
        perm_mask = FAN_OPEN_PERM | FAN_EVENT_ON_CHILD
        for p in self.paths:
            flags = FAN_MARK_ADD
            if os.path.isdir(p) and os.path.ismount(p):
                flags |= FAN_MARK_MOUNT
            self._mark(p, flags, perm_mask)
        for ex in self.excludes:
            if os.path.isdir(ex):
                try:
                    self._mark(
                        ex,
                        FAN_MARK_ADD
                        | FAN_MARK_IGNORED_MASK
                        | FAN_MARK_IGNORED_SURV_MODIFY,
                        FAN_OPEN | FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_ONDIR,
                    )
                except RealtimeUnavailableError:
                    pass
        self._thread = threading.Thread(target=self._read_loop, daemon=True, name="defentra-fanotify")
        self._thread.start()

    def _read_loop(self) -> None:
        import select

        while not self._stop_evt.is_set():
            try:
                ready, _, _ = select.select([self._fd], [], [], 0.5)
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
            for meta in parse_metadata(buf):
                self._handle(meta)

    def _handle(self, meta: dict) -> None:
        fd = meta["fd"]
        try:
            if meta["mask"] & FAN_Q_OVERFLOW or fd < 0:
                self._respond(fd, True)
                return
            # Self-access guard: deciding an event requires re-opening the
            # same file, which queues a nested permission event for OUR pid.
            # Answering that with another scan deadlocks the reader thread
            # (observed on Linux runners). Production scanners therefore
            # auto-allow their own process I/O; external pids get full
            # verdicts.
            if meta["pid"] == self._pid or meta["pid"] in self._trusted_pids:
                self.counters["self_allowed"] += 1
                self._respond(fd, True)
                return
            allowed = True
            try:
                st = os.fstat(fd)
                if stat.S_ISREG(st.st_mode):
                    path = self._path_of(fd)
                    event = FileEvent(path=path, kind="open_perm", pid=meta["pid"])
                    if self.decide is not None:
                        try:
                            allowed = bool(self.decide(event))
                        except Exception:
                            allowed = True
            except OSError:
                allowed = True
            self._respond(fd, allowed)
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _respond(self, fd: int, allow: bool) -> None:
        response = FAN_ALLOW if allow else FAN_DENY
        self.counters["responses"] += 1
        self.counters["allowed" if allow else "denied"] += 1
        try:
            os.write(self._fd, RESPONSE_STRUCT.pack(fd, response))
        except OSError:
            pass

    @staticmethod
    def _path_of(fd: int) -> str:
        try:
            link = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            link = ""
        if link.endswith(" (deleted)"):
            link = link[: -len(" (deleted)")]
        return link

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
