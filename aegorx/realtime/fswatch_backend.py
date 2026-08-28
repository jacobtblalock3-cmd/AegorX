"""Cross-platform filesystem watch backend: macOS FSEvents + Windows ReadDirectoryChangesW.

Provides async notification (on_event callback) for real-time detection and
quarantine.  Zero third-party dependencies — all native APIs accessed via ctypes.

macOS uses Core Services FSEvents (recursive, ~1 s latency).
Windows uses kernel32 ReadDirectoryChangesW (recursive via flag, overlapped I/O).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import struct
import threading
import time
from typing import Dict, List, Optional

from aegorx.realtime.events import BackendBase, FileEvent, RealtimeUnavailableError


# ---------------------------------------------------------------------------
# macOS FSEvents constants
# ---------------------------------------------------------------------------

_kFSEventStreamCreateFlagFileEvents = 0x00000010
_kFSEventStreamEventIdSinceNow = 0xFFFFFFFFFFFFFFFF

# Event flags from FSEventStreamEventFlags (macOS header values).
_kFSEventStreamEventFlagItemCreated = 0x00000100
_kFSEventStreamEventFlagItemRemoved = 0x00000200
_kFSEventStreamEventFlagItemInodeMetaMod = 0x00000400
_kFSEventStreamEventFlagItemRenamed = 0x00000800
_kFSEventStreamEventFlagItemModified = 0x00001000
_kFSEventStreamEventFlagItemXattrMod = 0x00008000
_kFSEventStreamEventFlagItemIsFile = 0x00010000
_kFSEventStreamEventFlagItemIsDir = 0x00020000

# ---------------------------------------------------------------------------
# macOS FSEvents callback
# ---------------------------------------------------------------------------

# Core Foundation types (borrowed refs — do not CFRelease).
CFArrayRef = ctypes.c_void_p
CFStringRef = ctypes.c_void_p
CFAllocatorRef = ctypes.c_void_p
FSEventStreamRef = ctypes.c_void_p
FSEventStreamEventFlags = ctypes.c_uint32
FSEventStreamEventId = ctypes.c_uint64

# Callback signature: void callback(
#     ConstFSEventStreamRef, void*, size_t, void*,
#     const FSEventStreamEventFlags[], const FSEventStreamEventId[])
_FSEventStreamCallback = ctypes.CFUNCTYPE(
    None,
    FSEventStreamRef,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_void_p),  # eventPaths (C strings)
    ctypes.POINTER(FSEventStreamEventFlags),
    ctypes.POINTER(FSEventStreamEventId),
)

_cf = None
_core = None

# Module-level registry: maps stream pointer (as int) -> backend instance.
# FSEventStreamContext is NULL; we use this to route callbacks to the right backend.
_backend_registry: Dict[int, "FSwatchMacOSBackend"] = {}


def _load_cf() -> None:
    """Load CoreFoundation + CoreServices frameworks and declare API signatures."""
    global _cf, _core
    if _cf is not None:
        return
    cf_path = ctypes.util.find_library("CoreFoundation")
    cs_path = ctypes.util.find_library("CoreServices")
    if not cf_path or not cs_path:
        raise RealtimeUnavailableError("CoreFoundation / CoreServices not found")
    _cf = ctypes.CDLL(cf_path)
    _core = ctypes.CDLL(cs_path)

    # Declare function signatures for proper ctypes calling conventions.
    _cf.CFStringCreateWithCString.restype = ctypes.c_void_p
    _cf.CFStringCreateWithCString.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32,
    ]
    _cf.CFArrayCreate.restype = ctypes.c_void_p
    _cf.CFArrayCreate.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_long, ctypes.c_void_p,
    ]
    _cf.CFRunLoopGetCurrent.restype = ctypes.c_void_p
    _cf.CFRunLoopRunInMode.restype = ctypes.c_int32
    _cf.CFRunLoopRunInMode.argtypes = [
        ctypes.c_void_p, ctypes.c_double, ctypes.c_bool,
    ]

    _core.FSEventStreamCreate.restype = ctypes.c_void_p
    _core.FSEventStreamCreate.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_uint64, ctypes.c_double, ctypes.c_uint32,
    ]
    _core.FSEventStreamScheduleWithRunLoop.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    _core.FSEventStreamStart.restype = ctypes.c_bool
    _core.FSEventStreamStart.argtypes = [ctypes.c_void_p]
    _core.FSEventStreamStop.argtypes = [ctypes.c_void_p]
    _core.FSEventStreamInvalidate.argtypes = [ctypes.c_void_p]
    _core.FSEventStreamRelease.argtypes = [ctypes.c_void_p]


def _fs_backend_cb(
    stream: FSEventStreamRef,
    clientCallBackInfo: ctypes.c_void_p,
    numEvents: ctypes.c_size_t,
    eventPaths,
    eventFlags,
    eventIds,
) -> None:
    """C-level callback invoked by the FSEventStream on the monitor thread."""
    # Look up the backend from the module-level registry using the stream pointer.
    backend = _backend_registry.get(ctypes.cast(stream, ctypes.c_void_p).value)
    if backend is None or backend._stop_evt.is_set():
        return
    try:
        num = int(numEvents)
    except (TypeError, ValueError):
        return
    for i in range(num):
        try:
            raw_ptr = eventPaths[i]
            if raw_ptr is None:
                continue
            path = ctypes.cast(raw_ptr, ctypes.c_char_p).value
            if path is None:
                continue
            path = path.decode("utf-8", errors="replace")
        except (IndexError, OSError, ValueError):
            continue

        try:
            flags = int(eventFlags[i])
        except (IndexError, TypeError, ValueError):
            flags = 0

        # Skip directories and excluded paths.
        if flags & _kFSEventStreamEventFlagItemIsDir:
            continue
        if backend.filter.excluded(path):
            continue

        # Map FSEvents flags to backend event kinds.
        if flags & _kFSEventStreamEventFlagItemCreated:
            kind = "created"
        elif flags & (_kFSEventStreamEventFlagItemModified | _kFSEventStreamEventFlagItemInodeMetaMod):
            kind = "modified"
        elif flags & _kFSEventStreamEventFlagItemRemoved:
            kind = "deleted"
        elif flags & (_kFSEventStreamEventFlagItemRenamed | _kFSEventStreamEventFlagItemXattrMod):
            kind = "moved_to"
        else:
            continue

        event = FileEvent(path=path, kind=kind)
        if backend.on_event is not None:
            try:
                backend.on_event(event)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# macOS backend implementation
# ---------------------------------------------------------------------------


class FSwatchMacOSBackend(BackendBase):
    """FSEvents-based async notification backend for macOS.

    Uses Core Services FSEvents to watch directory trees recursively.
    Events arrive with ~1 second latency (latency parameter).  Requires
    no special privileges — runs as any user.
    """

    name = "fswatch"

    def __init__(self, paths: List[str], excludes: Optional[List[str]] = None):
        super().__init__(paths)
        self.filter = _PathFilter(excludes or [])
        self._stream: Optional[FSEventStreamRef] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._context_ref: Optional[ctypes.py_object] = None
        self._run_loop = None
        self._watched: int = 0

    @staticmethod
    def available() -> bool:
        return platform.system() == "Darwin"

    def start(self) -> None:
        if not self.available():
            raise RealtimeUnavailableError("fswatch requires macOS")
        _load_cf()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="aegorx-fswatch"
        )
        self._thread.start()
        # Wait briefly for the stream to be created on the monitor thread.
        for _ in range(50):
            if self._stream is not None or self._stop_evt.is_set():
                break
            time.sleep(0.02)

    def _run(self) -> None:
        """Monitor thread: create stream, schedule on run loop, spin."""
        try:
            cf = _cf
            core = _core
            kCFRunLoopDefaultMode = ctypes.c_void_p.in_dll(cf, "kCFRunLoopDefaultMode")
            kCFStringEncodingUTF8 = 0x08000100

            cb = _FSEventStreamCallback(_fs_backend_cb)
            self._cb_ref = cb  # prevent GC

            latency = 1.0
            # FileEvents flag gives per-file granularity; no UseCFTypes
            # (paths arrive as raw char* pointers, easier to parse).
            flags = _kFSEventStreamCreateFlagFileEvents

            # Build a CFArray of CFString paths for FSEventStreamCreate.
            c_strings = []
            for p in self.paths:
                if not os.path.isdir(p):
                    continue
                c_str = cf.CFStringCreateWithCString(
                    None, os.fsencode(p), kCFStringEncodingUTF8
                )
                if c_str:
                    c_strings.append(c_str)
                    self._watched += 1

            if not c_strings:
                self._stop_evt.set()
                return

            arr = cf.CFArrayCreate(
                None,
                (ctypes.c_void_p * len(c_strings))(*c_strings),
                len(c_strings),
                None,
            )
            if not arr:
                self._stop_evt.set()
                return

            # Pass None as context; register self in module-level registry
            # so the callback can find us via the stream pointer.
            stream = core.FSEventStreamCreate(
                None,
                cb,
                None,
                arr,
                _kFSEventStreamEventIdSinceNow,
                ctypes.c_double(latency),
                ctypes.c_uint32(flags),
            )
            if not stream:
                self._stop_evt.set()
                return

            self._stream = stream

            # Register in module-level registry so the callback can find us.
            stream_key = ctypes.cast(stream, ctypes.c_void_p).value
            _backend_registry[stream_key] = self

            run_loop = cf.CFRunLoopGetCurrent()
            self._run_loop = run_loop
            core.FSEventStreamScheduleWithRunLoop(
                stream, run_loop, kCFRunLoopDefaultMode
            )
            core.FSEventStreamStart(stream)

            # Spin the run loop until stop is signaled.
            while not self._stop_evt.is_set():
                cf.CFRunLoopRunInMode(
                    kCFRunLoopDefaultMode, ctypes.c_double(0.5), False
                )

            # Cleanup.
            core.FSEventStreamStop(stream)
            core.FSEventStreamInvalidate(stream)
            core.FSEventStreamRelease(stream)

        except Exception:
            self._stop_evt.set()

    def stop(self) -> None:
        self._stop_evt.set()
        if self._stream is not None:
            stream_key = ctypes.cast(self._stream, ctypes.c_void_p).value
            _backend_registry.pop(stream_key, None)
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def watched_count(self) -> int:
        return self._watched


# ---------------------------------------------------------------------------
# Windows ReadDirectoryChangesW constants and types
# ---------------------------------------------------------------------------

# File notification change flags
_FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
_FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
_FILE_NOTIFY_CHANGE_SIZE = 0x00000008
_FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010

# File notification action codes
_FILE_ACTION_ADDED = 0x00000001
_FILE_ACTION_REMOVED = 0x00000002
_FILE_ACTION_MODIFIED = 0x00000003
_FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
_FILE_ACTION_RENamed_NEW_NAME = 0x00000005

# Access rights
_FILE_LIST_DIRECTORY = 0x00000001
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OVERLAPPED = 0x40000000
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Wait constants
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_INFINITE = 0xFFFFFFFF

# FILE_NOTIFY_INFORMATION header: NextEntryOffset(4) + Action(4) + FileNameLength(4)
_FNI_HEADER = struct.Struct("III")

# ---------------------------------------------------------------------------
# Windows backend implementation
# ---------------------------------------------------------------------------


class FSwatchWindowsBackend(BackendBase):
    """ReadDirectoryChangesW-based async notification backend for Windows.

    Watches specified directories recursively for file changes using
    overlapped I/O.  Events are parsed from the kernel's notification
    buffer and mapped to FileEvent objects.  Requires no special privileges.
    """

    name = "fswatch"

    def __init__(self, paths: List[str], excludes: Optional[List[str]] = None):
        super().__init__(paths)
        self.filter = _PathFilter(excludes or [])
        self._kernel32 = ctypes.windll.kernel32
        self._monitors: Dict[str, dict] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._watched: int = 0

    @staticmethod
    def available() -> bool:
        return platform.system() == "Windows"

    def _setup_api(self) -> None:
        """Declare Win32 API signatures."""
        k32 = self._kernel32

        k32.CreateFileW.restype = ctypes.c_void_p
        k32.CreateFileW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ]

        k32.ReadDirectoryChangesW.restype = ctypes.c_bool
        k32.ReadDirectoryChangesW.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_bool,
            ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p, ctypes.c_void_p,
        ]

        k32.CloseHandle.restype = ctypes.c_bool
        k32.CloseHandle.argtypes = [ctypes.c_void_p]

        k32.WaitForMultipleObjects.restype = ctypes.c_uint32
        k32.WaitForMultipleObjects.argtypes = [
            ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_bool, ctypes.c_uint32,
        ]

        k32.CreateEventW.restype = ctypes.c_void_p
        k32.CreateEventW.argtypes = [
            ctypes.c_void_p, ctypes.c_bool, ctypes.c_bool, ctypes.c_wchar_p,
        ]

        k32.CancelIo.restype = ctypes.c_bool
        k32.CancelIo.argtypes = [ctypes.c_void_p]

    def start(self) -> None:
        if not self.available():
            raise RealtimeUnavailableError("fswatch requires Windows")
        self._setup_api()

        self._stop_evt.clear()
        self._watched = 0

        for path in self.paths:
            if not os.path.isdir(path):
                continue

            handle = self._kernel32.CreateFileW(
                path,
                _FILE_LIST_DIRECTORY,
                7,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                None,
                _OPEN_EXISTING,
                _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OVERLAPPED,
                None,
            )
            if handle == _INVALID_HANDLE_VALUE or not handle:
                continue

            stop_event = self._kernel32.CreateEventW(None, True, False, None)
            overlapped = _OVERLAPPED()
            overlapped.hEvent = stop_event

            buf = ctypes.create_string_buffer(32 * 1024)

            self._monitors[path] = {
                "handle": handle,
                "overlapped": overlapped,
                "buf": buf,
                "stop_event": stop_event,
            }
            self._watched += 1

        if not self._monitors:
            self._stop_evt.set()
            return

        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="aegorx-fswatch-win"
        )
        self._thread.start()

    def _monitor_loop(self) -> None:
        """Background thread: one ReadDirectoryChangesW per watched dir."""
        k32 = self._kernel32

        # Issue initial reads for all directories.
        for path, m in self._monitors.items():
            k32.ReadDirectoryChangesW(
                m["handle"],
                m["buf"],
                ctypes.sizeof(m["buf"]),
                True,  # bWatchSubtree
                _FILE_NOTIFY_CHANGE_FILE_NAME
                | _FILE_NOTIFY_CHANGE_DIR_NAME
                | _FILE_NOTIFY_CHANGE_LAST_WRITE
                | _FILE_NOTIFY_CHANGE_SIZE,
                None,
                m["overlapped"],
                None,
            )

        while not self._stop_evt.is_set():
            handles = [m["stop_event"] for m in self._monitors.values()]
            if not handles:
                break
            arr = (ctypes.c_void_p * len(handles))(*handles)
            rc = k32.WaitForMultipleObjects(
                len(handles), arr, False, 500
            )

            if rc == _WAIT_TIMEOUT:
                continue

            if rc < 0 or rc >= len(handles):
                time.sleep(0.1)
                continue

            # Find which directory triggered.
            paths_list = list(self._monitors.keys())
            if rc < len(paths_list):
                path = paths_list[rc]
                m = self._monitors.get(path)
                if m is not None:
                    self._handle_events(m)
                    # Re-issue the read.
                    k32.ReadDirectoryChangesW(
                        m["handle"],
                        m["buf"],
                        ctypes.sizeof(m["buf"]),
                        True,
                        _FILE_NOTIFY_CHANGE_FILE_NAME
                        | _FILE_NOTIFY_CHANGE_DIR_NAME
                        | _FILE_NOTIFY_CHANGE_LAST_WRITE
                        | _FILE_NOTIFY_CHANGE_SIZE,
                        None,
                        m["overlapped"],
                        None,
                    )

    def _handle_events(self, monitor: dict) -> None:
        """Parse FILE_NOTIFY_INFORMATION entries from the completion buffer."""
        buf = monitor["buf"]
        offset = 0
        while offset < len(buf):
            if offset + _FNI_HEADER.size > len(buf):
                break
            next_entry, action, name_len = _FNI_HEADER.unpack_from(buf, offset)
            name_start = offset + _FNI_HEADER.size
            name_end = name_start + name_len
            if name_end > len(buf):
                break
            raw_name = buf[name_start:name_end]
            try:
                name = raw_name.decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                name = ""

            if name:
                # Determine event kind from action code.
                if action == _FILE_ACTION_ADDED:
                    kind = "created"
                elif action == _FILE_ACTION_REMOVED:
                    kind = "deleted"
                elif action == _FILE_ACTION_RENAMED_OLD_NAME:
                    kind = "moved_to"
                elif action == _FILE_ACTION_RENamed_NEW_NAME:
                    kind = "moved_to"
                elif action == _FILE_ACTION_MODIFIED:
                    kind = "modified"
                else:
                    kind = "modified"

                # Skip directories (heuristic: no extension often means dir).
                if "." not in os.path.basename(name):
                    pass  # Still process — ReadDirectoryChangesW only fires
                    # file events when FILE_NOTIFY_CHANGE_FILE_NAME is set.

                event = FileEvent(path=name, kind=kind)
                if self.on_event is not None and not self.filter.excluded(name):
                    try:
                        self.on_event(event)
                    except Exception:
                        pass

            if next_entry == 0:
                break
            offset += next_entry

    def stop(self) -> None:
        self._stop_evt.set()
        # Cancel pending I/O to unblock ReadDirectoryChangesW.
        for m in self._monitors.values():
            try:
                self._kernel32.CancelIo(m["handle"])
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        # Close handles.
        for m in self._monitors.values():
            try:
                self._kernel32.CloseHandle(m["stop_event"])
            except Exception:
                pass
            try:
                self._kernel32.CloseHandle(m["handle"])
            except Exception:
                pass
        self._monitors.clear()

    def watched_count(self) -> int:
        return self._watched


# ---------------------------------------------------------------------------
# OVERLAPPED structure for Windows
# ---------------------------------------------------------------------------


class _OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_ulong),
        ("InternalHigh", ctypes.c_ulong),
        ("Offset", ctypes.c_uint32),
        ("OffsetHigh", ctypes.c_uint32),
        ("hEvent", ctypes.c_void_p),
    ]


# ---------------------------------------------------------------------------
# Shared path filter (lightweight, avoids importing events.PathFilter here)
# ---------------------------------------------------------------------------


class _PathFilter:
    """fnmatch-based exclusion filter (local copy to avoid circular imports)."""

    def __init__(self, patterns: List[str]):
        import fnmatch

        self._patterns = list(patterns)
        self._fnmatch = fnmatch

    def excluded(self, path: str) -> bool:
        for pattern in self._patterns:
            if self._fnmatch.fnmatchcase(path, pattern):
                return True
        return False


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------


def create_fswatch_backend(
    paths: List[str], excludes: Optional[List[str]] = None
) -> BackendBase:
    """Return the appropriate platform-specific fswatch backend."""
    system = platform.system()
    if system == "Darwin":
        return FSwatchMacOSBackend(paths, excludes=excludes)
    if system == "Windows":
        return FSwatchWindowsBackend(paths, excludes=excludes)
    raise RealtimeUnavailableError(
        f"fswatch backend not available on {system}"
    )
