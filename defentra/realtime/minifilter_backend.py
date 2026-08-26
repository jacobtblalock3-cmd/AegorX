"""Windows minifilter communication backend.

Provides user-mode communication with a filesystem minifilter driver for
on-access blocking.  The kernel driver (not included — requires Windows
Driver Kit + WHQL code signing) intercepts file-open/create operations
and sends them to this user-mode component for scanning.

When the minifilter driver is not loaded, this backend falls back to a
soft-blocking mode that attempts immediate quarantine after detection.

This module is loaded conditionally — it will only be imported on Windows.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import platform
import struct
import threading
import time
from typing import Callable, List, Optional

from defentra.realtime.events import BackendBase, FileEvent, RealtimeUnavailableError

# ---------------------------------------------------------------------------
# Filter Manager constants and types (from fltUser.h)
# ---------------------------------------------------------------------------

# Communication port constants
FLT_PORT_ALL_ACCESS = 0x0001
FLT_PORT_CONNECT = 0x0001

# Message types from minifilter
FILEOP_EXEC = 0x0000
FILEOP_CREATE = 0x0001
FILEOP_CLOSE = 0x0002

# Response actions
FILEOP_ALLOW = 0x0000
FILEOP_DENY = 0x0001

# Error codes
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MORE_DATA = 234
ERROR_OPERATION_ABORTED = 995


# ---------------------------------------------------------------------------
# Minifilter message structures
# ---------------------------------------------------------------------------


class _FILTER_MESSAGE_HEADER(ctypes.Structure):
    """Header prepended to messages from the minifilter driver."""
    _fields_ = [
        ("MessageId", ctypes.c_ulong),
        ("Length", ctypes.c_ulong),
    ]


class _FILEOP_MESSAGE(ctypes.Structure):
    """Simplified file-operation message from the minifilter.

    In production this would match the driver's message structure exactly.
    This is a framework for the communication protocol.
    """
    _fields_ = [
        ("Operation", ctypes.c_ulong),       # FILEOP_EXEC, FILEOP_CREATE, etc.
        ("ProcessId", ctypes.c_ulong),        # PID of the requesting process
        ("FileObject", ctypes.c_void_p),      # Kernel file object pointer
        ("FileNameLength", ctypes.c_ulong),   # Length of FileName in bytes
        ("FileName", ctypes.c_wchar * 260),   # Full file path (MAX_PATH)
    ]


class _FILTER_REPLY_HEADER(ctypes.Structure):
    """Reply header sent back to the minifilter driver."""
    _fields_ = [
        ("MessageId", ctypes.c_ulong),
        ("Status", ctypes.c_long),  # 0 = allow, non-zero = deny
    ]


# ---------------------------------------------------------------------------
# Minifilter communication backend
# ---------------------------------------------------------------------------


class MinifilterBackend(BackendBase):
    """Windows minifilter communication backend for on-access blocking.

    Connects to a filesystem minifilter driver via a filter communication
    port.  Receives file-open/create events from the driver, scans them,
    and replies with allow/deny.

    Falls back to a notification-only mode (using ReadDirectoryChangesW)
    if the minifilter driver is not loaded.
    """

    name = "minifilter"

    def __init__(self, paths: List[str], excludes: Optional[List[str]] = None):
        super().__init__(paths)
        self._fltlib = None
        self._port_handle = ctypes.c_void_p()
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._connected = False
        self._watched: int = 0
        self._decide_fn: Optional[Callable[[FileEvent], bool]] = None
        self._fallback: Optional[BackendBase] = None
        self._stats = {"connected": 0, "scanned": 0, "denied": 0, "allowed": 0}

    @staticmethod
    def available() -> bool:
        return platform.system() == "Windows"

    def _setup_api(self) -> None:
        """Load fltLib.dll and declare API signatures."""
        try:
            self._fltlib = ctypes.CDLL("fltLib.dll")
        except OSError:
            try:
                self._fltlib = ctypes.CDLL("FltLib.dll")
            except OSError:
                return

        flt = self._fltlib

        flt.FilterConnectCommunicationPort.restype = ctypes.c_long
        flt.FilterConnectCommunicationPort.argtypes = [
            ctypes.c_wchar_p,            # PortName
            ctypes.c_ulong,              # Options
            ctypes.c_void_p,             # Context
            ctypes.c_ulong,              # ContextSize
            ctypes.POINTER(ctypes.c_void_p),  # PortHandle
        ]

        flt.FilterGetMessage.restype = ctypes.c_long
        flt.FilterGetMessage.argtypes = [
            ctypes.c_void_p,             # PortHandle
            ctypes.c_void_p,             # MessageBuffer
            ctypes.c_ulong,              # MessageBufferSize
            ctypes.POINTER(ctypes.c_ulong),  # BytesReturned
        ]

        flt.FilterReplyMessage.restype = ctypes.c_long
        flt.FilterReplyMessage.argtypes = [
            ctypes.c_void_p,             # PortHandle
            ctypes.c_void_p,             # MessageBuffer
            ctypes.c_ulong,              # MessageBufferSize
        ]

        flt.FilterClose.restype = ctypes.c_long
        flt.FilterClose.argtypes = [ctypes.c_void_p]

    def start(self) -> None:
        if not self.available():
            raise RealtimeUnavailableError("minifilter backend requires Windows")

        self._setup_api()

        # Try to connect to the minifilter driver's communication port.
        if self._try_connect():
            self._connected = True
            self._watched = len(self.paths)
            self._thread = threading.Thread(
                target=self._message_loop,
                daemon=True,
                name="defentra-minifilter",
            )
            self._thread.start()
        else:
            # Fall back to notification mode.
            self._start_fallback()

    def _try_connect(self) -> bool:
        """Attempt to connect to the minifilter communication port."""
        if not self._fltlib:
            return False

        flt = self._fltlib
        port_name = "\\DefentraFilterPort"
        handle = ctypes.c_void_p()

        rc = flt.FilterConnectCommunicationPort(
            port_name, 0, None, 0, ctypes.byref(handle)
        )
        if rc != 0:
            return False

        self._port_handle = handle
        return True

    def _start_fallback(self) -> None:
        """Fall back to ReadDirectoryChangesW notification mode."""
        from defentra.realtime.fswatch_backend import create_fswatch_backend

        self._fallback = create_fswatch_backend(self.paths)
        self._fallback.on_event = self.on_event
        self._fallback.decide = self.decide
        self._fallback.start()
        self._watched = self._fallback.watched_count()

    def _message_loop(self) -> None:
        """Main loop: receive messages from driver, scan, reply."""
        flt = self._fltlib
        buf_size = ctypes.sizeof(_FILTER_MESSAGE_HEADER) + ctypes.sizeof(_FILEOP_MESSAGE)
        buf = ctypes.create_string_buffer(buf_size)
        bytes_returned = ctypes.c_ulong(0)

        while not self._stop_evt.is_set():
            rc = flt.FilterGetMessage(
                self._port_handle, buf, buf_size, ctypes.byref(bytes_returned)
            )

            if rc != 0:
                if rc == ERROR_OPERATION_ABORTED:
                    break
                time.sleep(0.01)
                continue

            # Parse the message.
            header = _FILTER_MESSAGE_HEADER.from_buffer(buf)
            msg = _FILEOP_MESSAGE.from_buffer(
                buf, ctypes.sizeof(_FILTER_MESSAGE_HEADER)
            )

            self._process_message(header, msg)

    def _process_message(self, header: _FILTER_MESSAGE_HEADER, msg: _FILEOP_MESSAGE) -> None:
        """Scan the file referenced by a minifilter message and reply."""
        flt = self._fltlib

        path = msg.FileName[:msg.FileNameLength // 2] if msg.FileNameLength else ""
        path = path.rstrip("\x00")

        if not path or not os.path.isfile(path):
            self._reply(header.MessageId, FILEOP_ALLOW)
            return

        # Build event and scan.
        event = FileEvent(
            path=path,
            kind="exec" if msg.Operation == FILEOP_EXEC else "open_perm",
            pid=msg.ProcessId,
        )

        allowed = True
        if self.decide is not None:
            try:
                allowed = bool(self.decide(event))
            except Exception:
                allowed = True

        action = FILEOP_ALLOW if allowed else FILEOP_DENY
        self._stats["scanned"] += 1
        if allowed:
            self._stats["allowed"] += 1
        else:
            self._stats["denied"] += 1

        self._reply(header.MessageId, action)

    def _reply(self, message_id: int, action: int) -> None:
        """Send a reply to the minifilter driver."""
        if not self._fltlib or not self._connected:
            return

        reply = _FILTER_REPLY_HEADER()
        reply.MessageId = message_id
        reply.Status = action

        reply_buf = ctypes.byref(reply)
        self._fltlib.FilterReplyMessage(
            self._port_handle,
            reply_buf,
            ctypes.sizeof(reply),
        )

    def stop(self) -> None:
        self._stop_evt.set()
        if self._fallback is not None:
            self._fallback.stop()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        if self._connected and self._fltlib:
            try:
                self._fltlib.FilterClose(self._port_handle)
            except Exception:
                pass
            self._connected = False

    def watched_count(self) -> int:
        return self._watched

    def stats(self) -> dict:
        return dict(self._stats)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_minifilter_backend(
    paths: List[str], excludes: Optional[List[str]] = None
) -> MinifilterBackend:
    """Create a minifilter backend instance."""
    return MinifilterBackend(paths, excludes=excludes)
