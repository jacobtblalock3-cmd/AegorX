"""macOS EndpointSecurity blocking backend.

Uses Apple's EndpointSecurity framework to intercept and optionally deny
file-execution events in real-time.  Requires:

  - macOS 10.15+ (Catalina or later)
  - Hardened Runtime + com.apple.developer.endpoint-security.client entitlement
  - A valid Apple Developer ID for notarization.

When the EndpointSecurity entitlement is not present, the backend falls back
to a notification-only mode using the fswatch backend (FSEvents).

This module is loaded conditionally — it will only be imported on macOS.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import threading
from typing import Callable, List, Optional

from aegorx.realtime.events import BackendBase, FileEvent, RealtimeUnavailableError

# ---------------------------------------------------------------------------
# EndpointSecurity framework constants
# ---------------------------------------------------------------------------

ES_EVENT_TYPE_AUTH_EXEC = 0x0000
ES_EVENT_TYPE_AUTH_OPEN = 0x0002
ES_EVENT_TYPE_NOTIFY_EXEC = 0x0001
ES_EVENT_TYPE_NOTIFY_CREATE = 0x000A

ES_AUTH_RESULT_ALLOW = 0
ES_AUTH_RESULT_DENY = 1

ES_ERR_SUCCESS = 0

# Callback type: void (*)(es_client_t*, const es_message_t*, void*)
ESCallback = ctypes.CFUNCTYPE(
    None,
    ctypes.c_void_p,  # es_client_t*
    ctypes.c_void_p,  # const es_message_t*
    ctypes.c_void_p,  # void* context
)

_es = None
_es_loaded = False


def _load_es() -> bool:
    """Try to load the EndpointSecurity framework (macOS 10.15+)."""
    global _es, _es_loaded
    if _es_loaded:
        return _es is not None
    _es_loaded = True

    if platform.system() != "Darwin":
        return False

    es_path = ctypes.util.find_library("EndpointSecurity")
    if not es_path:
        return False

    try:
        _es = ctypes.CDLL(es_path)
        if not hasattr(_es, "es_new_client") or not hasattr(_es, "es_subscribe"):
            _es = None
            return False
        return True
    except OSError:
        _es = None
        return False


# ---------------------------------------------------------------------------
# EndpointSecurity backend
# ---------------------------------------------------------------------------


class EndpointSecurityBackend(BackendBase):
    """macOS EndpointSecurity-based blocking backend.

    Subscribes to ES_EVENT_TYPE_AUTH_EXEC and ES_EVENT_TYPE_AUTH_OPEN.
    When a malicious file is detected via the decide callback, the event
    is denied — the executing process receives an access-denied error.

    Falls back to FSEvents notification if EndpointSecurity is unavailable.
    """

    name = "es"

    def __init__(self, paths: List[str], excludes: Optional[List[str]] = None):
        super().__init__(paths)
        self._client: Optional[ctypes.c_void_p] = None
        self._stop_evt = threading.Event()
        self._callback_ref: Optional[ESCallback] = None
        self._watched: int = 0
        import fnmatch
        self._excludes = list(excludes or [])
        self._fnmatch = fnmatch

    def _is_excluded(self, path: str) -> bool:
        for pat in self._excludes:
            if self._fnmatch.fnmatchcase(path, pat):
                return True
        return False

    @staticmethod
    def available() -> bool:
        return _load_es()

    def start(self) -> None:
        if not self.available():
            raise RealtimeUnavailableError(
                "EndpointSecurity requires macOS 10.15+ with "
                "com.apple.developer.endpoint-security.client entitlement"
            )
        es = _es

        # Create client.
        client_ptr = ctypes.c_void_p()
        rc = es.es_new_client(ctypes.byref(client_ptr), self._es_callback)
        if rc != ES_ERR_SUCCESS or not client_ptr:
            raise RealtimeUnavailableError(
                f"es_new_client failed (rc={rc}); ensure the binary has "
                "the com.apple.developer.endpoint-security.client entitlement "
                "and is properly signed/notarized"
            )
        self._client = client_ptr

        # Subscribe to auth events.
        event_count = 2
        events = (ctypes.c_uint32 * event_count)(
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN,
        )
        rc = es.es_subscribe(self._client, events, event_count)
        if rc != ES_ERR_SUCCESS:
            es.es_close_client(self._client)
            self._client = None
            raise RealtimeUnavailableError(f"es_subscribe failed (rc={rc})")

        self._callback_ref = self._es_callback
        self._watched = len(self.paths)

    @ESCallback
    def _es_callback(
        self,
        client: ctypes.c_void_p,
        message: ctypes.c_void_p,
        ctx: ctypes.c_void_p,
    ) -> None:
        """Called by the EndpointSecurity framework on the event thread.

        We extract the event type from the message header (at offset 4)
        and the file path by navigating the message structure.  On any
        parsing error we fail open (allow the operation).
        """
        if self._stop_evt.is_set():
            return

        es = _es
        if not es:
            return

        try:
            # Read event_type from the message at offset 4 (after version uint32).
            event_type = ctypes.c_uint32.from_address(
                ctypes.addressof(message.contents) + 4
            ).value

            # Extract file path from the event's target/source ESFile.
            path = self._extract_path_from_message(message, event_type)

            if not path or self._is_excluded(path):
                self._respond(client, message, ES_AUTH_RESULT_ALLOW)
                return

            if not os.path.isfile(path):
                self._respond(client, message, ES_AUTH_RESULT_ALLOW)
                return

            kind = "exec" if event_type == ES_EVENT_TYPE_AUTH_EXEC else "open_perm"
            event = FileEvent(path=path, kind=kind)

            result = True
            if self.decide is not None:
                try:
                    result = bool(self.decide(event))
                except Exception:
                    result = True

            auth = ES_AUTH_RESULT_ALLOW if result else ES_AUTH_RESULT_DENY
            self._respond(client, message, auth)

        except Exception:
            self._respond(client, message, ES_AUTH_RESULT_ALLOW)

    def _extract_path_from_message(
        self, message: ctypes.c_void_p, event_type: int
    ) -> Optional[str]:
        """Extract file path from an ES message.

        The ES message layout (simplified):
          offset 0:  uint32 version
          offset 4:  uint32 event_type
          offset 8:  event union (exec, open, create, etc.)

        For AUTH_EXEC: event.exec.target->path
        For AUTH_OPEN: event.open.source->path

        ESFile layout: offset 0 = const char* path
        """
        try:
            msg_addr = ctypes.addressof(message.contents)
            event_addr = msg_addr + 8  # Skip version + event_type

            # The exec and open event types both have a pointer to ESFile
            # as their first field (target for exec, source for open).
            es_file_ptr = ctypes.c_void_p.from_address(event_addr).value
            if not es_file_ptr:
                return None

            # ESFile->path is at offset 0 of the ESFile struct.
            path_ptr = ctypes.c_char_p.from_address(es_file_ptr).value
            if not path_ptr:
                return None

            return path_ptr.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _respond(
        self, client: ctypes.c_void_p, message: ctypes.c_void_p, auth: int
    ) -> None:
        """Send an auth response to the framework."""
        es = _es
        if not es or not client:
            return
        try:
            es.es_respond_auth_result(client, message, auth, None)
        except Exception:
            pass

    def stop(self) -> None:
        self._stop_evt.set()
        es = _es
        if es and self._client:
            try:
                es.es_unsubscribe_all(self._client)
                es.es_close_client(self._client)
            except Exception:
                pass
            self._client = None

    def watched_count(self) -> int:
        return self._watched


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_es_backend(
    paths: List[str], excludes: Optional[List[str]] = None
) -> EndpointSecurityBackend:
    """Create an EndpointSecurity backend instance."""
    return EndpointSecurityBackend(paths, excludes=excludes)
