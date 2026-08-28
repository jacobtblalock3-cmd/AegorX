from __future__ import annotations

import hashlib
import os
from typing import Dict

try:
    import _aegorx_core as _fast_core

    FAST_BACKEND = "rust"
except ImportError:
    _fast_core = None
    FAST_BACKEND = "python"


def file_hashes(path: str) -> Dict[str, str]:
    if _fast_core is not None and os.path.getsize(path) > 4 * 1024 * 1024:
        sha256 = _fast_core.stream_sha256(path)
        md5, sha1 = _slow_extra(path)
        return {"md5": md5, "sha1": sha1, "sha256": sha256}
    return _hashes_python(path)


def file_hashes_fd(fd: int, size: int) -> Dict[str, str]:
    """Hash an ALREADY-OPEN descriptor without calling open(2).

    fanotify permission decisions must never open the watched path again:
    that queues a nested permission event and deadlocks the reader. The
    caller passes a dup() of the event's kernel-provided fd; we read it
    through a private file-object copy so the original position is kept.
    """
    h_md5 = hashlib.md5(usedforsecurity=False)
    h_sha1 = hashlib.sha1(usedforsecurity=False)
    h_sha256 = hashlib.sha256()
    read = 0
    with os.fdopen(os.dup(fd), "rb", closefd=True) as fh:
        fh.seek(0)
        while read < size:
            chunk = fh.read(min(1024 * 1024, size - read))
            if not chunk:
                break
            read += len(chunk)
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}


def _hashes_python(path: str) -> Dict[str, str]:
    h_md5 = hashlib.md5(usedforsecurity=False)
    h_sha1 = hashlib.sha1(usedforsecurity=False)
    h_sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}


def _slow_extra(path: str):
    h_md5 = hashlib.md5(usedforsecurity=False)
    h_sha1 = hashlib.sha1(usedforsecurity=False)
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h_md5.update(chunk)
            h_sha1.update(chunk)
    return h_md5.hexdigest(), h_sha1.hexdigest()
