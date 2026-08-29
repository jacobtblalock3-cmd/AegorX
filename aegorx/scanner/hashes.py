from __future__ import annotations

import collections
import hashlib
import os
from typing import Dict, Optional, Tuple

try:
    import _aegorx_core as _fast_core

    FAST_BACKEND = "rust"
except ImportError:
    _fast_core = None
    FAST_BACKEND = "python"

# Hash cache: (path, mtime, size) -> {md5, sha1, sha256}
# Prevents re-hashing unchanged files across repeated scans.
_HASH_CACHE: collections.OrderedDict = collections.OrderedDict()
_HASH_CACHE_MAX = 8192


def file_hashes(path: str) -> Dict[str, str]:
    """Compute MD5, SHA1, SHA256 of a file, using cache when possible."""
    cache_key = _cache_key(path)
    if cache_key and cache_key in _HASH_CACHE:
        _HASH_CACHE.move_to_end(cache_key)
        return _HASH_CACHE[cache_key]

    if _fast_core is not None and os.path.getsize(path) > 4 * 1024 * 1024:
        sha256 = _fast_core.stream_sha256(path)
        md5, sha1 = _slow_extra(path)
        result = {"md5": md5, "sha1": sha1, "sha256": sha256}
    else:
        result = _hashes_python(path)

    if cache_key:
        _HASH_CACHE[cache_key] = result
        while len(_HASH_CACHE) > _HASH_CACHE_MAX:
            _HASH_CACHE.popitem(last=False)

    return result


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


def _cache_key(path: str) -> Optional[Tuple]:
    """Generate cache key from path, mtime, and size. Returns None if stat fails."""
    try:
        s = os.stat(path)
        return (path, s.st_mtime, s.st_size)
    except OSError:
        return None


def clear_hash_cache() -> None:
    """Clear the hash cache (e.g., after signature DB updates)."""
    _HASH_CACHE.clear()
