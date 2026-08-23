from __future__ import annotations

import hashlib
import os
from typing import Dict

try:
    import _defentra_core as _fast_core

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
