"""Shared helpers used across the Defentra engine."""

from __future__ import annotations

import math
import os
import stat

DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".defentra")
MAX_HASH_FILE_SIZE = 2 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


def state_dir() -> str:
    override = os.environ.get("DEFENTRA_HOME")
    return override if override else DEFAULT_STATE_DIR


def ensure_state_dir() -> str:
    """Create the state directory with owner-only permissions (0700)."""
    path = state_dir()
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        current = stat.S_IMODE(os.stat(path).st_mode)
        if current & 0o077:
            os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def iter_file_chunks(path: str, chunk_size: int = CHUNK_SIZE):
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            yield chunk


def read_capped(path: str, cap: int) -> bytes:
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        if size <= cap:
            return fh.read()
        head = fh.read(cap // 2)
        fh.seek(-min(cap // 4, size), os.SEEK_END)
        tail = fh.read(cap // 4)
        return head + tail


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def human_size(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.0f} {unit}" if unit == "B" else f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def rva_to_offset(rva: int, sections) -> int | None:
    """Map a PE relative virtual address to a raw file offset."""
    for sec in sections:
        if sec["virtual_address"] <= rva < sec["virtual_address"] + max(sec["virtual_size"], sec["raw_size"]):
            delta = rva - sec["virtual_address"]
            if delta < sec["raw_size"]:
                return sec["raw_pointer"] + delta
    return None
