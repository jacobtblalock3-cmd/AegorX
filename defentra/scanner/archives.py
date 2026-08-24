"""Bounded archive inspection: ZIP, tar (+gz/bz2/xz), and single-file gzip.

Extraction is deliberately paranoid because archives are a classic denial-
of-service and evasion vector:

- Every entry is written under an attacker-uninfluenceable name (its digest),
  so path traversal ("zip-slip") cannot escape the working directory.
- A shared budget caps total uncompressed bytes, entry count, per-entry size,
  nesting depth, and wall-clock time. Exceeding the byte budget with a
  suspicious compression ratio raises ArchiveBomb so the caller can flag the
  parent instead of grinding on.
- Nested archives recurse through the engine, not this module, up to the
  depth limit; deeper entries are reported as skipped.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import os
import shutil
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional

MAGIC_ZIP = b"PK\x03\x04"
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_BZIP2 = b"BZh"
MAGIC_XZ = b"\xfd7zXZ\x00"
MAGIC_TAR_OFFSET = 257

# A healthy archive compresses text ~10x; anything far beyond that against
# the raw file size is treated as a bomb attempt rather than extracted.
MAX_SANE_RATIO = 600
MIN_BOMB_FLOOR_BYTES = 64 * 1024 * 1024


class ArchiveError(Exception):
    """Archive could not be inspected (corrupt, unsupported, unreadable)."""


class ArchiveBomb(ArchiveError):
    """Resource budget blown with a bomb-like compression ratio."""


@dataclass
class ArchiveLimits:
    max_entries: int = 1000
    max_total_bytes: int = 256 * 1024 * 1024
    max_entry_bytes: int = 128 * 1024 * 1024
    max_depth: int = 3
    timeout_seconds: float = 60.0


@dataclass
class _Budget:
    limits: ArchiveLimits
    entries_used: int = 0
    bytes_used: int = 0
    deadline: float = field(default_factory=lambda: time.monotonic())

    def __post_init__(self) -> None:
        self.deadline += self.limits.timeout_seconds


@dataclass
class ArchiveEntry:
    name: str
    size: int
    temp_path: str


def sniff_format(path: str) -> Optional[str]:
    """Identify archive container by magic bytes (never by extension)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if head.startswith(MAGIC_ZIP):
        return "zip"
    if head.startswith(MAGIC_GZIP):
        return "gzip"
    if head.startswith(MAGIC_BZIP2):
        return "bzip2"
    if head.startswith(MAGIC_XZ):
        return "xz"
    if len(head) > MAGIC_TAR_OFFSET + 5 and head[MAGIC_TAR_OFFSET:MAGIC_TAR_OFFSET + 5] == b"ustar":
        return "tar"
    return None


def looks_like_archive(head: bytes) -> bool:
    if head.startswith((MAGIC_ZIP, MAGIC_GZIP, MAGIC_BZIP2, MAGIC_XZ)):
        return True
    if len(head) > MAGIC_TAR_OFFSET + 5 and head[MAGIC_TAR_OFFSET:MAGIC_TAR_OFFSET + 5] == b"ustar":
        return True
    # gzip/bzip2/xz wrappers around tar start with their own magic (covered
    # above); plain tar is caught here for short reads too.
    return False


def _check_budget(budget: _Budget) -> None:
    if time.monotonic() > budget.deadline:
        raise ArchiveError("extraction exceeded time budget")
    if budget.entries_used > budget.limits.max_entries:
        raise ArchiveBomb(f"entry count exceeded {budget.limits.max_entries}")


def _write_stream(stream: io.BufferedIOBase, workdir: str, name: str, budget: _Budget) -> Optional[ArchiveEntry]:
    """Stream one entry to disk under a safe name, enforcing the budget."""
    digest = hashlib.sha256(name.encode("utf-8", "replace")).hexdigest()[:16]
    out_path = os.path.join(workdir, f"{digest}.bin")
    written = 0
    try:
        with open(out_path, "wb") as out:
            while True:
                chunk = stream.read(256 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                budget.bytes_used += len(chunk)
                if written > budget.limits.max_entry_bytes:
                    raise ArchiveBomb(f"entry '{name}' exceeds per-entry cap")
                if budget.bytes_used > budget.limits.max_total_bytes:
                    raise ArchiveBomb(f"total uncompressed bytes exceeded {budget.limits.max_total_bytes}")
                out.write(chunk)
    except OSError:
        try:
            os.unlink(out_path)
        except OSError:
            pass
        return None
    budget.entries_used += 1
    _check_budget(budget)
    return ArchiveEntry(name=name, size=written, temp_path=out_path)


def _extract_zip(path: str, workdir: str, budget: _Budget) -> List[ArchiveEntry]:
    entries: List[ArchiveEntry] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            _check_budget(budget)
            if info.is_dir():
                continue
            ratio_ok = (
                info.file_size <= MIN_BOMB_FLOOR_BYTES
                or info.compress_size == 0
                or info.file_size / max(1, info.compress_size) <= MAX_SANE_RATIO
            )
            if not ratio_ok:
                raise ArchiveBomb(f"entry '{info.filename}' has impossible compression ratio")
            try:
                with zf.open(info) as stream:
                    entry = _write_stream(stream, workdir, info.filename, budget)
            except RuntimeError as exc:  # encrypted entry
                raise ArchiveError(f"entry '{info.filename}' unreadable: {exc}") from exc
            if entry:
                entries.append(entry)
    return entries


def _extract_tar(path: str, workdir: str, budget: _Budget, mode: str = "r:*") -> List[ArchiveEntry]:
    entries: List[ArchiveEntry] = []
    # Members are read via extractfile and re-written under safe names;
    # extractall()/extract() are never used, so link/special-member and
    # traversal attacks have no effect.
    with tarfile.open(path, mode) as tf:
        for member in tf.getmembers():
            _check_budget(budget)
            if not member.isfile():
                continue
            if member.size > budget.limits.max_entry_bytes:
                raise ArchiveBomb(f"member '{member.name}' exceeds per-entry cap")
            stream = tf.extractfile(member)
            if stream is None:
                continue
            entry = _write_stream(stream, workdir, member.name, budget)
            if entry:
                entries.append(entry)
    return entries


_COMPRESSION_OPENERS = {
    "gzip": gzip.open,
    "bzip2": bz2.open,
    "xz": lzma.open,
}


def _extract_single_compressed(path: str, workdir: str, budget: _Budget, fmt: str) -> List[ArchiveEntry]:
    """A bare .gz/.bz2/.xz wrapping one file (possibly a tar or nested payload)."""
    inner_name = os.path.basename(path)
    for ext in (".gz", ".bz2", ".xz"):
        if inner_name.lower().endswith(ext):
            inner_name = inner_name[: -len(ext)]
            break
    opener = _COMPRESSION_OPENERS[fmt]
    with opener(path, "rb") as stream:
        entry = _write_stream(stream, workdir, inner_name, budget)
    return [entry] if entry else []


def extract_archive(
    path: str,
    workdir: Optional[str] = None,
    limits: Optional[ArchiveLimits] = None,
) -> List[ArchiveEntry]:
    """Extract one level of `path` into `workdir` under the given limits.

    Returns the extracted entries. Raises ArchiveError/ArchiveBomb; the
    caller owns cleanup of workdir when it supplied one.
    """
    limits = limits or ArchiveLimits()
    owned = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="defentra-arch-")
    try:
        fmt = sniff_format(path)
        if fmt == "zip":
            return _extract_zip(path, workdir, _Budget(limits))
        if fmt == "tar":
            return _extract_tar(path, workdir, _Budget(limits))
        if fmt in ("gzip", "bzip2", "xz"):
            budget = _Budget(limits)
            try:
                return _extract_tar(path, workdir, budget, mode="r:*")
            except tarfile.TarError:
                pass
            return _extract_single_compressed(path, workdir, _Budget(limits), fmt)
        raise ArchiveError("unsupported or unrecognized archive format")
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, lzma.LZMAError, OSError) as exc:
        raise ArchiveError(f"malformed archive: {exc}") from exc
    finally:
        if owned:
            shutil.rmtree(workdir, ignore_errors=True)


def iter_nested_candidates(entries: List[ArchiveEntry]) -> List[ArchiveEntry]:
    """Entries whose content sniffs as an archive and deserves recursion."""
    nested = []
    for entry in entries:
        try:
            with open(entry.temp_path, "rb") as fh:
                if looks_like_archive(fh.read(8)):
                    nested.append(entry)
        except OSError:
            continue
    return nested
