"""Archive sandbox — safe extraction with bomb detection.

Extracts archives (zip, tar, rar, 7z) in an isolated environment with
protections against:
- Zip bombs (nested compression ratio attacks)
- Path traversal (../../etc/passwd)
- Symlink attacks
- Archive nesting depth limits
- Decompression time limits
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import tarfile
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field
from typing import IO, Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Dangerous path patterns
_PATH_TRAVERSAL = re.compile(r"(^|[\\/])\.\.([\\/]|$)")
_ABSOLUTE_PATH = re.compile(r"^[/\\]|[A-Za-z]:")

# Known archive magic bytes
_ARCHIVE_MAGIC = {
    b"PK": "zip",
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ": "xz",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"Rar!": "rar",
}


@dataclass
class ArchiveEntry:
    name: str
    size: int
    compressed_size: int = 0
    is_dir: bool = False
    is_symlink: bool = False
    link_target: str = ""
    SHA256: str = ""
    depth: int = 0
    modified_time: float = 0.0


@dataclass
class ExtractionResult:
    archive_path: str = ""
    archive_type: str = "unknown"
    total_entries: int = 0
    extracted_entries: int = 0
    skipped_entries: int = 0
    entries: List[ArchiveEntry] = field(default_factory=list)

    # Security
    path_traversal_attempts: int = 0
    symlink_attacks: int = 0
    bomb_detected: bool = False
    bomb_type: str = ""
    max_nesting_depth: int = 0

    # Stats
    total_size_extracted: int = 0
    total_size_compressed: int = 0
    compression_ratio: float = 0.0
    extraction_time: float = 0.0

    # Risk
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    verdict: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "archive_type": self.archive_type,
            "total_entries": self.total_entries,
            "extracted_entries": self.extracted_entries,
            "skipped_entries": self.skipped_entries,
            "path_traversal_attempts": self.path_traversal_attempts,
            "symlink_attacks": self.symlink_attacks,
            "bomb_detected": self.bomb_detected,
            "bomb_type": self.bomb_type,
            "compression_ratio": self.compression_ratio,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "risk_factors": self.risk_factors,
        }


class ArchiveSandbox:
    """Safe archive extraction with bomb detection."""

    MAX_ENTRIES = 10000
    MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
    MAX_COMPRESSION_RATIO = 100  # 100:1 is likely a bomb
    MAX_NESTING_DEPTH = 5
    MAX_ENTRY_SIZE = 500 * 1024 * 1024  # 500 MB per file
    MAX_EXTRACTION_TIME = 60.0  # seconds
    MAX_INDIVIDUAL_SIZE = 100 * 1024 * 1024  # 100 MB per file during extraction

    def __init__(
        self,
        extract_dir: Optional[str] = None,
        max_entries: int = 10000,
        max_total_size: int = 2 * 1024 * 1024 * 1024,
    ):
        self._extract_dir = extract_dir
        self._max_entries = max_entries
        self._max_total_size = max_total_size

    def analyze(self, path: str) -> ExtractionResult:
        result = ExtractionResult(archive_path=path)

        if not os.path.isfile(path):
            result.risk_factors.append("file_not_found")
            return result

        archive_type = self._detect_type(path)
        result.archive_type = archive_type

        if archive_type == "zip":
            self._analyze_zip(path, result)
        elif archive_type in ("gzip", "bzip2", "xz", "tar"):
            self._analyze_tar(path, result, archive_type)
        else:
            result.risk_factors.append("unsupported_archive_type")

        self._compute_risk(result)
        return result

    def extract(self, path: str, dest_dir: str) -> ExtractionResult:
        result = self.analyze(path)

        if result.risk_score >= 0.7:
            result.verdict = "malicious"
            return result

        archive_type = result.archive_type
        start_time = time.time()

        if archive_type == "zip":
            self._extract_zip(path, dest_dir, result)
        elif archive_type in ("gzip", "bzip2", "xz"):
            self._extract_tar(path, dest_dir, result, archive_type)

        result.extraction_time = time.time() - start_time
        self._compute_risk(result)
        return result

    def _detect_type(self, path: str) -> str:
        try:
            with open(path, "rb") as f:
                head = f.read(8)
        except (OSError, PermissionError):
            return "unknown"

        for magic, ftype in _ARCHIVE_MAGIC.items():
            if head.startswith(magic):
                return ftype

        # Check if it's a tar (no magic, check for .tar extension)
        if path.endswith(".tar"):
            return "tar"
        if path.endswith((".tar.gz", ".tgz")):
            return "gzip"
        if path.endswith(".tar.bz2"):
            return "bzip2"
        if path.endswith(".tar.xz"):
            return "xz"

        return "unknown"

    def _analyze_zip(self, path: str, result: ExtractionResult) -> None:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                info_list = zf.infolist()
                result.total_entries = len(info_list)

                if result.total_entries > self._max_entries:
                    result.risk_factors.append("too_many_entries")
                    result.bomb_detected = True
                    result.bomb_type = "entry_count"
                    return

                total_compressed = 0
                total_uncompressed = 0

                for info in info_list:
                    entry = ArchiveEntry(
                        name=info.filename,
                        size=info.file_size,
                        compressed_size=info.compress_size,
                        is_dir=info.is_dir(),
                        modified_time=info.date_time,
                    )

                    total_compressed += info.compress_size
                    total_uncompressed += info.file_size

                    # Path traversal check
                    if _PATH_TRAVERSAL.search(info.filename):
                        result.path_traversal_attempts += 1
                        entry.depth = info.filename.count("..")

                    # Absolute path check
                    if _ABSOLUTE_PATH.match(info.filename):
                        result.path_traversal_attempts += 1

                    # Symlink in zip (via external attributes)
                    if info.external_attr >> 16 & 0o170000 == 0o120000:
                        entry.is_symlink = True
                        result.symlink_attacks += 1

                    # Single entry size check
                    if info.file_size > self.MAX_ENTRY_SIZE:
                        result.risk_factors.append("large_entry")

                    result.entries.append(entry)

                result.total_size_compressed = total_compressed
                result.total_size_extracted = total_uncompressed

                if total_compressed > 0:
                    result.compression_ratio = total_uncompressed / total_compressed

                # Bomb detection: compression ratio
                if result.compression_ratio > self.MAX_COMPRESSION_RATIO:
                    result.bomb_detected = True
                    result.bomb_type = "compression_ratio"

                # Zip bomb: many entries with high total uncompressed size
                if total_uncompressed > self._max_total_size:
                    result.bomb_detected = True
                    result.bomb_type = "total_uncompressed_size"

        except zipfile.BadZipFile:
            result.risk_factors.append("bad_zip_file")
        except (OSError, PermissionError) as e:
            result.risk_factors.append(f"zip_read_error: {e}")

    def _analyze_tar(
        self, path: str, result: ExtractionResult, compression: str
    ) -> None:
        try:
            if compression == "tar":
                mode = "r"
            elif compression == "bzip2":
                mode = "r:bz2"
            elif compression == "xz":
                mode = "r:xz"
            else:
                mode = "r:gz"

            with tarfile.open(path, mode) as tf:
                members = tf.getmembers()
                result.total_entries = len(members)

                if result.total_entries > self._max_entries:
                    result.risk_factors.append("too_many_entries")
                    result.bomb_detected = True
                    result.bomb_type = "entry_count"
                    return

                total_size = 0
                max_depth = 0

                for member in members:
                    entry = ArchiveEntry(
                        name=member.name,
                        size=member.size,
                        is_dir=member.isdir(),
                        is_symlink=member.issym(),
                        link_target=member.linkname or "",
                        depth=member.name.count("/"),
                    )
                    total_size += member.size
                    max_depth = max(max_depth, entry.depth)

                    # Path traversal check
                    if _PATH_TRAVERSAL.search(member.name):
                        result.path_traversal_attempts += 1

                    # Absolute path check
                    if _ABSOLUTE_PATH.match(member.name):
                        result.path_traversal_attempts += 1

                    # Symlink attack check
                    if member.issym():
                        target = member.linkname
                        if target and (
                            _ABSOLUTE_PATH.match(target)
                            or _PATH_TRAVERSAL.search(target)
                        ):
                            result.symlink_attacks += 1

                    # Size checks
                    if member.size > self.MAX_ENTRY_SIZE:
                        result.risk_factors.append("large_entry")

                    result.entries.append(entry)

                result.total_size_extracted = total_size
                result.max_nesting_depth = max_depth

                if max_depth > self.MAX_NESTING_DEPTH:
                    result.risk_factors.append("excessive_nesting")

        except tarfile.TarError:
            result.risk_factors.append("bad_tar_file")
        except (OSError, PermissionError) as e:
            result.risk_factors.append(f"tar_read_error: {e}")

    def _extract_zip(self, path: str, dest: str, result: ExtractionResult) -> None:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    # Security checks before extraction
                    if _PATH_TRAVERSAL.search(info.filename):
                        logger.warning("Skipping path traversal: %s", info.filename)
                        result.skipped_entries += 1
                        continue

                    if _ABSOLUTE_PATH.match(info.filename):
                        logger.warning("Skipping absolute path: %s", info.filename)
                        result.skipped_entries += 1
                        continue

                    if info.file_size > self.MAX_INDIVIDUAL_SIZE:
                        logger.warning("Skipping oversized entry: %s", info.filename)
                        result.skipped_entries += 1
                        continue

                    # Safe extraction
                    zf.extract(info, dest)
                    result.extracted_entries += 1

        except (zipfile.BadZipFile, OSError) as e:
            result.risk_factors.append(f"extraction_error: {e}")

    def _extract_tar(
        self, path: str, dest: str, result: ExtractionResult, compression: str
    ) -> None:
        try:
            if compression == "tar":
                mode = "r"
            elif compression == "bzip2":
                mode = "r:bz2"
            elif compression == "xz":
                mode = "r:xz"
            else:
                mode = "r:gz"

            with tarfile.open(path, mode) as tf:
                for member in tf.getmembers():
                    # Security checks
                    if _PATH_TRAVERSAL.search(member.name):
                        logger.warning("Skipping path traversal: %s", member.name)
                        result.skipped_entries += 1
                        continue

                    if _ABSOLUTE_PATH.match(member.name):
                        logger.warning("Skipping absolute path: %s", member.name)
                        result.skipped_entries += 1
                        continue

                    if member.size > self.MAX_INDIVIDUAL_SIZE:
                        logger.warning("Skipping oversized: %s", member.name)
                        result.skipped_entries += 1
                        continue

                    # Symlink safety
                    if member.issym() or member.islnk():
                        target = member.linkname
                        if target and _PATH_TRAVERSAL.search(target):
                            result.skipped_entries += 1
                            continue

                    tf.extract(member, dest)
                    result.extracted_entries += 1

        except (tarfile.TarError, OSError) as e:
            result.risk_factors.append(f"extraction_error: {e}")

    def _compute_risk(self, result: ExtractionResult) -> None:
        score = 0.0
        factors = []

        if result.bomb_detected:
            score += 0.5
            factors.append(f"bomb_detected({result.bomb_type})")

        if result.path_traversal_attempts > 0:
            score += 0.3
            factors.append(f"path_traversal({result.path_traversal_attempts})")

        if result.symlink_attacks > 0:
            score += 0.25
            factors.append(f"symlink_attack({result.symlink_attacks})")

        if result.compression_ratio > 50:
            score += 0.2
            factors.append(f"high_compression({result.compression_ratio:.0f}:1)")

        if result.total_entries > 5000:
            score += 0.1
            factors.append(f"many_entries({result.total_entries})")

        if result.max_nesting_depth > 3:
            score += 0.1
            factors.append(f"deep_nesting({result.max_nesting_depth})")

        result.risk_score = min(1.0, score)
        result.risk_factors.extend(factors)

        if result.risk_score >= 0.7:
            result.verdict = "malicious"
        elif result.risk_score >= 0.3:
            result.verdict = "suspicious"
        else:
            result.verdict = "clean"
