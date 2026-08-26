"""Core scan engine: orchestrates signature, YARA, ML, archive, and macro detectors."""

from __future__ import annotations

import os
import sys
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from defentra.ml.features import extract_features, looks_executable, vectorize
from defentra.scanner import archives, office, pdfdoc
from defentra.scanner.archives import ArchiveLimits
from defentra.scanner.hashes import FAST_BACKEND, file_hashes
from defentra.scanner.yara_scanner import YaraScanner
from defentra.signatures.db import SignatureDB

MALICIOUS_SEVERITY = 8
SUSPICIOUS_SEVERITY = 5
MALICIOUS_PROBABILITY = 0.85
SUSPICIOUS_PROBABILITY = 0.60
DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024
_REPO_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules"
)


def _candidate_rules_dirs() -> List[str]:
    """Where YARA rule files may live: source tree, or frozen-app layouts."""
    candidates = [_REPO_RULES_DIR]
    frozen_base = getattr(sys, "_MEIPASS", None) or (
        os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else None
    )
    if frozen_base:
        candidates.append(os.path.join(frozen_base, "rules"))
    return [d for d in candidates if os.path.isdir(d)]


DEFAULT_RULES_DIRS = _candidate_rules_dirs()


@dataclass
class Detection:
    detector: str
    name: str
    severity: int
    details: Dict = field(default_factory=dict)


@dataclass
class FileScanResult:
    path: str
    size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    verdict: str = "clean"
    detections: List[Detection] = field(default_factory=list)
    ml_probability: Optional[float] = None
    error: Optional[str] = None


class ScanEngine:
    """Multi-detector file scanner.

    Verdict policy:
      malicious : any detection with severity >= MALICIOUS_SEVERITY, or ML prob >= MALICIOUS_PROBABILITY
      suspicious: any detection >= SUSPICIOUS_SEVERITY, or ML prob >= SUSPICIOUS_PROBABILITY
      clean     : otherwise
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        rules_dirs: Optional[List[str]] = None,
        enable_ml: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ):
        self.db = SignatureDB(db_path)
        dirs = list(rules_dirs) if rules_dirs is not None else list(DEFAULT_RULES_DIRS)
        from defentra.rules_store import rules_dir as state_rules_dir

        state_dir_path = state_rules_dir()
        if state_dir_path not in dirs:
            dirs.append(state_dir_path)
        self.yara = YaraScanner(dirs)
        self.max_file_size = max_file_size
        self.archive_limits = ArchiveLimits()
        self.fast_backend = FAST_BACKEND

        # Fleet policy overrides (optional central management): thresholds
        # only; detection content itself always comes from signed feeds.
        from defentra.policy import load_policy

        policy = load_policy() or {}
        self.malicious_probability = float(
            policy.get("malicious_probability", MALICIOUS_PROBABILITY)
        )
        self.suspicious_probability = float(
            policy.get("suspicious_probability", SUSPICIOUS_PROBABILITY)
        )
        self.classifier = None
        if enable_ml:
            from defentra.ml.classifier import MalwareClassifier

            self.classifier = MalwareClassifier()

    @property
    def capabilities(self) -> Dict:
        return {
            "signature_db": self.db.count(),
            "yara_available": self.yara.available,
            "yara_rules": self.yara.rule_count,
            "ml_model": bool(self.classifier and self.classifier.available),
            "hash_backend": self.fast_backend,
            "archives": True,
            "office_macros": office.OFFICE_AVAILABLE,
            "pdf": True,
        }

    def scan_target(self, target: str, recursive: bool = True) -> List[FileScanResult]:
        target = os.path.abspath(target)
        results: List[FileScanResult] = []
        if os.path.isdir(target):
            for root, dirs, files in os.walk(target):
                if not recursive:
                    dirs[:] = []
                for name in sorted(files):
                    results.append(self.scan_file(os.path.join(root, name)))
        elif os.path.isfile(target):
            results.append(self.scan_file(target))
        else:
            results.append(FileScanResult(path=target, verdict="error", error="no such file or directory"))
        return results

    def scan_file(self, path: str) -> FileScanResult:
        return self._scan_file(os.path.abspath(path), depth=0)

    def scan_file_descriptor(self, fd: int, path_hint: str = "") -> FileScanResult:
        """Scan via an ALREADY-OPEN descriptor without open(2) on the path.

        Used by fanotify permission decisions: the kernel hands us an open
        handle for the very open we are adjudicating; re-opening the path
        would queue a nested permission event and deadlock the reader.
        Signature + YARA detectors run on the descriptor's bytes; ML and
        archive recursion stay path-based and are skipped in this mode.
        """
        result = FileScanResult(path=path_hint or f"<fd:{fd}>")
        try:
            st = os.fstat(fd)
        except OSError as exc:
            result.verdict = "error"
            result.error = str(exc)
            return result
        size = st.st_size
        result.size = size
        if size > self.max_file_size:
            result.verdict = "error"
            result.error = f"skipped: exceeds max size ({self.max_file_size} bytes)"
            return result

        from defentra.scanner.hashes import file_hashes_fd

        try:
            dup = os.dup(fd)
        except OSError as exc:
            result.verdict = "error"
            result.error = str(exc)
            return result
        try:
            hashes = file_hashes_fd(dup, size)
            result.md5, result.sha1, result.sha256 = (
                hashes["md5"],
                hashes["sha1"],
                hashes["sha256"],
            )
        except OSError as exc:
            os.close(dup)
            result.verdict = "error"
            result.error = str(exc)
            return result

        detections: List[Detection] = []
        sig = self.db.lookup(sha256=result.sha256, md5=result.md5, sha1=result.sha1)
        if sig:
            detections.append(
                Detection(
                    detector="signature",
                    name=sig["name"],
                    severity=int(sig["severity"]),
                    details={"family": sig.get("family", ""), "source": sig.get("source", "")},
                )
            )
        try:
            os.lseek(dup, 0, os.SEEK_SET)
            with os.fdopen(os.dup(dup), "rb") as fh:
                data = fh.read(self.max_file_size + 1)
            for m in self.yara.match_bytes(data):
                detections.append(
                    Detection(
                        detector="yara",
                        name=m["rule"],
                        severity=m["severity"],
                        details={"tags": ",".join(m["tags"])},
                    )
                )
        except OSError:
            pass
        finally:
            os.close(dup)

        result.detections = detections
        result.verdict = self._verdict(detections, None)
        return result

    def _scan_file(self, path: str, depth: int) -> FileScanResult:
        result = FileScanResult(path=path)
        try:
            result.size = os.path.getsize(path)
        except OSError as exc:
            result.verdict = "error"
            result.error = str(exc)
            return result
        if result.size > self.max_file_size:
            result.verdict = "error"
            result.error = f"skipped: exceeds max size ({self.max_file_size} bytes)"
            return result
        try:
            hashes = file_hashes(path)
            result.md5, result.sha1, result.sha256 = (
                hashes["md5"],
                hashes["sha1"],
                hashes["sha256"],
            )
        except OSError as exc:
            result.verdict = "error"
            result.error = str(exc)
            return result

        detections: List[Detection] = []
        sig = self.db.lookup(sha256=result.sha256, md5=result.md5, sha1=result.sha1)
        if sig:
            detections.append(
                Detection(
                    detector="signature",
                    name=sig["name"],
                    severity=int(sig["severity"]),
                    details={"family": sig.get("family", ""), "source": sig.get("source", "")},
                )
            )
        for m in self.yara.match_file(path):
            detections.append(
                Detection(
                    detector="yara",
                    name=m["rule"],
                    severity=m["severity"],
                    details={"tags": ",".join(m["tags"])},
                )
            )

        ml_prob: Optional[float] = None
        ml_failed = False
        try:
            with open(path, "rb") as fh:
                head = fh.read(512)
        except OSError:
            head = b""
        if self.classifier is not None and self.classifier.available:
            try:
                if looks_executable(head):
                    feats = extract_features(path)
                    ml_prob = self.classifier.predict_proba(vectorize(feats))
            except OSError:
                pass
            except Exception:
                ml_failed = True

        # Office documents: VBA macro risk analysis (also reached through
        # archive entries, e.g. word/vbaProject.bin inside a .docx).
        if office.looks_like_office(head):
            office_detections = office.analyze_document(path)
            if office_detections is None:
                if not office.OFFICE_AVAILABLE and not detections:
                    detections.append(
                        Detection(
                            detector="office",
                            name="Document.MacroAnalysisUnavailable",
                            severity=3,
                            details={"hint": "pip install 'defentra[office]'"},
                        )
                    )
            else:
                for od in office_detections:
                    detections.append(Detection("office", od["name"], od["severity"], od["details"]))

        # PDF documents: auto-exec / launch-action analysis (also reached
        # through archive entries).
        if pdfdoc.looks_like_pdf(head):
            pdf_detections = pdfdoc.analyze_pdf(path)
            if pdf_detections:
                for pd in pdf_detections:
                    detections.append(Detection("pdf", pd["name"], pd["severity"], pd["details"]))

        # Archives: bounded extraction, then recursive scan of the contents.
        archive_note: Optional[str] = None
        if archives.looks_like_archive(head):
            if depth >= self.archive_limits.max_depth:
                detections.append(
                    Detection(
                        detector="archive",
                        name="Archive.NestedTooDeep",
                        severity=3,
                        details={"depth": depth, "limit": self.archive_limits.max_depth},
                    )
                )
            else:
                inner_detections, inner_probs, note = self._scan_archive_contents(path, depth)
                detections.extend(inner_detections)
                archive_note = note
                if inner_probs:
                    candidates = [p for p in (ml_prob, *inner_probs) if p is not None]
                    ml_prob = max(candidates) if candidates else None

        result.ml_probability = ml_prob
        if ml_prob is not None:
            if ml_prob >= MALICIOUS_PROBABILITY:
                detections.append(
                    Detection(
                        detector="ml",
                        name="Heuristic.Malware.HighConfidence",
                        severity=9,
                        details={"probability": round(ml_prob, 4)},
                    )
                )
            elif ml_prob >= SUSPICIOUS_PROBABILITY:
                detections.append(
                    Detection(
                        detector="ml",
                        name="Heuristic.Suspicious.StaticFeatures",
                        severity=6,
                        details={"probability": round(ml_prob, 4)},
                    )
                )

        result.detections = detections
        result.verdict = self._verdict(detections, ml_prob)
        if archive_note and not detections:
            result.verdict = "error"
            result.error = f"archive {archive_note}"
        if ml_failed and result.verdict == "clean":
            result.verdict = "error"
            result.error = "feature extraction failed on malformed input"
        return result

    def _scan_archive_contents(
        self, path: str, depth: int
    ) -> Tuple[List[Detection], List[float], Optional[str]]:
        """Extract and scan one level of an archive.

        Returns (detections prefixed with 'archive:', inner ML probabilities,
        note). A non-None note means the container itself was unscannable.
        """
        workdir = tempfile.mkdtemp(prefix="defentra-arch-")
        try:
            try:
                entries = archives.extract_archive(path, workdir, self.archive_limits)
            except archives.ArchiveBomb as exc:
                return (
                    [Detection("archive", "Archive.BombSuspected", 6, {"detail": str(exc)})],
                    [],
                    None,
                )
            except archives.ArchiveError as exc:
                return [], [], f"unscannable ({exc})"

            collected: List[Detection] = []
            probabilities: List[float] = []
            for entry in entries:
                inner = self._scan_file(entry.temp_path, depth + 1)
                if inner.ml_probability is not None:
                    probabilities.append(inner.ml_probability)
                for d in inner.detections:
                    details = {"entry": entry.name}
                    details.update(d.details)
                    collected.append(
                        Detection(f"archive:{d.detector}", d.name, d.severity, details)
                    )
            return collected, probabilities, None
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def _verdict(self, detections: List[Detection], ml_prob: Optional[float]) -> str:
        if any(d.severity >= MALICIOUS_SEVERITY for d in detections):
            return "malicious"
        if ml_prob is not None and ml_prob >= self.malicious_probability:
            return "malicious"
        if any(d.severity >= SUSPICIOUS_SEVERITY for d in detections):
            return "suspicious"
        if ml_prob is not None and ml_prob >= self.suspicious_probability:
            return "suspicious"
        return "clean"
