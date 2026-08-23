"""Core scan engine: orchestrates signature, YARA, and ML detectors."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from defentra.ml.features import extract_features, looks_executable, vectorize
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
DEFAULT_RULES_DIRS = [_REPO_RULES_DIR] if os.path.isdir(_REPO_RULES_DIR) else []


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
        self.yara = YaraScanner(rules_dirs or DEFAULT_RULES_DIRS)
        self.max_file_size = max_file_size
        self.fast_backend = FAST_BACKEND
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
        result = FileScanResult(path=os.path.abspath(path))
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
        if self.classifier is not None and self.classifier.available:
            try:
                with open(path, "rb") as fh:
                    head = fh.read(4)
                if looks_executable(head):
                    feats = extract_features(path)
                    ml_prob = self.classifier.predict_proba(vectorize(feats))
            except OSError:
                pass
            except Exception:
                ml_failed = True
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
        if ml_failed and result.verdict == "clean":
            result.verdict = "error"
            result.error = "feature extraction failed on malformed input"
        return result

    @staticmethod
    def _verdict(detections: List[Detection], ml_prob: Optional[float]) -> str:
        if any(d.severity >= MALICIOUS_SEVERITY for d in detections):
            return "malicious"
        if ml_prob is not None and ml_prob >= MALICIOUS_PROBABILITY:
            return "malicious"
        if any(d.severity >= SUSPICIOUS_SEVERITY for d in detections):
            return "suspicious"
        if ml_prob is not None and ml_prob >= SUSPICIOUS_PROBABILITY:
            return "suspicious"
        return "clean"
