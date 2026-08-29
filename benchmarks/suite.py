"""Benchmark suite for evaluating AegorX detection and performance.

Provides standardized metrics comparable to AV-TEST / AV-Comparatives:
- True Positive Rate (TPR) / Recall
- False Positive Rate (FPR)
- Scan throughput (files/second)
- Memory usage profiling
"""

from __future__ import annotations

import collections
import json
import logging
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Results from a single benchmark run."""
    name: str = ""
    timestamp: float = field(default_factory=time.time)
    duration_seconds: float = 0.0

    # Detection metrics
    total_files: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    false_positives: int = 0

    # Derived metrics
    tpr: float = 0.0  # True Positive Rate (recall / detection rate)
    fpr: float = 0.0  # False Positive Rate
    precision: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0

    # Performance metrics
    scan_rate: float = 0.0  # files per second
    avg_scan_time_ms: float = 0.0
    peak_memory_mb: float = 0.0

    # Per-detector breakdown
    detector_stats: Dict[str, Dict[str, int]] = field(default_factory=dict)

    # Error tracking
    errors: int = 0
    skipped: int = 0

    def compute_derived(self) -> None:
        """Compute derived metrics from raw counts."""
        tp, fn, tn, fp = (
            self.true_positives,
            self.false_negatives,
            self.true_negatives,
            self.false_positives,
        )
        total_pos = tp + fn
        total_neg = tn + fp

        self.tpr = tp / total_pos if total_pos > 0 else 0.0
        self.fpr = fp / total_neg if total_neg > 0 else 0.0
        self.precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        self.f1_score = (
            2 * self.precision * self.tpr / (self.precision + self.tpr)
            if (self.precision + self.tpr) > 0
            else 0.0
        )
        self.accuracy = (tp + tn) / self.total_files if self.total_files > 0 else 0.0

        if self.duration_seconds > 0:
            self.scan_rate = self.total_files / self.duration_seconds

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration_seconds, 3),
            "total_files": self.total_files,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "precision": round(self.precision, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
            "scan_rate": round(self.scan_rate, 1),
            "avg_scan_time_ms": round(self.avg_scan_time_ms, 2),
            "peak_memory_mb": round(self.peak_memory_mb, 1),
            "detector_stats": self.detector_stats,
            "errors": self.errors,
            "skipped": self.skipped,
        }

    def summary(self) -> str:
        return (
            f"Detection Rate (TPR): {self.tpr:.1%}\n"
            f"False Positive Rate:  {self.fpr:.1%}\n"
            f"Precision:            {self.precision:.1%}\n"
            f"F1 Score:             {self.f1_score:.3f}\n"
            f"Scan Throughput:      {self.scan_rate:.0f} files/sec\n"
            f"Avg Scan Time:        {self.avg_scan_time_ms:.1f} ms\n"
            f"Peak Memory:          {self.peak_memory_mb:.1f} MB\n"
            f"Total Files:          {self.total_files}\n"
            f"  TP={self.true_positives} FN={self.false_negatives} "
            f"TN={self.true_negatives} FP={self.false_positives}"
        )


class BenchmarkSuite:
    """Run detection and performance benchmarks against labeled datasets.

    Expected directory structure:
        data_dir/
            benign/     -- known clean files
            malicious/  -- known malware samples

    Or provide custom file lists.
    """

    def __init__(self, engine, data_dir: Optional[str] = None):
        self._engine = engine
        self._data_dir = data_dir

    def run_detection_benchmark(
        self,
        benign_files: Optional[List[str]] = None,
        malicious_files: Optional[List[str]] = None,
        name: str = "detection_benchmark",
    ) -> BenchmarkResult:
        """Evaluate detection accuracy against labeled files."""
        result = BenchmarkResult(name=name)

        if benign_files is None or malicious_files is None:
            if self._data_dir:
                benign_files = benign_files or self._collect_files(
                    os.path.join(self._data_dir, "benign")
                )
                malicious_files = malicious_files or self._collect_files(
                    os.path.join(self._data_dir, "malicious")
                )
            else:
                logger.warning("No data_dir or file lists provided")
                return result

        all_files = [(f, 0) for f in benign_files] + [(f, 1) for f in malicious_files]
        result.total_files = len(all_files)

        if not all_files:
            return result

        import tracemalloc
        tracemalloc.start()

        start_time = time.time()
        for path, label in all_files:
            try:
                scan_result = self._engine.scan_file(path)
                predicted = 1 if scan_result.verdict == "malicious" else 0

                if label == 1 and predicted == 1:
                    result.true_positives += 1
                elif label == 1 and predicted == 0:
                    result.false_negatives += 1
                elif label == 0 and predicted == 0:
                    result.true_negatives += 1
                elif label == 0 and predicted == 1:
                    result.false_positives += 1

                # Track per-detector stats
                for det in scan_result.detections:
                    dname = det.detector
                    if dname not in result.detector_stats:
                        result.detector_stats[dname] = {"detections": 0, "total_severity": 0}
                    result.detector_stats[dname]["detections"] += 1
                    result.detector_stats[dname]["total_severity"] += det.severity

            except Exception as e:
                result.errors += 1
                logger.debug("Benchmark error on %s: %s", path, e)

        result.duration_seconds = time.time() - start_time

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        result.peak_memory_mb = peak / (1024 * 1024)

        if result.total_files > 0:
            result.avg_scan_time_ms = (result.duration_seconds * 1000) / result.total_files

        result.compute_derived()
        return result

    def run_performance_benchmark(
        self,
        files: Optional[List[str]] = None,
        iterations: int = 3,
        name: str = "performance_benchmark",
    ) -> BenchmarkResult:
        """Measure scan throughput and latency."""
        result = BenchmarkResult(name=name)

        if files is None:
            if self._data_dir:
                files = self._collect_files(self._data_dir)
            else:
                return result

        result.total_files = len(files) * iterations

        import tracemalloc
        tracemalloc.start()

        start_time = time.time()
        for _ in range(iterations):
            for path in files:
                try:
                    self._engine.scan_file(path)
                except Exception:
                    result.errors += 1
        result.duration_seconds = time.time() - start_time

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        result.peak_memory_mb = peak / (1024 * 1024)

        if result.total_files > 0:
            result.avg_scan_time_ms = (result.duration_seconds * 1000) / result.total_files

        result.compute_derived()
        return result

    def _collect_files(self, directory: str) -> List[str]:
        """Collect all files in a directory tree."""
        files = []
        if not os.path.isdir(directory):
            return files
        for root, _, filenames in os.walk(directory):
            for f in filenames:
                path = os.path.join(root, f)
                if os.path.isfile(path):
                    files.append(path)
        return files

    def save_report(self, result: BenchmarkResult, path: str) -> None:
        """Save benchmark results to JSON."""
        report = result.to_dict()
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info("Benchmark report saved to %s", path)

    def compare_baseline(
        self, current: BenchmarkResult, baseline: BenchmarkResult
    ) -> Dict[str, Dict]:
        """Compare current results against a baseline."""
        comparison = {}
        for metric in ["tpr", "fpr", "precision", "f1_score", "scan_rate", "avg_scan_time_ms"]:
            old_val = getattr(baseline, metric, 0)
            new_val = getattr(current, metric, 0)
            if old_val != 0:
                change_pct = ((new_val - old_val) / abs(old_val)) * 100
            else:
                change_pct = 0.0 if new_val == 0 else 100.0
            comparison[metric] = {
                "baseline": round(old_val, 4),
                "current": round(new_val, 4),
                "change_pct": round(change_pct, 1),
            }
        return comparison
