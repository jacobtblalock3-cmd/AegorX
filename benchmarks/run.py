#!/usr/bin/env python3
"""Run AegorX benchmark suite.

Usage:
    python -m benchmarks.run [--data-dir DIR] [--output FILE] [--iterations N]

If --data-dir is provided, runs detection benchmark against
benign/ and malicious/ subdirectories.

Otherwise, runs a performance benchmark using available test fixtures.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegorx.engine import ScanEngine
from benchmarks.suite import BenchmarkSuite


def generate_test_files(tmpdir: str) -> tuple:
    """Generate simple test files for benchmarking."""
    benign_dir = os.path.join(tmpdir, "benign")
    malicious_dir = os.path.join(tmpdir, "malicious")
    os.makedirs(benign_dir, exist_ok=True)
    os.makedirs(malicious_dir, exist_ok=True)

    # Create benign test files
    for i in range(100):
        path = os.path.join(benign_dir, f"benign_{i}.txt")
        with open(path, "w") as f:
            f.write(f"This is test file {i}.\n" * 100)

    # Create files with suspicious patterns (for heuristic testing)
    suspicious_content = b"\x00" * 1024 + b"VirtualAlloc" + b"\x00" * 1024
    for i in range(50):
        path = os.path.join(malicious_dir, f"suspicious_{i}.bin")
        with open(path, "wb") as f:
            f.write(suspicious_content)

    return benign_dir, malicious_dir


def main():
    parser = argparse.ArgumentParser(description="AegorX Benchmark Suite")
    parser.add_argument("--data-dir", help="Directory with benign/ and malicious/ subdirs")
    parser.add_argument("--output", default="benchmark_report.json", help="Output report path")
    parser.add_argument("--iterations", type=int, default=3, help="Performance test iterations")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    print("Initializing AegorX scan engine...")
    engine = ScanEngine(enable_ml=True)
    caps = engine.capabilities
    print(f"  Signatures: {caps['signature_db']}")
    print(f"  YARA rules: {caps['yara_rules']}")
    print(f"  ML model:   {'loaded' if caps['ml_model'] else 'not available'}")
    print(f"  Hash backend: {caps['hash_backend']}")

    suite = BenchmarkSuite(engine, data_dir=args.data_dir)

    # Use provided data or generate test files
    if args.data_dir:
        print(f"\nRunning detection benchmark on {args.data_dir}...")
        result = suite.run_detection_benchmark(name="detection_benchmark")
    else:
        print("\nGenerating test files for benchmark...")
        tmpdir = tempfile.mkdtemp(prefix="aegorx_bench_")
        benign_dir, malicious_dir = generate_test_files(tmpdir)
        suite = BenchmarkSuite(engine)
        result = suite.run_detection_benchmark(
            benign_files=[os.path.join(benign_dir, f) for f in os.listdir(benign_dir)],
            malicious_files=[os.path.join(malicious_dir, f) for f in os.listdir(malicious_dir)],
            name="detection_benchmark",
        )

    print("\n" + "=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)
    print(result.summary())

    # Performance benchmark
    print(f"\nRunning performance benchmark ({args.iterations} iterations)...")
    perf_result = suite.run_performance_benchmark(iterations=args.iterations)
    print(f"\nScan throughput: {perf_result.scan_rate:.0f} files/sec")
    print(f"Avg scan time:   {perf_result.avg_scan_time_ms:.1f} ms")
    print(f"Peak memory:     {perf_result.peak_memory_mb:.1f} MB")

    # Save report
    report = {
        "detection": result.to_dict(),
        "performance": perf_result.to_dict(),
        "engine_capabilities": caps,
    }
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()
