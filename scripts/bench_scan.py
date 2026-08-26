#!/usr/bin/env python3
"""Scan-throughput benchmark for the Defentra engine.

Builds a deterministic synthetic corpus in a temp directory, scans it with a
default-configuration engine, and reports wall-clock throughput:

    python scripts/bench_scan.py [--files 2000] [--size-kb 32] [--rounds 3]

Use it to sanity-check performance-affecting changes locally; numbers are
machine-dependent by nature and are not asserted anywhere.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    "!$H+H*"
)


def build_corpus(root: str, n_files: int, size_kb: int, seed: int = 0x9E3779B9) -> int:
    """Deterministic pseudo-random corpus; returns total bytes written."""
    state = seed
    total = 0
    for i in range(n_files):
        subdir = os.path.join(root, f"dir{i % 20}")
        os.makedirs(subdir, exist_ok=True)
        path = os.path.join(subdir, f"file_{i:05d}.bin")
        # xorshift for cheap reproducible filler
        chunks = []
        remaining = size_kb * 1024
        while remaining > 0:
            state ^= (state << 13) & 0xFFFFFFFF
            state ^= state >> 17
            state ^= (state << 5) & 0xFFFFFFFF
            chunk_len = min(remaining, 4096)
            chunks.append((state.to_bytes(4, "little") * (chunk_len // 4 or 1))[:chunk_len])
            remaining -= chunk_len
        payload = b"".join(chunks)
        if i % 500 == 0:
            payload = payload[:-68] + EICAR.encode()  # sprinkle known threats
        with open(path, "wb") as fh:
            fh.write(payload)
        total += len(payload)
    return total


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=1000, help="corpus file count")
    parser.add_argument("--size-kb", type=int, default=16, help="per-file size (KB)")
    parser.add_argument("--rounds", type=int, default=3, help="scan repetitions to average")
    args = parser.parse_args(argv)

    from defentra import __version__
    from defentra.engine import ScanEngine

    root = tempfile.mkdtemp(prefix="defentra-bench-")
    try:
        total_bytes = build_corpus(root, args.files, args.size_kb)
        print(f"corpus: {args.files} files x {args.size_kb}KB = {total_bytes / 1e6:.1f} MB")

        timings = []
        counts = []
        for round_index in range(args.rounds):
            engine = ScanEngine(enable_ml=False)
            started = time.perf_counter()
            results = engine.scan_target(root)
            elapsed = time.perf_counter() - started
            timings.append(elapsed)
            counts.append(len(results))
            print(
                f"round {round_index + 1}: {len(results)} files in {elapsed:.2f}s"
                f" -> {len(results) / elapsed:.0f} files/s,"
                f" {total_bytes / 1e6 / elapsed:.1f} MB/s"
            )

        best = min(timings)
        threats = sum(
            1 for r in results if r.verdict == "malicious"
        )
        print(
            f"\nbest round: {args.files / best:.0f} files/s | "
            f"engine version {__version__} | malicious found: {threats}"
        )
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
