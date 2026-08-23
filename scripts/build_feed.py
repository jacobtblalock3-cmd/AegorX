#!/usr/bin/env python3
"""Build and sign the official Defentra signature feed.

Sources merged into the feed (later files win on sha256 conflicts):

  * built-in seed signatures shipped with the engine
  * curated JSON lists passed via --extra ({"signatures": [...]} each)

Example:

    python scripts/build_feed.py \
        --extra feeds/community.json \
        --key ~/signing/signing_private.pem \
        --out artifacts/signatures.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from defentra.signatures.db import SignatureDB
from defentra.signing.feed import new_feed, save_feed, sign_document

FEED_ENTRY_FIELDS = ("sha256", "md5", "sha1", "name", "family", "severity")


def _db_entries() -> List[Dict]:
    """Builtin seeds via a throwaway in-memory database."""
    db = SignatureDB(":memory:")
    rows = []
    with db._lock:
        raw = db.conn.execute("SELECT * FROM hash_signatures").fetchall()
    for row in raw:
        record = dict(row)
        rows.append({k: record.get(k, "") for k in FEED_ENTRY_FIELDS})
    return rows


def _file_entries(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("signatures", [])
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a signatures list")
    return [rec for rec in data if isinstance(rec, dict)]


def collect_entries(extra_paths: Optional[List[str]] = None) -> List[Dict]:
    """Merge sources, keeping the last entry per unique sha256."""
    import glob as _glob

    expanded: List[str] = []
    for pattern in extra_paths or []:
        matched = sorted(_glob.glob(pattern))
        if matched:
            expanded.extend(matched)
        else:
            expanded.append(pattern)
    merged: Dict[str, Dict] = {}
    for source in [_db_entries()] + [_file_entries(p) for p in expanded]:
        for rec in source:
            sha256 = str(rec.get("sha256", "")).lower().strip()
            if len(sha256) != 64:
                continue
            entry = {k: rec.get(k, "" if k != "severity" else 8) for k in FEED_ENTRY_FIELDS}
            entry["sha256"] = sha256
            merged[sha256] = entry
    return sorted(merged.values(), key=lambda e: e["sha256"])


def build_feed(extra_paths: Optional[List[str]] = None, ttl_hours: int = 168) -> Dict:
    return new_feed(collect_entries(extra_paths), ttl_hours=ttl_hours)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="output path for the (signed) feed")
    parser.add_argument("--key", default=None, help="Ed25519 private key PEM; omit for unsigned draft")
    parser.add_argument("--extra", action="append", default=None, help="curated signatures JSON (repeatable)")
    parser.add_argument("--ttl-hours", type=int, default=168, help="feed validity window (default 7 days)")
    args = parser.parse_args()

    doc = build_feed(args.extra, ttl_hours=args.ttl_hours)
    if args.key:
        doc = sign_document(doc, args.key)
        print(f"[feed] signed with {args.key}")
    save_feed(doc, args.out)
    digest = hashlib.sha256(open(args.out, "rb").read()).hexdigest()
    print(
        f"[feed] wrote {args.out}: {len(doc['signatures'])} signature(s), "
        f"expires {doc['expires_utc']}, sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
