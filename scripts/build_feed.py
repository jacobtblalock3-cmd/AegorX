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


def _rule_entries(globs: Optional[List[str]]) -> List[Dict]:
    """Embed .yar/.yara sources as feed rules with content hashes."""
    import glob as _glob
    import hashlib as _hashlib

    if not globs:
        return []
    rules: Dict[str, Dict] = {}
    for pattern in globs:
        for path in sorted(_glob.glob(pattern)):
            if not os.path.isfile(path) or not path.endswith((".yar", ".yara")):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                source = fh.read()
            name = os.path.splitext(os.path.basename(path))[0]
            digest = _hashlib.sha256(source.encode("utf-8")).hexdigest()
            severity = 5
            for line in source.splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("severity"):
                    _, _, value = stripped.partition("=")
                    try:
                        severity = min(10, max(0, int(value.strip().rstrip("\"'"))))
                    except ValueError:
                        pass
                    break
            rules[digest] = {
                "name": f"file.{name}",
                "source": source,
                "sha256": digest,
                "severity": severity,
            }
    return sorted(rules.values(), key=lambda r: r["name"])


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


def build_feed(
    extra_paths: Optional[List[str]] = None,
    ttl_hours: int = 168,
    rules_globs: Optional[List[str]] = None,
) -> Dict:
    return new_feed(
        collect_entries(extra_paths),
        rules=_rule_entries(rules_globs),
        ttl_hours=ttl_hours,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="output path for the (signed) feed")
    parser.add_argument("--key", default=None, help="Ed25519 private key PEM; omit for unsigned draft")
    parser.add_argument("--extra", action="append", nargs="+", default=None, metavar="JSON", help="curated signatures JSON file(s)/glob(s), repeatable")
    parser.add_argument("--rules-glob", action="append", nargs="+", default=None, metavar="GLOB", dest="rules_glob", help="YARA rule file(s)/glob(s) to embed, repeatable")
    parser.add_argument("--ttl-hours", type=int, default=168, help="feed validity window (default 7 days)")
    args = parser.parse_args()

    extras = [p for group in (args.extra or []) for p in group]
    rule_globs = [g for group in (args.rules_glob or []) for g in group]
    doc = build_feed(extras, ttl_hours=args.ttl_hours, rules_globs=rule_globs)
    if rule_globs:
        print(f"[feed] embedded {len(doc.get('rules', []))} YARA rule(s)")
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
