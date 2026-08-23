#!/usr/bin/env python3
"""Ingest current malware IOC hashes from public abuse.ch feeds.

Maintains feeds/<store>.json in the standard curated-feed schema so
scripts/build_feed.py picks it up automatically. Designed for unattended CI:

    python scripts/fetch_intel.py --store feeds/malwarebazaar.json

Sources:
  * malwarebazaar - recent submissions with family attribution
                    (optional free Auth-Key via --auth-key or $MALWAREBAZAAR_KEY)
  * urlhaus       - recent malware payloads (no auth)

Failures degrade gracefully: a source that errors is skipped with a warning
and the previous store is kept intact, so transient API outages never break
the daily feed build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/payloads/recent/"
DEFAULT_STORE = "feeds/malwarebazaar.json"
ENTRY_FIELDS = ("sha256", "md5", "sha1", "name", "family", "severity", "first_seen")


class IntelSourceError(RuntimeError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_field(rec: dict, *names: str) -> str:
    for name in names:
        value = rec.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _entry(
    sha256: str,
    md5: str,
    sha1: str,
    name: str,
    family: str,
    first_seen: str = "",
    severity: int = 8,
) -> Dict:
    entry = {
        "sha256": sha256,
        "md5": md5,
        "sha1": sha1,
        "name": name,
        "family": family,
        "severity": int(severity),
        "first_seen": first_seen,
    }
    return {k: v for k, v in entry.items() if v not in ("", None)}


def _require_object(payload) -> dict:
    if not isinstance(payload, dict):
        raise IntelSourceError("unexpected non-object API response")
    return payload


def _seen_date(value) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text[:10]


def parse_malwarebazaar(payload: dict) -> List[Dict]:
    """Parse a MalwareBazaar get_recent response into feed entries."""
    data = _require_object(payload)
    status = data.get("query_status")
    if status not in (None, "ok"):
        hint = (
            "register a free abuse.ch key and set MALWAREBAZAAR_KEY"
            if "auth" in str(status).lower()
            else ""
        )
        raise IntelSourceError(f"malwarebazaar query_status={status}" + (f" ({hint})" if hint else ""))
    entries: List[Dict] = []
    for rec in data.get("data") or []:
        if not isinstance(rec, dict):
            continue
        sha256 = _hash_field(rec, "sha256", "sha256_hash")
        if len(sha256) != 64:
            continue
        family = str(rec.get("signature") or "").strip()
        entries.append(
            _entry(
                sha256=sha256,
                md5=_hash_field(rec, "md5", "md5_hash"),
                sha1=_hash_field(rec, "sha1", "sha1_hash"),
                name=f"MB.{family}" if family else "MB.Unknown",
                family=family.lower(),
                first_seen=_seen_date(rec.get("first_seen_utc") or rec.get("first_seen")),
            )
        )
    return entries


def parse_urlhaus(payload: dict) -> List[Dict]:
    """Parse a URLhaus recent-payloads response into feed entries."""
    data = _require_object(payload)
    entries: List[Dict] = []
    for rec in data.get("payloads") or []:
        if not isinstance(rec, dict):
            continue
        sha256 = _hash_field(rec, "sha256", "sha256_hash")
        if len(sha256) != 64:
            continue
        family = str(rec.get("signature") or "").strip()
        if not family:
            tags = rec.get("tags")
            if isinstance(tags, list) and tags:
                family = str(tags[0]).strip()
        entries.append(
            _entry(
                sha256=sha256,
                md5=_hash_field(rec, "md5", "md5_hash"),
                sha1=_hash_field(rec, "sha1", "sha1_hash"),
                name=f"UH.{family}" if family else "UH.Malware",
                family=family.lower(),
                first_seen=_seen_date(rec.get("first_seen")),
            )
        )
    return entries


def http_post_json(url: str, fields: Dict[str, str], opener=None) -> dict:
    if not url.lower().startswith("https://"):
        raise IntelSourceError(f"refusing non-HTTPS intel URL: {url}")
    opener = opener or urllib.request.urlopen
    body = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with opener(request, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        raise IntelSourceError(f"{url}: {exc}")


def fetch_malwarebazaar(auth_key: str = "", opener=None) -> List[Dict]:
    fields: Dict[str, str] = {"query": "get_recent", "selector": "time"}
    if auth_key:
        fields["Auth-Key"] = auth_key
    return parse_malwarebazaar(http_post_json(MALWAREBAZAAR_URL, fields, opener=opener))


def fetch_urlhaus(limit: int = 1000, opener=None) -> List[Dict]:
    payload = http_post_json(URLHAUS_RECENT_URL, {"limit": str(min(limit, 1000))}, opener=opener)
    return parse_urlhaus(payload)


def load_store(path: str) -> Dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("signatures"), list):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"signatures": []}


def save_store(path: str, store: Dict) -> str:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=1)
        fh.write("\n")
    os.replace(tmp, path)
    return path


def _key(entry: Dict) -> str:
    return str(entry.get("sha256", "")).lower()


def merge_entries(existing: List[Dict], incoming: List[Dict]) -> Tuple[List[Dict], int]:
    """Union by sha256; incoming fills gaps, never clobbers richer existing fields."""
    merged: Dict[str, Dict] = {_key(e): dict(e) for e in existing}
    added = 0
    for entry in incoming:
        k = _key(entry)
        if not k:
            continue
        if k not in merged:
            added += 1
            merged[k] = entry
        else:
            current = merged[k]
            for field in ENTRY_FIELDS:
                if not current.get(field) and entry.get(field):
                    current[field] = entry[field]
    return sorted(merged.values(), key=lambda e: e["sha256"]), added


def prune_entries(entries: List[Dict], keep_days: int, now: Optional[datetime] = None) -> Tuple[List[Dict], int]:
    cutoff = (now or _utc_now()).date() - timedelta(days=keep_days)
    kept: List[Dict] = []
    dropped = 0
    for entry in entries:
        seen = str(entry.get("first_seen") or "")
        try:
            seen_date = datetime.strptime(seen[:10], "%Y-%m-%d").date() if seen else None
        except ValueError:
            seen_date = None
        if seen_date is None or seen_date >= cutoff:
            kept.append(entry)
        else:
            dropped += 1
    return kept, dropped


def run(args, opener: Optional[Callable] = None) -> int:
    args.opener = opener
    auth_key = args.auth_key or os.environ.get("MALWAREBAZAAR_KEY", "")
    sources = [s.strip().lower() for s in args.source.split(",") if s.strip()]
    store = load_store(args.store)
    failures: List[str] = []

    for source in sources:
        try:
            if source == "malwarebazaar":
                if args.mb_response:
                    with open(args.mb_response, "r", encoding="utf-8") as fh:
                        entries = parse_malwarebazaar(json.load(fh))
                else:
                    entries = fetch_malwarebazaar(auth_key=auth_key, opener=args.opener)
            elif source == "urlhaus":
                if args.uh_response:
                    with open(args.uh_response, "r", encoding="utf-8") as fh:
                        entries = parse_urlhaus(json.load(fh))
                else:
                    entries = fetch_urlhaus(opener=args.opener)
            else:
                print(f"[intel] unknown source '{source}', skipping", file=sys.stderr)
                continue
            merged, added = merge_entries(store["signatures"], entries)
            store["signatures"] = merged
            print(f"[intel] {source}: fetched {len(entries)}, new {added}, total {len(merged)}")
        except (IntelSourceError, OSError) as exc:
            failures.append(f"{source}: {exc}")
            print(f"[intel] WARNING {source}: {exc}", file=sys.stderr)

    pruned, dropped = prune_entries(store["signatures"], args.prune_days)
    store["signatures"] = pruned
    save_store(args.store, store)
    digest = hashlib.sha256(open(args.store, "rb").read()).hexdigest()[:16]
    print(
        f"[intel] store {args.store}: {len(store['signatures'])} entries "
        f"(pruned {dropped}) sha256:{digest}"
    )
    if failures and not store["signatures"]:
        print("[intel] all sources failed and store is empty", file=sys.stderr)
        return 3
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", default=DEFAULT_STORE, help="curated store JSON to create/update")
    parser.add_argument("--source", default="malwarebazaar,urlhaus", help="comma-separated sources")
    parser.add_argument("--prune-days", type=int, default=90, help="drop entries first seen before N days ago")
    parser.add_argument("--auth-key", default=None, help="MalwareBazaar Auth-Key (else $MALWAREBAZAAR_KEY)")
    parser.add_argument("--mb-response", default=None, help="offline MalwareBazaar response JSON (testing)")
    parser.add_argument("--uh-response", default=None, help="offline URLhaus response JSON (testing)")
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
