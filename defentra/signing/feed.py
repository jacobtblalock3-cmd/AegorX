"""Signed signature feeds: create, verify, and apply threat-intel bundles.

A feed is a JSON document:

    {
      "format": "defentra-signature-feed",
      "feed_version": 1,
      "generated_utc": "...",
      "expires_utc": "...",
      "signatures": [{"sha256": ..., "name": ...}, ...],
      "signature": "<base64 Ed25519 sig over the canonical payload>"
    }

The signature covers every field except "signature" itself, serialized as
sorted-key compact JSON, so any tampering invalidates it.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional

from defentra.signing.keys import (
    load_private_key,
    public_key_fingerprint,
    trusted_key_paths,
)
from defentra.utils import state_dir

FEED_FORMAT = "defentra-signature-feed"
FEED_VERSION = 1
MAX_FEED_BYTES = 32 * 1024 * 1024
DEFAULT_FEED_URL = (
    "https://github.com/jacobtblalock3-cmd/defentra/"
    "releases/download/signature-feed/signatures.json"
)


class FeedError(RuntimeError):
    pass


class FeedExpired(FeedError):
    pass


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise FeedError(f"invalid UTC timestamp: {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def canonical_payload(doc: Dict) -> bytes:
    payload = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_canonical(doc) -> bytes:
    try:
        return canonical_payload(doc)
    except (TypeError, ValueError) as exc:
        raise FeedError(f"feed document is not JSON-serializable: {exc}") from exc


def new_feed(signatures: List[Dict], ttl_hours: int = 720) -> Dict:
    """Build an unsigned feed document from raw signature entries."""
    from datetime import timedelta

    generated = datetime.now(timezone.utc)
    return {
        "format": FEED_FORMAT,
        "feed_version": FEED_VERSION,
        "generated_utc": generated.isoformat(timespec="seconds"),
        "expires_utc": (generated + timedelta(hours=ttl_hours)).isoformat(timespec="seconds"),
        "signatures": signatures,
    }


def sign_document(doc: Dict, private_key_path: str) -> Dict:
    key = load_private_key(private_key_path)
    signed = dict(doc)
    signed.pop("signature", None)
    digest = key.sign(canonical_payload(signed))
    signed["signature"] = base64.b64encode(digest).decode("ascii")
    return signed


def verify_document(doc: Dict, extra_trusted_keys: Optional[List[str]] = None) -> str:
    """Verify against all trusted keys; returns the fingerprint that matched."""
    if not isinstance(doc, dict) or doc.get("format") != FEED_FORMAT:
        raise FeedError("not a defentra signature feed (bad 'format')")
    try:
        version = int(doc.get("feed_version", 0))
    except (TypeError, ValueError):
        version = -1
    if version != FEED_VERSION:
        raise FeedError(f"unsupported feed_version: {doc.get('feed_version')}")
    b64_sig = doc.get("signature")
    if not b64_sig or not isinstance(b64_sig, str):
        raise FeedError("feed has no signature")
    try:
        sig = base64.b64decode(b64_sig, validate=True)
    except (binascii.Error, ValueError):
        raise FeedError("signature is not valid base64")

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    candidates = list(trusted_key_paths())
    for extra in extra_trusted_keys or []:
        candidates.append(extra)
    if not candidates:
        raise FeedError("no trusted public keys installed")

    payload = _safe_canonical(doc)
    errors: List[str] = []
    for path in candidates:
        try:
            key = _load_pub(path)
            key.verify(sig, payload)
            return public_key_fingerprint(key)
        except (InvalidSignature, ValueError, OSError) as exc:
            errors.append(f"{os.path.basename(path)}: {exc}")
    raise FeedError(
        "signature did not verify against any trusted key (" + "; ".join(errors) + ")"
    )


def _load_pub(path: str) -> Ed25519PublicKey:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    with open(path, "rb") as fh:
        key = serialization.load_pem_public_key(fh.read())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def check_expiry(doc: Dict, now: Optional[datetime] = None, allow_expired: bool = False) -> None:
    expires_raw = doc.get("expires_utc")
    if not expires_raw:
        return
    expires = parse_utc(expires_raw)
    current = now or datetime.now(timezone.utc)
    if expires < current and not allow_expired:
        raise FeedExpired(f"feed expired at {doc['expires_utc']}")


def load_feed(path: str) -> Dict:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read(MAX_FEED_BYTES + 1)
    except OSError as exc:
        raise FeedError(f"cannot read feed: {exc}")
    if len(data) > MAX_FEED_BYTES:
        raise FeedError("feed exceeds maximum size")
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        raise FeedError(f"feed is not valid JSON: {exc}")


def save_feed(doc: Dict, path: str) -> str:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    return path


def fetch_feed(url: str, opener=None) -> Dict:
    if not url.lower().startswith("https://"):
        raise FeedError(f"refusing non-HTTPS feed URL: {url}")
    opener = opener or urllib.request.urlopen
    try:
        with opener(url, timeout=60) as resp:
            data = resp.read(MAX_FEED_BYTES + 1)
    except Exception as exc:
        raise FeedError(f"download failed: {exc}")
    if len(data) > MAX_FEED_BYTES:
        raise FeedError("feed exceeds maximum size")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FeedError(f"downloaded feed is not valid JSON: {exc}")


def replay_state_path() -> str:
    return os.path.join(state_dir(), "feed_state.json")


def _load_replay_state() -> Dict:
    try:
        with open(replay_state_path(), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"last_generated_utc": ""}


def check_replay(doc: Dict, force: bool = False) -> bool:
    """True if this feed is newer than anything previously applied."""
    generated = parse_utc(doc["generated_utc"])
    last_raw = _load_replay_state().get("last_generated_utc", "")
    if not last_raw or force:
        return True
    return generated > parse_utc(last_raw)


def record_applied(doc: Dict) -> None:
    generated = parse_utc(doc["generated_utc"])
    state = _load_replay_state()
    last_raw = state.get("last_generated_utc", "")
    if last_raw:
        last = parse_utc(last_raw)
        if generated <= last:
            return
    state["last_generated_utc"] = doc["generated_utc"]
    os.makedirs(state_dir(), exist_ok=True)
    tmp = replay_state_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, replay_state_path())


def apply_feed(db, doc: Dict) -> int:
    """Insert verified feed signatures into the database; returns added count."""
    entries = doc.get("signatures")
    if not isinstance(entries, list):
        raise FeedError("feed has no signatures array")
    added = 0
    for rec in entries:
        if not isinstance(rec, dict) or not rec.get("sha256") or not rec.get("name"):
            continue
        added += db.add(
            sha256=str(rec["sha256"]),
            name=str(rec["name"]),
            md5=str(rec.get("md5", "") or ""),
            sha1=str(rec.get("sha1", "") or ""),
            family=str(rec.get("family", "") or ""),
            severity=int(rec.get("severity", 8)),
            source="feed",
        )
    return added
