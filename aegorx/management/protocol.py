"""Message protocol for the DAS management plane.

Every command sent to an agent carries an Ed25519 signature made with the
management server's key; agents refuse to execute anything that does not
verify against the admin public key pinned during pairing. Reports flow the
opposite way, authenticated by a per-agent bearer token issued at enrollment.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Dict, Optional

MAX_MESSAGE_BYTES = 4 * 1024 * 1024
TOKEN_BYTES = 32

ALLOWED_COMMANDS = (
    "ping",
    "status",
    "diag",
    "scan-path",
    "feed-update",
    "check-update",
    "quarantine-list",
    "quarantine-delete",
    "apply-policy",
)


def canonical(payload: Dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def new_token() -> str:
    return secrets.token_hex(TOKEN_BYTES)


def sign_payload(payload: Dict, private_key) -> str:
    digest = private_key.sign(canonical(payload))
    return base64.b64encode(digest).decode("ascii")


def verify_payload(payload: Dict, signature_b64: str, public_key) -> bool:
    try:
        raw = base64.b64decode(signature_b64, validate=True)
        public_key.verify(raw, canonical(payload))
        return True
    except Exception:
        return False


def make_command(command: str, args: Optional[Dict] = None, private_key=None, ttl_seconds: int = 300) -> Dict:
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"command not in allowed set: {command}")
    body = {
        "command_id": secrets.token_hex(8),
        "command": command,
        "args": args or {},
        "issued_utc": time.time(),
        "expires_utc": time.time() + ttl_seconds,
    }
    envelope = {"body": body}
    if private_key is not None:
        envelope["signature"] = sign_payload(body, private_key)
    return envelope


def verify_command(envelope: Dict, public_key, now: Optional[float] = None) -> Dict:
    """Validate signature + freshness; returns the command body or raises."""
    from aegorx.management.protocol_errors import CommandRejected

    if not isinstance(envelope, dict) or "body" not in envelope:
        raise CommandRejected("malformed envelope")
    body = envelope.get("body")
    signature = envelope.get("signature")
    if not isinstance(signature, str) or not isinstance(body, dict):
        raise CommandRejected("missing body or signature")
    if not verify_payload(body, signature, public_key):
        raise CommandRejected("command signature did not verify")
    current = now if now is not None else time.time()
    if not isinstance(body.get("expires_utc"), (int, float)) or body["expires_utc"] < current:
        raise CommandRejected("command expired")
    if body.get("command") not in ALLOWED_COMMANDS:
        raise CommandRejected("unknown command")
    return body


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
