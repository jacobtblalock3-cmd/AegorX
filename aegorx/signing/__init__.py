"""Cryptographic signing for Defentra signature feeds (Ed25519)."""

from aegorx.signing.feed import (
    FeedError,
    FeedExpired,
    apply_feed,
    check_expiry,
    fetch_feed,
    load_feed,
    sign_document,
    verify_document,
)
from aegorx.signing.keys import (
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_fingerprint,
    trusted_key_paths,
)

__all__ = [
    "FeedError",
    "FeedExpired",
    "apply_feed",
    "check_expiry",
    "fetch_feed",
    "generate_keypair",
    "load_feed",
    "load_private_key",
    "load_public_key",
    "public_key_fingerprint",
    "sign_document",
    "trusted_key_paths",
    "verify_document",
]
