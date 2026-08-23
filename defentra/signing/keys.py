"""Ed25519 key generation, loading, and trust-store management."""

from __future__ import annotations

import hashlib
import glob
import os
from typing import List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from defentra.utils import ensure_dir, state_dir

PACKAGE_TRUST_DIR = os.path.join(os.path.dirname(__file__), "trusted_keys")
USER_TRUST_SUBDIR = "keys"
PRIVATE_PEM_NAME = "signing_private.pem"
PUBLIC_PEM_NAME = "signing_public.pem"


def default_signing_dir() -> str:
    return ensure_dir(os.path.join(state_dir(), "signing"))


def generate_keypair(out_dir: str) -> Tuple[str, str]:
    """Create an Ed25519 keypair; returns (private_path, public_path).

    The private key is written with 0600 permissions and must never leave
    the signing host.
    """
    ensure_dir(out_dir)
    key = Ed25519PrivateKey.generate()
    private_path = os.path.join(out_dir, PRIVATE_PEM_NAME)
    public_path = os.path.join(out_dir, PUBLIC_PEM_NAME)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_pem)
    with open(public_path, "wb") as fh:
        fh.write(public_pem)
    return private_path, public_path


def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_public_key(fh.read())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def user_trust_dir() -> str:
    return os.path.join(state_dir(), USER_TRUST_SUBDIR)


def trusted_key_paths() -> List[str]:
    """All trusted public keys: bundled package roots + user-installed ones."""
    paths: List[str] = []
    seen = set()
    for directory in (PACKAGE_TRUST_DIR, user_trust_dir()):
        for path in sorted(glob.glob(os.path.join(directory, "*.pub"))):
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                paths.append(path)
    return paths


def trust_public_key(source_path: str) -> str:
    """Copy a public key into the user trust store; returns installed path."""
    load_public_key(source_path)
    dest_dir = ensure_dir(user_trust_dir())
    dest = os.path.join(dest_dir, os.path.basename(source_path))
    if not dest.endswith(".pub"):
        dest += ".pub"
    with open(source_path, "rb") as src, open(dest, "wb") as out:
        out.write(src.read())
    os.chmod(dest, 0o644)
    return dest


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    """Short SHA256 fingerprint of the DER-encoded public key."""
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]
