"""Download and install published reference models with integrity verification."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import urllib.request
from typing import Callable, Optional

from aegorx.utils import ensure_dir

logger = logging.getLogger(__name__)

DEFAULT_MODEL_URL = (
    "https://github.com/jacobtblalock3-cmd/AegorX/"
    "releases/download/reference-model/aegorx-ember-reference.lgbm"
)
DEFAULT_INSTALL_NAME = "malware.lgbm"
META_SUFFIX = ".meta.json"
CHUNK = 64 * 1024
MAX_MODEL_BYTES = 512 * 1024 * 1024


def install_dir() -> str:
    override = os.environ.get("AEGORX_MODEL_DIR")
    if override:
        return ensure_dir(override)
    from aegorx.utils import ensure_state_dir

    return ensure_dir(os.path.join(ensure_state_dir(), "models"))


def default_dest() -> str:
    return os.path.join(install_dir(), DEFAULT_INSTALL_NAME)


def _stream_to(resp, dest_path: str) -> int:
    total = 0
    fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MODEL_BYTES:
                raise RuntimeError(f"download exceeds {MAX_MODEL_BYTES} byte limit")
            fh.write(chunk)
    return total


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


class ModelHubError(RuntimeError):
    pass


def _require_https(url: str) -> str:
    if not url.lower().startswith("https://"):
        raise ModelHubError(f"refusing non-HTTPS download URL: {url}")
    return url


def _verify_meta_signature(meta: dict) -> bool:
    """Verify an Ed25519 signature over the canonical metadata payload.

    Returns False when the sidecar is unsigned (integrity still enforced via
    model_sha256); raises ModelHubError when a signature is present but does
    not verify against any trusted key.
    """
    signature = meta.get("signature")
    if not isinstance(signature, str) or not signature:
        return False
    from aegorx.signing.keys import load_public_key, trusted_key_paths

    payload = json.dumps(
        {k: v for k, v in meta.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        raw = base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise ModelHubError(f"invalid model metadata signature encoding: {exc}") from exc
    last_error = "no trusted keys installed"
    for path in trusted_key_paths():
        try:
            load_public_key(path).verify(raw, payload)
            return True
        except Exception as exc:
            last_error = str(exc)
    raise ModelHubError(f"model metadata signature did not verify against trusted keys: {last_error}")


def fetch(
    url: Optional[str] = None,
    dest: Optional[str] = None,
    timeout: int = 120,
    opener: Optional[Callable] = None,
) -> str:
    """Download a model (and its signed .meta.json sidecar) into the install dir.

    Raises RuntimeError on download/checksum/signature failures; returns the
    installed model path.
    """
    url = _require_https(url or DEFAULT_MODEL_URL)
    dest = dest or default_dest()
    opener = opener or urllib.request.urlopen
    parent = os.path.dirname(dest)
    if parent:
        os.makedirs(parent, exist_ok=True)

    # Use unpredictable temp filename to prevent symlink attacks
    import tempfile
    fd, tmp = tempfile.mkstemp(dir=parent or ".", suffix=".tmp")
    os.close(fd)
    print(f"[fetch] {url}")
    try:
        with opener(url, timeout=timeout) as resp:
            size = _stream_to(resp, tmp)
    except Exception as exc:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise RuntimeError(f"download failed: {exc}") from exc
    if size == 0:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise RuntimeError("download failed: empty response")

    meta = {}
    meta_path = dest + META_SUFFIX
    try:
        with opener(_require_https(url + META_SUFFIX), timeout=min(timeout, 30)) as resp:
            meta = json.loads(resp.read().decode("utf-8"))
        if not isinstance(meta, dict):
            meta = {}
        _verify_meta_signature(meta)
    except ModelHubError:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    except Exception:
        meta = {}

    expected = meta.get("model_sha256")
    if expected and _sha256(tmp) != expected:
        os.remove(tmp)
        if os.path.exists(meta_path):
            os.remove(meta_path)
        raise RuntimeError("checksum mismatch: downloaded model does not match published sha256")

    os.replace(tmp, dest)
    os.chmod(dest, 0o644)
    if meta:
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
        print(f"[fetch] metadata: source={meta.get('source')} auc={meta.get('test_auc')}")
    elif os.path.exists(meta_path):
        os.remove(meta_path)
    print(f"[fetch] installed {dest} ({size} bytes)")
    return dest


def installed_models() -> list:
    d = install_dir()
    if not os.path.isdir(d):
        return []
    return sorted(
        os.path.join(d, f) for f in os.listdir(d) if f.endswith(".lgbm") and not f.endswith(META_SUFFIX)
    )
