"""Download and install published reference models with integrity verification."""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from typing import Callable, Optional

from defentra.utils import ensure_dir, state_dir

DEFAULT_MODEL_URL = (
    "https://github.com/defentra/defentra/releases/latest/download/defentra-ember-reference.lgbm"
)
DEFAULT_INSTALL_NAME = "malware.lgbm"
META_SUFFIX = ".meta.json"
CHUNK = 64 * 1024


def install_dir() -> str:
    override = os.environ.get("DEFENTRA_MODEL_DIR")
    if override:
        return ensure_dir(override)
    return ensure_dir(os.path.join(state_dir(), "models"))


def default_dest() -> str:
    return os.path.join(install_dir(), DEFAULT_INSTALL_NAME)


def _stream_to(resp, dest_path: str) -> int:
    total = 0
    with open(dest_path, "wb") as fh:
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            fh.write(chunk)
            total += len(chunk)
    return total


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(
    url: Optional[str] = None,
    dest: Optional[str] = None,
    timeout: int = 120,
    opener: Optional[Callable] = None,
) -> str:
    """Download a model (and its .meta.json sidecar) into the install dir.

    Raises RuntimeError on checksum mismatch; returns the installed model path.
    """
    url = url or DEFAULT_MODEL_URL
    dest = dest or default_dest()
    opener = opener or urllib.request.urlopen
    parent = os.path.dirname(dest)
    if parent:
        os.makedirs(parent, exist_ok=True)

    tmp = dest + ".tmp"
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
        with opener(url + META_SUFFIX, timeout=min(timeout, 30)) as resp:
            meta = json.loads(resp.read().decode("utf-8"))
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
