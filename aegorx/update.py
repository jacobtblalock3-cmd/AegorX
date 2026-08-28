"""Self-update channel: signed release manifests, verified artifact install.

The Release workflow publishes an Ed25519-signed ``update-manifest.json``
asset on every GitHub Release. Clients verify the manifest against the same
pinned root keys used for signature feeds and ML models, then download the
artifact and enforce the manifest's sha256 + size before handing off to the
system installer.

Trust properties:
  * provenance: Ed25519 signature over the canonical JSON payload, checked
    against package-pinned keys (never just transport security)
  * integrity: artifact sha256/size must match the signed manifest exactly
  * transport: HTTPS-only downloads with hard byte caps
  * rollback safety: applying a version older than the running one requires
    an explicit --force
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Dict, List, Optional, Tuple

from aegorx.signing.feed import canonical_payload, check_expiry
from aegorx.signing.keys import public_key_fingerprint, trusted_key_paths

UPDATE_FORMAT = "aegorx-update-manifest"
MANIFEST_VERSION = 1
DEFAULT_MANIFEST_URL = (
    "https://github.com/jacobtblalock3-cmd/AegorX/"
    "releases/latest/download/update-manifest.json"
)
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
DOWNLOAD_CHUNK = 64 * 1024

ARTIFACT_SUFFIXES = {
    "deb": ".deb",
    "wheel": ".whl",
    "sdist": ".tar.gz",
}


class UpdateError(RuntimeError):
    pass


# ------------------------------------------------------------------ manifests


def build_manifest(
    version: str,
    artifacts: List[Dict],
    ttl_hours: int = 336,
) -> Dict:
    """Build an unsigned update manifest from artifact descriptors.

    Each descriptor needs url/sha256/size; `kind` is derived from the URL
    suffix when absent.
    """
    from datetime import datetime, timedelta, timezone

    entries: Dict[str, Dict] = {}
    for art in artifacts:
        entry = dict(art)
        url = str(entry.get("url") or "")
        kind = entry.get("kind")
        if not kind:
            for name, suffix in ARTIFACT_SUFFIXES.items():
                if url.lower().endswith(suffix):
                    kind = name
                    break
        if kind not in ARTIFACT_SUFFIXES:
            raise UpdateError(f"cannot determine artifact kind for {url!r}")
        for field in ("sha256", "size"):
            if not entry.get(field):
                raise UpdateError(f"artifact {kind} missing {field}")
        entries[kind] = {
            "url": url,
            "sha256": str(entry["sha256"]).lower(),
            "size": int(entry["size"]),
        }
    if not entries:
        raise UpdateError("manifest needs at least one artifact")

    generated = datetime.now(timezone.utc)
    return {
        "format": UPDATE_FORMAT,
        "manifest_version": MANIFEST_VERSION,
        "version": version,
        "generated_utc": generated.isoformat(timespec="seconds"),
        "expires_utc": (generated + timedelta(hours=ttl_hours)).isoformat(timespec="seconds"),
        "artifacts": entries,
    }


def fetch_manifest(url: Optional[str] = None, opener=None) -> Dict:
    from aegorx.signing.feed import FeedError, fetch_feed

    try:
        doc = fetch_feed(url or DEFAULT_MANIFEST_URL, opener=opener)
    except FeedError as exc:
        raise UpdateError(f"manifest download failed: {exc}") from exc
    return doc


def verify_manifest(doc: Dict, extra_trusted_keys: Optional[List[str]] = None) -> str:
    """Verify format and Ed25519 provenance; returns the fingerprint that matched."""
    if not isinstance(doc, dict) or doc.get("format") != UPDATE_FORMAT:
        raise UpdateError("not an aegorx update manifest (bad 'format')")
    if doc.get("manifest_version") != MANIFEST_VERSION:
        raise UpdateError(f"unsupported manifest_version: {doc.get('manifest_version')}")
    artifacts = doc.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise UpdateError("manifest has no artifacts")
    for kind, entry in artifacts.items():
        if kind not in ARTIFACT_SUFFIXES or not isinstance(entry, dict):
            raise UpdateError(f"bad artifact entry: {kind}")
        if not isinstance(entry.get("url"), str) or not entry["url"].startswith("https://"):
            raise UpdateError(f"artifact {kind}: refusing non-HTTPS url")
        sha = entry.get("sha256")
        if (
            not isinstance(sha, str)
            or len(sha) != 64
            or any(c not in "0123456789abcdef" for c in sha.lower())
        ):
            raise UpdateError(f"artifact {kind}: bad sha256")
        try:
            if int(entry.get("size", -1)) < 0:
                raise ValueError
        except (TypeError, ValueError):
            raise UpdateError(f"artifact {kind}: bad size")

    b64_sig = doc.get("signature")
    if not b64_sig or not isinstance(b64_sig, str):
        raise UpdateError("manifest has no signature")
    try:
        sig = base64.b64decode(b64_sig, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise UpdateError(f"signature is not valid base64: {exc}") from exc

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    candidates = list(trusted_key_paths())
    for extra in extra_trusted_keys or []:
        candidates.append(extra)
    if not candidates:
        raise UpdateError("no trusted public keys installed")

    payload = canonical_payload(doc)
    errors: List[str] = []
    for path in candidates:
        try:
            from aegorx.signing.keys import load_public_key

            key = load_public_key(path)
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("not an Ed25519 public key")
            key.verify(sig, payload)
            return public_key_fingerprint(key)
        except (InvalidSignature, ValueError, OSError) as exc:
            errors.append(f"{os.path.basename(path)}: {exc}")
    raise UpdateError(
        "manifest signature did not verify against any trusted key (" + "; ".join(errors) + ")"
    )


def parse_version(version: str) -> Tuple[int, ...]:
    """'v1.2.3rc1' -> (1, 2, 3); non-numeric tails are ignored."""
    text = str(version).strip().lstrip("vV")
    parts: List[int] = []
    for chunk in text.split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
    if not parts:
        raise UpdateError(f"unparseable version: {version!r}")
    return tuple(parts)


def check(
    current: Optional[str] = None,
    url: Optional[str] = None,
    opener: Optional[Callable] = None,
    allow_expired: bool = False,
) -> Dict:
    """Fetch + verify the latest release manifest; report whether it is newer."""
    if current is None:
        from aegorx import __version__

        current = __version__
    doc = fetch_manifest(url=url, opener=opener)
    fingerprint = verify_manifest(doc)
    from aegorx.signing.feed import FeedError

    try:
        check_expiry(doc, allow_expired=allow_expired)
    except FeedError as exc:
        raise UpdateError(f"{exc} (use --allow-expired to override)") from exc
    available = str(doc.get("version", ""))
    try:
        newer = parse_version(available) > parse_version(current)
    except UpdateError:
        newer = False
    return {
        "current": current,
        "available": available,
        "update_available": newer,
        "key_fingerprint": fingerprint,
        "generated_utc": doc.get("generated_utc", ""),
        "expires_utc": doc.get("expires_utc", ""),
        "artifacts": doc.get("artifacts", {}),
        "_doc": doc,
    }


# ------------------------------------------------------------------ artifacts


def _require_https(url: str) -> str:
    if not url.lower().startswith("https://"):
        raise UpdateError(f"refusing non-HTTPS download URL: {url}")
    return url


def download_artifact(entry: Dict, dest_dir: str, opener=None) -> str:
    """Stream the artifact into dest_dir, enforcing signed size + sha256."""
    url = _require_https(str(entry.get("url") or ""))
    expected_sha = str(entry.get("sha256") or "").lower()
    expected_size = int(entry.get("size") or -1)
    if len(expected_sha) != 64 or expected_size < 0:
        raise UpdateError("artifact entry lacks usable sha256/size")

    basename = os.path.basename(url.split("?")[0])
    if not any(basename.lower().endswith(s) for s in ARTIFACT_SUFFIXES.values()):
        raise UpdateError(f"artifact filename has no known suffix: {basename!r}")
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, basename)

    if opener is None:
        import urllib.request

        opener = urllib.request.urlopen
    digest = hashlib.sha256()
    written = 0
    try:
        with opener(url, timeout=300) as resp, open(dest_path, "wb") as fh:
            while True:
                chunk = resp.read(DOWNLOAD_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_ARTIFACT_BYTES:
                    raise UpdateError("artifact exceeds maximum size")
                digest.update(chunk)
                fh.write(chunk)
    except UpdateError:
        raise
    except Exception as exc:
        raise UpdateError(f"artifact download failed: {exc}") from exc

    if written != expected_size:
        raise UpdateError(f"artifact size mismatch: got {written}, manifest says {expected_size}")
    actual = digest.hexdigest()
    if actual != expected_sha:
        raise UpdateError(f"artifact checksum mismatch: got {actual}, manifest says {expected_sha}")
    return dest_path


def _installer_for(artifact_path: str) -> Optional[List[str]]:
    lower = artifact_path.lower()
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if lower.endswith(".deb"):
        if is_root and shutil.which("apt-get"):
            return ["apt-get", "install", "-y", artifact_path]
        return None
    if lower.endswith(".whl") or lower.endswith(".tar.gz"):
        return [sys.executable, "-m", "pip", "install", "--upgrade", artifact_path]
    return None


def apply_update(
    artifact_path: str,
    target_version: str,
    force: bool = False,
    installer_cmd: Optional[List[str]] = None,
    timeout: int = 600,
) -> Dict:
    """Hand a verified artifact to the system installer after rollback checks."""
    from aegorx import __version__

    try:
        target = parse_version(target_version)
        running = parse_version(__version__)
    except UpdateError:
        raise UpdateError(f"unparseable target version: {target_version!r}")
    if not force and target <= running:
        raise UpdateError(
            f"refusing downgrade/rollback: running {__version__},"
            f" target {target_version} (use --force to override)"
        )
    cmd = installer_cmd or _installer_for(artifact_path)
    if not cmd:
        raise UpdateError(
            f"no automatic installer for {artifact_path!r}; install manually "
            f"(root + apt-get required for .deb)"
        )
    try:
        proc = subprocess.run(  # noqa: S603 (fixed argv, no shell)
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise UpdateError(f"installer timed out after {timeout}s") from exc
    tail = "\n".join((proc.stdout or "").splitlines()[-15:])
    err_tail = "\n".join((proc.stderr or "").splitlines()[-15:])
    return {
        "installer": cmd[0],
        "returncode": proc.returncode,
        "output_tail": tail[-2000:],
        "error_tail": err_tail[-2000:],
    }


def auto_apply(
    kind: str = "auto",
    url: Optional[str] = None,
    opener: Optional[Callable] = None,
    force: bool = False,
    allow_expired: bool = False,
    dest_dir: Optional[str] = None,
) -> Dict:
    """check -> pick artifact -> verified download -> installer handoff."""
    result = check(url=url, opener=opener, allow_expired=allow_expired)
    if not result["update_available"] and not force:
        return {"updated": False, "reason": f"already at {result['current']}"} | {
            k: result[k] for k in ("available", "update_available")
        }
    doc = result["_doc"]
    artifacts = doc.get("artifacts") or {}
    order = (
        [kind]
        if kind != "auto"
        else ["deb", "wheel"]
    )
    chosen = next((k for k in order if k in artifacts), None)
    if chosen is None:
        raise UpdateError(f"no suitable artifact in manifest (wanted {order}, have {list(artifacts)})")
    cleanup = dest_dir is None
    dest = dest_dir or tempfile.mkdtemp(prefix="aegorx-update-")
    try:
        path = download_artifact(artifacts[chosen], dest, opener=opener)
        outcome = apply_update(path, doc["version"], force=force)
    finally:
        if cleanup and os.path.isdir(dest):
            shutil.rmtree(dest, ignore_errors=True)
    outcome.update({"artifact_kind": chosen, "target_version": doc["version"]})
    return outcome
