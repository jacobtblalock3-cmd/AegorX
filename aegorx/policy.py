"""Central fleet policy: one Ed25519-signed document per machine.

The administrator pushes an `apply-policy` command through the management
server; the signed envelope already guarantees provenance, so this module
only has to validate structure and apply atomically. Policy affects:

  * engine verdict thresholds (malicious/suspicious ML probabilities)
  * realtime monitor exclusions (fnmatch patterns)
  * scheduled deep-scan interval + paths (agent loop)

Absence of a policy file means stock behavior — every field is optional.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Dict, List, Optional

POLICY_FILE = "policy.json"
_POLICY_LOCK = threading.Lock()
BACKENDS = ("auto", "fanotify", "inotify", "fswatch", "es", "minifilter")
MAX_EXCLUSIONS = 200


class PolicyError(ValueError):
    pass


def policy_path() -> str:
    from aegorx.utils import ensure_state_dir

    return os.path.join(ensure_state_dir(), POLICY_FILE)


def validate_policy(doc) -> Dict:
    """Return a normalized policy dict or raise PolicyError."""
    if not isinstance(doc, dict):
        raise PolicyError("policy must be an object")

    out: Dict = {}

    exclusions = doc.get("exclusions", [])
    if not isinstance(exclusions, list) or len(exclusions) > MAX_EXCLUSIONS:
        raise PolicyError("exclusions must be a list of at most 200 patterns")
    for pattern in exclusions:
        if not isinstance(pattern, str) or not pattern.strip():
            raise PolicyError("exclusion patterns must be non-empty strings")
        if ".." in pattern:
            raise PolicyError("exclusion patterns may not contain '..'")
    out["exclusions"] = [p for p in (s.strip() for s in exclusions) if p]

    interval = doc.get("scan_interval_seconds", 0)
    if not isinstance(interval, int) or isinstance(interval, bool) or interval < 0:
        raise PolicyError("scan_interval_seconds must be a non-negative integer")
    out["scan_interval_seconds"] = interval

    paths = doc.get("scheduled_paths", [])
    if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths):
        raise PolicyError("scheduled_paths must be a list of strings")
    out["scheduled_paths"] = [p for p in paths if p]

    backend = doc.get("backend", "auto")
    if backend not in BACKENDS:
        raise PolicyError(f"backend must be one of {BACKENDS}")
    out["backend"] = backend

    for key, default in (
        ("malicious_probability", None),
        ("suspicious_probability", None),
    ):
        value = doc.get(key)
        if value is None:
            continue
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1:
            raise PolicyError(f"{key} must be a number in [0, 1]")
        out[key] = float(value)

    unknown = set(doc) - {
        "exclusions",
        "scan_interval_seconds",
        "scheduled_paths",
        "backend",
        "malicious_probability",
        "suspicious_probability",
    }
    if unknown:
        raise PolicyError(f"unknown policy fields: {sorted(unknown)}")
    return out


def save_policy(doc: Dict) -> str:
    """Validate then atomically write the active policy."""
    normalized = validate_policy(doc)
    path = policy_path()
    with _POLICY_LOCK:
        # Use O_NOFOLLOW to prevent symlink attacks on temp file
        _O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(normalized, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(path + ".tmp", path)
    return path


def load_policy() -> Optional[Dict]:
    with _POLICY_LOCK:
        try:
            with open(policy_path(), "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            return doc if isinstance(doc, dict) else None
        except (OSError, json.JSONDecodeError):
            return None


def clear_policy() -> bool:
    with _POLICY_LOCK:
        try:
            os.remove(policy_path())
            return True
        except OSError:
            return False
