"""Local YARA-rule store fed by signed signature-feed updates.

Rules arrive inside the Ed25519-signed feed document and are installed into
<state>/rules/ as a full-state sync: the feed defines the authoritative rule
set, so rotated or retired family rules disappear on the next update instead
of accumulating forever. Installation is all-or-nothing: every rule must
compile (when yara-python is available) before any file touches disk.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Dict, List, Optional

from aegorx.utils import ensure_state_dir

RULES_DIR_NAME = "rules"
MANIFEST_NAME = "rules-manifest.json"
MAX_TOTAL_RULE_BYTES = 8 * 1024 * 1024
_LOCK = threading.RLock()


class RuleStoreError(RuntimeError):
    pass


def rules_dir() -> str:
    path = os.path.join(ensure_state_dir(), RULES_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def manifest_path() -> str:
    return os.path.join(rules_dir(), MANIFEST_NAME)


def load_manifest() -> Dict:
    try:
        with open(manifest_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"rules": {}}


_NAME_SAFE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")


def install_rules(entries: List[Dict]) -> Dict:
    """Atomically sync <state>/rules/ to exactly `entries`.

    Returns a summary {installed, removed, total}. Raises RuleStoreError on
    validation failure without modifying the active set.
    """
    from aegorx.signing.feed import sanitize_rule_entries

    normalized = sanitize_rule_entries(entries)

    total_bytes = sum(len(e["source"].encode("utf-8")) for e in normalized)
    if total_bytes > MAX_TOTAL_RULE_BYTES:
        raise RuleStoreError(f"rule set exceeds {MAX_TOTAL_RULE_BYTES} byte cap")

    compiled = None
    try:
        import yara

        sources = {}
        for idx, entry in enumerate(normalized):
            sources[f"{entry['name']}:{idx}"] = entry["source"]
        if sources:
            combined = "\n".join(sources.values())
            compiled = yara.compile(source=combined)
    except ImportError:
        compiled = None
    except Exception as exc:
        raise RuleStoreError(f"feed rule set failed to compile: {exc}") from exc

    directory = rules_dir()
    desired: Dict[str, Dict] = {}
    for entry in normalized:
        filename = f"{entry['sha256']}.yar"
        desired[filename] = entry

    with _LOCK:
        existing = {
            name for name in os.listdir(directory) if name.endswith(".yar")
        }
        stale = existing - set(desired)

        staged_dir = directory + ".staging"
        _rmtree(staged_dir)
        os.makedirs(staged_dir, exist_ok=True)
        for filename, entry in desired.items():
            stage_path = os.path.join(staged_dir, filename)
            fd = os.open(stage_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(entry["source"])
        manifest = {
            "updated_utc": time.time(),
            "rules": {
                entry["name"]: {
                    "sha256": entry["sha256"],
                    "file": filename,
                    "severity": entry["severity"],
                }
                for filename, entry in desired.items()
            },
        }
        with open(os.path.join(staged_dir, MANIFEST_NAME), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        for filename in stale:
            try:
                os.remove(os.path.join(directory, filename))
            except OSError:
                pass
        for filename in desired:
            src = os.path.join(staged_dir, filename)
            dst = os.path.join(directory, filename)
            os.replace(src, dst)
        _rmtree(staged_dir)

        tmp_manifest = manifest_path() + ".tmp"
        fd = os.open(tmp_manifest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_manifest, manifest_path())

    return {
        "installed": len(desired),
        "removed": len(stale),
        "total": len(desired),
        "compiled": compiled is not None,
    }


def clear_rules() -> int:
    """Remove every feed-provided rule; returns count removed."""
    with _LOCK:
        directory = rules_dir()
        removed = 0
        for name in os.listdir(directory):
            if name.endswith(".yar"):
                try:
                    os.remove(os.path.join(directory, name))
                    removed += 1
                except OSError:
                    pass
        tmp = manifest_path() + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"rules": {}}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, manifest_path())
        return removed


def current_rules() -> Dict:
    return load_manifest().get("rules", {})


def _rmtree(path: str) -> None:
    import logging
    import shutil

    if os.path.isdir(path):
        try:
            shutil.rmtree(path)
        except OSError as exc:
            logging.warning("rules_store: failed to remove staging dir %s: %s", path, exc)
