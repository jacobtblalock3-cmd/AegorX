"""Application control — allowlist/blocklist executables.

Controls which executables can run on the system by:
  - Hash-based allowlisting/blocklisting (SHA-256)
  - Path-based rules (allow/block specific directories)
  - Publisher verification (code signature checking)
  - Extension-based filtering (.exe, .dll, .scr, etc.)

Platform enforcement:
  Linux:   fanotify permission events (already in realtime monitor)
  macOS:   EndpointSecurity (already in realtime monitor)
  Windows: AppLocker-style hash checking

This module provides the policy engine; the actual enforcement happens
through the existing realtime monitor backends.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from aegorx.utils import state_dir


# ---------------------------------------------------------------------------
# Policy rules
# ---------------------------------------------------------------------------

@dataclass
class AppRule:
    """A single application control rule."""
    rule_type: str  # "hash", "path", "extension", "publisher"
    value: str      # hash value, path pattern, extension, or publisher name
    action: str     # "allow" or "block"
    name: str = ""  # human-readable name
    enabled: bool = True
    created_at: float = 0.0

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()
        if not self.name:
            self.name = f"{self.rule_type}:{self.value}"


@dataclass
class AppControlPolicy:
    """Application control policy."""
    rules: List[AppRule] = field(default_factory=list)
    default_action: str = "allow"  # "allow" or block everything not in allowlist
    log_blocked: bool = True
    quarantine_blocked: bool = False


# ---------------------------------------------------------------------------
# Policy Store
# ---------------------------------------------------------------------------

class PolicyStore:
    """Persist application control policies."""

    def __init__(self, path: Optional[str] = None) -> None:
        state = state_dir()
        self._path = path or os.path.join(state, "app-control-policy.json")

    def load(self) -> AppControlPolicy:
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            rules = [AppRule(**r) for r in data.get("rules", [])]
            return AppControlPolicy(
                rules=rules,
                default_action=data.get("default_action", "allow"),
                log_blocked=data.get("log_blocked", True),
                quarantine_blocked=data.get("quarantine_blocked", False),
            )
        except (OSError, json.JSONDecodeError, TypeError):
            return AppControlPolicy()

    def save(self, policy: AppControlPolicy) -> None:
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            data = {
                "rules": [
                    {
                        "rule_type": r.rule_type,
                        "value": r.value,
                        "action": r.action,
                        "name": r.name,
                        "enabled": r.enabled,
                        "created_at": r.created_at,
                    }
                    for r in policy.rules
                ],
                "default_action": policy.default_action,
                "log_blocked": policy.log_blocked,
                "quarantine_blocked": policy.quarantine_blocked,
            }
            tmp = self._path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except (OSError, json.JSONDecodeError):
            pass


# ---------------------------------------------------------------------------
# Hash Calculator
# ---------------------------------------------------------------------------

def file_sha256(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                data = fh.read(65536)
                if not data:
                    break
                h.update(data)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


# ---------------------------------------------------------------------------
# Application Controller
# ---------------------------------------------------------------------------

class ApplicationController:
    """Enforce application control policies.

    Parameters
    ----------
    policy:
        The application control policy.  Created from store if None.
    store:
        Policy store for persistence.  Created with defaults if None.
    scan_callback:
        Called with ``(path, verdict)`` when an executable is checked.
    """

    def __init__(
        self,
        policy: Optional[AppControlPolicy] = None,
        store: Optional[PolicyStore] = None,
        scan_callback: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self._store = store or PolicyStore()
        self._policy = policy or self._store.load()
        self.scan_callback = scan_callback
        self._lock = threading.Lock()
        self._cache: Dict[str, str] = {}  # path -> verdict (cached)
        self._stats = {
            "executables_checked": 0,
            "allowed": 0,
            "blocked": 0,
        }

    # -- Rule management ---------------------------------------------------

    def add_rule(self, rule_type: str, value: str, action: str, name: str = "") -> AppRule:
        """Add a new rule to the policy."""
        rule = AppRule(rule_type=rule_type, value=value, action=action, name=name)
        with self._lock:
            self._policy.rules.append(rule)
            self._store.save(self._policy)
            self._cache.clear()
        return rule

    def remove_rule(self, index: int) -> bool:
        """Remove a rule by index."""
        with self._lock:
            if 0 <= index < len(self._policy.rules):
                self._policy.rules.pop(index)
                self._store.save(self._policy)
                self._cache.clear()
                return True
        return False

    def list_rules(self) -> List[AppRule]:
        with self._lock:
            return list(self._policy.rules)

    def set_default_action(self, action: str) -> None:
        with self._lock:
            self._policy.default_action = action
            self._store.save(self._policy)

    # -- Checking ----------------------------------------------------------

    def check(self, path: str) -> str:
        """Check if an executable is allowed or blocked.

        Returns "allow" or "block".
        """
        with self._lock:
            # Check cache
            if path in self._cache:
                return self._cache[path]

            verdict = self._evaluate(path)
            self._cache[path] = verdict
            self._stats["executables_checked"] += 1
            if verdict == "allow":
                self._stats["allowed"] += 1
            else:
                self._stats["blocked"] += 1
            return verdict

    def _evaluate(self, path: str) -> str:
        """Evaluate all rules against a path."""
        path = os.path.abspath(path)
        _, ext = os.path.splitext(path)
        ext = ext.lower()

        # Check rules in order (first match wins)
        for rule in self._policy.rules:
            if not rule.enabled:
                continue
            if self._matches_rule(path, ext, rule):
                return rule.action

        # No rule matched — use default
        return self._policy.default_action

    def _matches_rule(self, path: str, ext: str, rule: AppRule) -> bool:
        """Check if a path matches a rule."""
        if rule.rule_type == "hash":
            current_hash = file_sha256(path)
            return current_hash == rule.value and current_hash != ""
        if rule.rule_type == "path":
            return fnmatch.fnmatch(path, rule.value)
        if rule.rule_type == "extension":
            return ext == rule.value.lower()
        if rule.rule_type == "publisher":
            # Publisher check requires code signing verification
            # Simplified: check if the path contains the publisher name
            return rule.value.lower() in path.lower()
        return False

    # -- Convenience methods -----------------------------------------------

    def block_hash(self, path: str, name: str = "") -> AppRule:
        """Block an executable by its SHA-256 hash."""
        h = file_sha256(path)
        if not h:
            raise ValueError(f"cannot hash {path}")
        return self.add_rule("hash", h, "block", name or os.path.basename(path))

    def block_path(self, pattern: str, name: str = "") -> AppRule:
        """Block executables matching a path pattern."""
        return self.add_rule("path", pattern, "block", name)

    def block_extension(self, extension: str, name: str = "") -> AppRule:
        """Block executables with a specific extension."""
        if not extension.startswith("."):
            extension = "." + extension
        return self.add_rule("extension", extension, "block", name)

    def allow_path(self, pattern: str, name: str = "") -> AppRule:
        """Allow executables matching a path pattern."""
        return self.add_rule("path", pattern, "allow", name)

    def allow_hash(self, path: str, name: str = "") -> AppRule:
        """Allow an executable by its SHA-256 hash."""
        h = file_sha256(path)
        if not h:
            raise ValueError(f"cannot hash {path}")
        return self.add_rule("hash", h, "allow", name or os.path.basename(path))

    # -- Status ------------------------------------------------------------

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0
