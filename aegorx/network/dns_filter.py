"""DNS-based domain filtering for network protection.

Maintains a blocklist of malicious domains and provides fast O(domain-length)
lookups via a trie.  Supports three blocklist sources that merge on load:

  1. Threat-intel blocklist   — pulled from URLhaus, community feeds, etc.
  2. Custom blocklist         — user-managed allow/block overrides.
  3. Built-in blocklist       — shipped with the engine (phishing, malware C2).

Blocked domains resolve to ``BLOCK_IP`` (0.0.0.0) so connections fail fast
without leaking DNS queries upstream.

The filter is platform-independent — it does not touch ``/etc/hosts`` or
firewall rules.  Higher-level wrappers (``cmd_network``) are responsible
for platform integration (iptables, WFP, pf).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from aegorx.utils import ensure_state_dir

logger = logging.getLogger(__name__)

BLOCK_IP = "0.0.0.0"

# ---------------------------------------------------------------------------
# Trie node for fast domain lookups (reversed-label ordering)
# ---------------------------------------------------------------------------

class _TrieNode:
    __slots__ = ("children", "blocked")

    def __init__(self) -> None:
        self.children: Dict[str, _TrieNode] = {}
        self.blocked: bool = False


# ---------------------------------------------------------------------------
# DNSFilter
# ---------------------------------------------------------------------------

class DNSFilter:
    """Fast domain blocklist with trie-based lookups.

    Parameters
    ----------
    blocklist_path:
        JSON file containing ``{"domains": ["evil.com", ...]}``.
        Created automatically if absent.
    custom_blocklist_path:
        User-managed overrides (same format).  Merged on top of the
        primary blocklist.
    """

    def __init__(
        self,
        blocklist_path: Optional[str] = None,
        custom_blocklist_path: Optional[str] = None,
    ) -> None:
        state = ensure_state_dir()
        self.blocklist_path = blocklist_path or os.path.join(state, "network-blocklist.json")
        self.custom_blocklist_path = custom_blocklist_path or os.path.join(
            state, "network-custom-blocklist.json"
        )
        self._lock = threading.RLock()
        self._root = _TrieNode()
        self._blocked_domains: Set[str] = set()
        self._allow_domains: Set[str] = set()
        self._stats = {
            "queries": 0,
            "blocked": 0,
            "allowed": 0,
            "custom_blocked": 0,
            "custom_allowed": 0,
        }
        self._load()

    # -- persistence --------------------------------------------------------

    def _empty_store(self) -> Dict:
        return {"domains": [], "updated_utc": 0.0, "version": 1}

    def _load_json(self, path: str) -> Dict:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and isinstance(data.get("domains"), list):
                return data
        except (OSError, json.JSONDecodeError):
            pass
        return self._empty_store()

    def _save_json(self, path: str, data: Dict) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    # -- trie operations ----------------------------------------------------

    @staticmethod
    def _normalize(domain: str) -> str:
        return domain.strip().lower().lstrip(".")

    @staticmethod
    def _reverse_labels(domain: str) -> List[str]:
        return list(reversed(domain.split(".")))

    def _insert(self, domain: str) -> None:
        node = self._root
        for label in self._reverse_labels(domain):
            node = node.children.setdefault(label, _TrieNode())
        node.blocked = True

    def _lookup_node(self, domain: str) -> Optional[_TrieNode]:
        node = self._root
        for label in self._reverse_labels(domain):
            node = node.children.get(label)
            if node is None:
                return None
        return node

    def _build_trie(self, domains: Set[str]) -> None:
        self._root = _TrieNode()
        for domain in domains:
            self._insert(domain)

    # -- public API ---------------------------------------------------------

    def _load(self) -> None:
        with self._lock:
            primary = self._load_json(self.blocklist_path)
            custom = self._load_json(self.custom_blocklist_path)
            primary_set = {self._normalize(d) for d in primary.get("domains", []) if isinstance(d, str)}
            custom_list = custom.get("domains", [])
            custom_blocked = {self._normalize(d) for d in custom_list if isinstance(d, str)}
            self._blocked_domains = primary_set | custom_blocked
            allowed_list = custom.get("allowed", [])
            self._allow_domains = {self._normalize(d) for d in allowed_list if isinstance(d, str)}
            self._build_trie(self._blocked_domains)

    def reload(self) -> None:
        """Reload blocklist from disk."""
        self._load()

    def lookup(self, domain: str) -> bool:
        """Return True if the domain is blocked."""
        domain = self._normalize(domain)
        if not domain:
            return False
        with self._lock:
            if domain in self._allow_domains:
                self._stats["queries"] += 1
                self._stats["allowed"] += 1
                return False
            self._stats["queries"] += 1
            node = self._lookup_node(domain)
            if node is not None and node.blocked:
                self._stats["blocked"] += 1
                return True
            # Check ancestor domains (subdomain of blocked domain)
            labels = self._reverse_labels(domain)
            ancestor = self._root
            for label in labels:
                ancestor = ancestor.children.get(label)
                if ancestor is None:
                    break
                if ancestor.blocked:
                    self._stats["blocked"] += 1
                    return True
            self._stats["allowed"] += 1
            return False

    def block(self, domain: str) -> bool:
        """Add a domain to the custom blocklist.  Returns True if newly added."""
        domain = self._normalize(domain)
        if not domain:
            return False
        with self._lock:
            if domain in self._blocked_domains:
                return False
            self._blocked_domains.add(domain)
            self._insert(domain)
            self._persist_custom()
            return True

    def unblock(self, domain: str) -> bool:
        """Remove a domain from the custom blocklist.  Returns True if removed."""
        domain = self._normalize(domain)
        if not domain:
            return False
        with self._lock:
            if domain not in self._blocked_domains:
                return False
            self._blocked_domains.discard(domain)
            self._rebuild_and_persist()
            return True

    def allow(self, domain: str) -> bool:
        """Add a domain to the allow-list (bypasses blocking)."""
        domain = self._normalize(domain)
        if not domain:
            return False
        with self._lock:
            if domain in self._allow_domains:
                return False
            self._allow_domains.add(domain)
            self._save_json(
                self.custom_blocklist_path,
                {
                    "domains": sorted(self._blocked_domains),
                    "allowed": sorted(self._allow_domains),
                    "updated_utc": time.time(),
                    "version": 1,
                },
            )
            return True

    def is_allowed(self, domain: str) -> bool:
        """Return True if domain is in the allow-list."""
        with self._lock:
            return self._normalize(domain) in self._allow_domains

    def _persist_custom(self) -> None:
        with self._lock:
            primary_domains = set(
                self._normalize(d)
                for d in self._load_json(self.blocklist_path).get("domains", [])
            )
            custom = {
                "domains": sorted(self._blocked_domains - primary_domains),
                "updated_utc": time.time(),
                "version": 1,
            }
        self._save_json(self.custom_blocklist_path, custom)

    def _rebuild_and_persist(self) -> None:
        self._build_trie(self._blocked_domains)
        self._persist_custom()

    def import_blocklist(self, domains: List[str], source: str = "import") -> int:
        """Bulk-import domains.  Returns count of newly added domains."""
        added = 0
        with self._lock:
            for domain in domains:
                domain = self._normalize(domain)
                if domain and domain not in self._blocked_domains:
                    self._blocked_domains.add(domain)
                    self._insert(domain)
                    added += 1
            if added:
                self._save_json(
                    self.blocklist_path,
                    {
                        "domains": sorted(self._blocked_domains),
                        "updated_utc": time.time(),
                        "version": 1,
                        "source": source,
                    },
                )
        return added

    def domains(self) -> List[str]:
        """Return sorted list of all blocked domains."""
        with self._lock:
            return sorted(self._blocked_domains)

    def count(self) -> int:
        with self._lock:
            return len(self._blocked_domains)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0
