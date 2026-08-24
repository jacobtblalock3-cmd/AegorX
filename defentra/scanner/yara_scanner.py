from __future__ import annotations

import os
from typing import List, Optional

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False


class YaraScanner:
    """Compiles YARA rule files from one or more directories and scans targets."""

    def __init__(self, rules_dirs: Optional[List[str]] = None, timeout: int = 60):
        self.timeout = timeout
        self.rules_dirs = list(rules_dirs or [])
        self._sources_mtime = 0.0
        self.rules = None
        self.rule_count = 0
        if YARA_AVAILABLE and self.rules_dirs:
            self._compile()

    def _collect_sources(self) -> Dict[str, str]:
        sources = {}
        latest_mtime = 0.0
        for rules_dir in self.rules_dirs:
            if not os.path.isdir(rules_dir):
                continue
            for fname in sorted(os.listdir(rules_dir)):
                if fname.endswith((".yar", ".yara")):
                    fpath = os.path.join(rules_dir, fname)
                    try:
                        mtime = os.path.getmtime(fpath)
                        latest_mtime = max(latest_mtime, mtime)
                        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                            sources[f"{fname}:{len(sources)}"] = fh.read()
                    except OSError:
                        continue
        self._sources_mtime = latest_mtime
        return sources

    def _compile(self) -> None:
        sources = self._collect_sources()
        if not sources:
            return
        # Namespace each file so identical rule names across sources
        # (e.g. a builtin rule also shipped via the signed feed) coexist
        # instead of failing compilation with DUPLICATE_IDENTIFIER.
        namespaced = {f"ns{idx}": source for idx, source in enumerate(sources.values())}
        try:
            self.rules = yara.compile(sources=namespaced)
            self.rule_count = len(sources)
        except yara.Error:
            self.rules = None
            self.rule_count = 0

    def maybe_reload(self) -> bool:
        """Recompile when any rule file changed on disk; returns True if reloaded."""
        if not (YARA_AVAILABLE and self.rules_dirs):
            return False
        latest = 0.0
        for rules_dir in self.rules_dirs:
            if not os.path.isdir(rules_dir):
                continue
            try:
                for fname in os.listdir(rules_dir):
                    if fname.endswith((".yar", ".yara")):
                        latest = max(latest, os.path.getmtime(os.path.join(rules_dir, fname)))
            except OSError:
                continue
        if latest <= self._sources_mtime:
            return False
        self._compile()
        return True

    @property
    def available(self) -> bool:
        return self.rules is not None

    def match_file(self, path: str) -> List[dict]:
        if self.rules is None:
            return []
        try:
            matches = self.rules.match(path, timeout=self.timeout)
        except yara.TimeoutError:
            return []
        except yara.Error:
            return []
        results = []
        for m in matches:
            severity = m.meta.get("severity", 5)
            try:
                severity = int(severity)
            except (TypeError, ValueError):
                severity = 5
            results.append(
                {
                    "rule": m.rule,
                    "tags": list(m.tags),
                    "severity": severity,
                    "meta": {k: str(v) for k, v in m.meta.items()},
                }
            )
        return results
