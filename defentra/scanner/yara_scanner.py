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
        self.rules = None
        self.rule_count = 0
        if not YARA_AVAILABLE or not rules_dirs:
            return
        sources = {}
        for rules_dir in rules_dirs:
            if not os.path.isdir(rules_dir):
                continue
            for fname in sorted(os.listdir(rules_dir)):
                if fname.endswith((".yar", ".yara")):
                    fpath = os.path.join(rules_dir, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                            sources[f"{fname}:{len(sources)}"] = fh.read()
                    except OSError:
                        continue
        if not sources:
            return
        combined = "\n".join(sources.values())
        self.rules = yara.compile(source=combined)
        self.rule_count = len(sources)

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
