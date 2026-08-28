"""Office document analysis: OLE compound files and embedded VBA macros.

Uses oletools when available (install extra `office`); degrades gracefully
to structural checks otherwise, mirroring how the engine treats yara-python
and the ML model. Detection policy is deliberately conservative:

- Macros present, nothing risky          -> info-level note (severity 3)
- Risky API surface in any module        -> suspicious (severity 6)
- Auto-exec entrypoint + execution chain -> malicious (severity 8)

Pure-heuristic detections never claim certainty silently: names carry the
evidence ("VBA.AutoExec.Chain", "VBA.RiskyAPIs") so analysts can triage.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

MAGIC_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

try:  # pragma: no cover - exercised only when the extra is installed
    from oletools.olevba import VBA_Parser  # type: ignore

    OFFICE_AVAILABLE = True
except ImportError:  # pragma: no cover
    VBA_Parser = None  # type: ignore
    OFFICE_AVAILABLE = False


class _Pattern:
    __slots__ = ("regex", "label")

    def __init__(self, regex: str, label: str) -> None:
        self.regex = re.compile(regex, re.IGNORECASE)
        self.label = label


AUTOEXEC_PATTERNS = [
    _Pattern(r"\bAuto(?:Open|Close|Exec|Exit|New)\b", "autoexec"),
    _Pattern(r"\bDocument_(?:Open|Close|BeforeClose)\b", "autoexec"),
    _Pattern(r"\bWorkbook_(?:Open|BeforeClose)\b", "autoexec"),
    _Pattern(r"\bAuto_?Open\b", "autoexec"),
]

EXEC_CHAIN_PATTERNS = [
    _Pattern(r"\bShell\s*\(", "shell"),
    _Pattern(r"WScript\.Shell", "wscript"),
    _Pattern(r"\bcmd(\.exe)?\s+/c\b", "cmd"),
    _Pattern(r"powershell(?!.*Get-Help)", "powershell"),
    _Pattern(r"\bInvoke-Expression\b|\bIEX\s*\(", "iex"),
    _Pattern(r"CreateObject\(\s*['\"](WScript\.Shell|MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest|ADODB\.Stream)", "createobject-chain"),
    _Pattern(r"\bVirtualAlloc\b|\bWriteProcessMemory\b|\bCreateThread\b", "native-inject"),
    _Pattern(r"\bEnviron\(['\"](PUBLIC|TEMP|APPDATA)", "env-path-probe"),
]

DOWNLOAD_PATTERNS = [
    _Pattern(r"https?://", "url-reference"),
    _Pattern(r"\bURLDownloadToFile\b", "download-api"),
]

OBFUSCATION_PATTERNS = [
    _Pattern(r"\bChr\(\s*\d+\s*\)\s*&", "chr-concat"),
    _Pattern(r"\bStrReverse\b", "strreverse"),
    _Pattern(r"\bBase64Decode\b|\bFromBase64String\b", "base64"),
]


def analyze_vba_sources(sources: List[str]) -> List[Dict]:
    """Score raw VBA source text; pure function so it is directly testable.

    Returns dicts: {"name", "severity", "details"} — empty list when no VBA.
    """
    if not sources:
        return []
    joined = "\n".join(sources)

    autoexec = sorted({p.label for p in AUTOEXEC_PATTERNS if p.regex.search(joined)})
    exec_chain = sorted({p.label for p in EXEC_CHAIN_PATTERNS if p.regex.search(joined)})
    downloads = sorted({p.label for p in DOWNLOAD_PATTERNS if p.regex.search(joined)})
    obfuscation = sorted({p.label for p in OBFUSCATION_PATTERNS if p.regex.search(joined)})

    if autoexec and exec_chain:
        return [
            {
                "name": "VBA.AutoExec.Chain",
                "severity": 8,
                "details": {
                    "autoexec": ",".join(autoexec),
                    "execution": ",".join(exec_chain),
                    **({"downloads": ",".join(downloads)} if downloads else {}),
                    **({"obfuscation": ",".join(obfuscation)} if obfuscation else {}),
                },
            }
        ]
    risky = exec_chain or downloads or obfuscation
    if risky:
        return [
            {
                "name": "VBA.RiskyAPIs",
                "severity": 6,
                "details": {"indicators": ",".join(sorted(set(exec_chain + downloads + obfuscation)))},
            }
        ]
    return [{"name": "Document.ContainsMacros", "severity": 3, "details": {"modules": str(len(sources))}}]


def looks_like_office(head: bytes) -> bool:
    return head.startswith(MAGIC_OLE)


def extract_macro_sources(path: str) -> Optional[List[str]]:
    """Extract VBA module sources; None when unsupported/unavailable/unreadable."""
    if not OFFICE_AVAILABLE:
        return None
    try:  # pragma: no cover - requires oletools at runtime
        parser = VBA_Parser(path)
        try:
            if not parser.detect_vba_macros():
                return []
            return [code for (_f, _s, _n, code) in parser.extract_macros() if code]
        finally:
            parser.close()
    except Exception:
        return None


def analyze_document(path: str) -> Optional[List[Dict]]:
    """Full office analysis for a file already confirmed to be OLE magic.

    Returns detection dicts, [] when no macros, or None when macro analysis
    is unavailable (caller may surface that as an informational note).
    """
    sources = extract_macro_sources(path)
    if sources is None:
        return None
    return analyze_vba_sources(sources)
