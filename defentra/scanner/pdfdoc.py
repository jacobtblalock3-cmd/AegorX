"""PDF document analysis: automatic-execution and payload heuristics.

Pure stdlib. Real malicious PDFs compress their JavaScript and launch
objects into FlateDecode streams, so analysis inflates every stream within
budget before scoring. Detection policy is deliberately conservative:

- Auto-exec context (/OpenAction, /AA) plus an execution payload (/Launch,
  /JS) -> malicious (severity 8): code runs merely by opening the file.
- Execution payload without auto-exec -> suspicious (severity 6).
- Embedded files / form submission / data import -> informational (severity 4).

Structure keywords are matched against the raw bytes AND all inflated
streams; comments between keywords are not stripped, but the compound
conditions make accidental matches from prose unlikely.
"""

from __future__ import annotations

import re
import zlib
from typing import Dict, List, Optional

MAGIC_PDF = b"%PDF-"

MAX_PDF_BYTES = 64 * 1024 * 1024
MAX_INFLATED_TOTAL_BYTES = 32 * 1024 * 1024
MAX_STREAMS = 4096

_AUTOEXEC = [rb"/OpenAction", rb"/AA\b"]
_ACTIVE = [
    rb"/JavaScript",
    rb"/JS\b",
    rb"/Launch",
]
_PASSIVE_RISK = [
    rb"/EmbeddedFile",
    rb"/SubmitForm",
    rb"/ImportData",
    rb"/GoToE",  # embedded-document navigation
    rb"/GoToR",  # remote-document navigation
]


def looks_like_pdf(head: bytes) -> bool:
    return head.startswith(MAGIC_PDF)


def _inflate_streams(data: bytes) -> List[bytes]:
    """Decompress FlateDecode streams up to budget; best-effort by design."""
    inflated: List[bytes] = []
    total = 0
    for match in re.finditer(rb"stream\r?\n", data):
        if len(inflated) >= MAX_STREAMS or total >= MAX_INFLATED_TOTAL_BYTES:
            break
        start = match.end()
        end = data.find(b"endstream", start)
        if end == -1:
            continue
        raw = data[start:end].rstrip(b"\r\n")
        try:
            blob = zlib.decompress(raw)
        except zlib.error:
            continue
        remaining = MAX_INFLATED_TOTAL_BYTES - total
        if len(blob) > remaining:
            blob = blob[:remaining]
        total += len(blob)
        inflated.append(blob)
        if total >= MAX_INFLATED_TOTAL_BYTES:
            break
    return inflated


def analyze_pdf_content(content_blobs: List[bytes]) -> List[Dict]:
    """Score already-extracted byte blobs; pure function, directly testable."""
    if not content_blobs:
        return []

    def present(pattern: bytes) -> bool:
        return any(re.search(pattern, blob) for blob in content_blobs)

    autoexec = any(present(p) for p in _AUTOEXEC)
    active = any(present(p) for p in _ACTIVE)
    passive = sorted(
        {p.rstrip(b"\\b").lstrip(b"/").decode("ascii") for p in _PASSIVE_RISK if present(p)}
    )

    detections: List[Dict] = []
    if autoexec and active:
        details: Dict = {"trigger": "OpenAction/AA", "payload": "JS/Launch"}
        if passive:
            details["extras"] = ",".join(passive)
        detections.append({"name": "PDF.AutoExec.Chain", "severity": 8, "details": details})
    elif active:
        detections.append(
            {"name": "PDF.ActiveContent", "severity": 6, "details": {"note": "script/launch action present"}}
        )
    elif passive:
        detections.append(
            {"name": "PDF.PassiveExtras", "severity": 4, "details": {"features": ",".join(passive)}}
        )
    return detections


def analyze_pdf(path: str) -> Optional[List[Dict]]:
    """Analyze a file already confirmed to carry %PDF magic.

    Returns detection dicts, or None when the file could not be read.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_PDF_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_PDF_BYTES:
        data = data[:MAX_PDF_BYTES]
    blobs = [data] + _inflate_streams(data)
    return analyze_pdf_content(blobs)
