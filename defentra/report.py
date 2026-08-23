"""Human-readable and JSON rendering of scan results."""

from __future__ import annotations

import json
import platform
import time
from typing import Iterable, List

from defentra.engine import FileScanResult
from defentra import __version__

COLORS = {
    "malicious": "\033[91m",
    "suspicious": "\033[93m",
    "clean": "\033[92m",
    "error": "\033[95m",
}
RESET = "\033[0m"
BOLD = "\033[1m"

_CONTROL_RE = __import__("re").compile(r"[\x00-\x1f\x7f]")


def sanitize(text: str) -> str:
    """Neutralize control/ANSI escape sequences from untrusted strings.

    Malicious files can carry terminal-escape sequences in their names;
    rendering them raw would let the file control the user's terminal.
    """
    return _CONTROL_RE.sub("?", str(text))


def to_dict(results: List[FileScanResult], target: str, elapsed: float) -> dict:
    files = []
    counts = {"clean": 0, "suspicious": 0, "malicious": 0, "error": 0}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
        files.append(
            {
                "path": r.path,
                "size": r.size,
                "sha256": r.sha256,
                "md5": r.md5,
                "verdict": r.verdict,
                "ml_probability": r.ml_probability,
                "detections": [
                    {
                        "detector": d.detector,
                        "name": d.name,
                        "severity": d.severity,
                        "details": d.details,
                    }
                    for d in r.detections
                ],
                "error": r.error,
            }
        )
    return {
        "engine": "defentra",
        "version": __version__,
        "target": target,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "elapsed_seconds": round(elapsed, 3),
        "files_scanned": len(results),
        "summary": counts,
        "platform": platform.platform(),
        "files": files,
    }


def render_json(results: List[FileScanResult], target: str, elapsed: float) -> str:
    return json.dumps(to_dict(results, target, elapsed), indent=2)


def render_text(results: List[FileScanResult], target: str, elapsed: float, color: bool = True) -> str:
    lines: List[str] = []
    lines.append(f"{BOLD if color else ''}Defentra scan report{RESET if color else ''}")
    lines.append(f"Target : {target}")

    flagged = 0
    for r in results:
        if r.verdict in ("malicious", "suspicious"):
            flagged += 1
            c = COLORS.get(r.verdict, "") if color else ""
            lines.append("")
            lines.append(f"  {c}[{r.verdict.upper()}]{RESET if color else ''} {sanitize(r.path)}")
            lines.append(f"    sha256 : {sanitize(r.sha256)}")
            lines.append(f"    size   : {r.size} bytes")
            if r.ml_probability is not None:
                lines.append(f"    ml     : {r.ml_probability:.3f} malware probability")
            for d in r.detections:
                lines.append(f"    hit    : [{sanitize(d.detector)}] {sanitize(d.name)} (severity {d.severity})")
        elif r.verdict == "error":
            lines.append(f"\n  [ERROR] {sanitize(r.path)}: {sanitize(r.error)}")

    summary = {"clean": 0, "suspicious": 0, "malicious": 0, "error": 0}
    for r in results:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1
    lines.append("")
    lines.append("-" * 62)
    lines.append(
        f"{len(results)} file(s) scanned in {elapsed:.2f}s | "
        f"clean={summary['clean']} suspicious={summary['suspicious']} "
        f"malicious={summary['malicious']} error={summary['error']}"
    )
    status = "THREATS FOUND" if flagged else "NO THREATS DETECTED"
    sc = COLORS.get("malicious" if flagged else "clean", "") if color else ""
    lines.append(f"{sc}{status}{RESET if color else ''}")
    return "\n".join(lines)
