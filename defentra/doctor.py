"""One-shot health/suitability report for a Defentra installation.

`defentra doctor` probes every protection layer read-only and prints an
OK/WARN/FAIL line per check:

  * runtime & privileges (root / fanotify availability)
  * detection content (signature DB, ML model, feed freshness)
  * trust (pinned keys, sealed anchors, audit-chain integrity)
  * fleet wiring (agent pairing, central policy)

Exit code is non-zero when any check FAILs, so cron/monitoring can consume it.
Doctor never mutates state, never touches the network, and works on any OS
(reports the platform's gaps as warnings rather than crashing).
"""

from __future__ import annotations

import os
import sys
import time
from typing import Callable, Dict, List

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"

CHECKS: List[Dict] = []


def check(name: str) -> Callable:
    def register(fn: Callable[[], Dict]) -> Dict:
        CHECKS.append({"name": name, "fn": fn})
        return fn

    return register


def _result(status: str, detail: str) -> Dict:
    return {"status": status, "detail": detail}


# ------------------------------------------------------------------- checks


@check("platform")
def _check_platform() -> Dict:
    import platform

    system = platform.system()
    version = platform.release()
    if system == "Linux":
        return _result(STATUS_OK, f"Linux {version}")
    return _result(
        STATUS_WARN,
        f"{system} {version} — realtime blocking requires Linux; scanning still works",
    )


@check("privileges")
def _check_privileges() -> Dict:
    if not hasattr(os, "geteuid"):
        return _result(STATUS_WARN, "cannot determine uid on this platform")
    if os.geteuid() == 0:
        return _result(STATUS_OK, "running as root (fanotify permission events possible)")
    return _result(STATUS_WARN, "not root — realtime monitor will fall back to inotify")


@check("fanotify")
def _check_fanotify() -> Dict:
    if sys.platform != "linux":
        return _result(STATUS_WARN, "fanotify is Linux-only")
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.fanotify_init
    except (OSError, AttributeError):
        return _result(STATUS_WARN, "fanotify syscall wrapper unavailable in libc")
    FAN_CLOEXEC = 0x1
    FAN_CLASS_CONTENT = 0x4
    init.restype = ctypes.c_int
    init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    fd = init(FAN_CLOEXEC | FAN_CLASS_CONTENT, os.O_RDONLY)
    if fd >= 0:
        os.close(fd)
        return _result(STATUS_OK, "fanotify_init(FAN_CLASS_CONTENT) succeeded")
    import errno

    err = ctypes.get_errno()
    name = errno.errorcode.get(err, str(err))
    if err in (errno.EPERM, errno.EACCES):
        return _result(STATUS_WARN, f"fanotify_init denied ({name}) — run as root for blocking mode")
    return _result(STATUS_FAIL, f"fanotify_init failed: {name} — kernel support problem")


@check("signatures")
def _check_signatures() -> Dict:
    from defentra.signatures.db import SignatureDB
    from defentra.utils import state_dir

    path = os.path.join(state_dir(), "signatures.db")
    try:
        count = SignatureDB(path).count()
    except Exception as exc:
        return _result(STATUS_FAIL, f"signature database unusable: {exc}")
    if count <= 0:
        return _result(STATUS_WARN, "signature database empty — run 'defentra db seed' or 'feed update'")
    return _result(STATUS_OK, f"{count} signatures in {path}")


@check("ml-model")
def _check_model() -> Dict:
    from defentra.ml.classifier import MalwareClassifier

    info = MalwareClassifier().info()
    if info.get("available"):
        return _result(STATUS_OK, f"model loaded from {info.get('model_path')}")
    return _result(
        STATUS_WARN,
        "no ML model — run 'defentra model fetch' (detection relies on signatures/YARA)",
    )


@check("feed-freshness")
def _check_feed_freshness() -> Dict:
    import json

    from defentra.utils import state_dir

    state_path = os.path.join(state_dir(), "feed_state.json")
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh).get("last_generated_utc", "")
    except (OSError, json.JSONDecodeError):
        return _result(STATUS_WARN, "no feed ever applied — run 'defentra feed update'")
    if not raw:
        return _result(STATUS_WARN, "no feed ever applied — run 'defentra feed update'")
    from defentra.signing.feed import parse_utc

    age_days = (time.time() - parse_utc(raw).timestamp()) / 86400
    if age_days > 30:
        return _result(STATUS_WARN, f"last feed applied {age_days:.0f} days ago")
    return _result(STATUS_OK, f"last feed applied {age_days:.1f} days ago")


@check("trust-keys")
def _check_trust_keys() -> Dict:
    from defentra.signing.keys import trusted_key_paths

    paths = trusted_key_paths()
    bundled = [p for p in paths if "/trusted_keys/" in p.replace(os.sep, "/")]
    if not bundled:
        return _result(STATUS_FAIL, "package root trust key missing — updates cannot be verified")
    extra = len(paths) - len(bundled)
    detail = f"{len(bundled)} pinned package key(s)"
    if extra:
        detail += f" + {extra} user-trusted"
    return _result(STATUS_OK, detail)


@check("audit-chain")
def _check_audit_chain() -> Dict:
    from defentra.realtime.monitor import verify_audit_log
    from defentra.utils import state_dir

    path = os.path.join(state_dir(), "realtime.log")
    if not os.path.exists(path):
        return _result(STATUS_WARN, "no realtime audit log yet (monitor never ran)")
    ok, detail = verify_audit_log(path)
    if ok:
        return _result(STATUS_OK, f"realtime audit chain valid ({detail})")
    return _result(STATUS_FAIL, f"realtime audit chain INVALID: {detail}")


@check("quarantine-vault")
def _check_quarantine() -> Dict:
    from defentra.quarantine.vault import QuarantineVault

    vault = QuarantineVault()
    items = vault.list_items()
    return _result(STATUS_OK, f"vault accessible, {len(items)} item(s) quarantined")


@check("agent-pairing")
def _check_agent_pairing() -> Dict:
    from defentra.management.agent import AgentConfigError, load_config

    try:
        cfg = load_config()
    except AgentConfigError:
        return _result(STATUS_WARN, "not paired to a management console (standalone mode)")
    return _result(
        STATUS_OK,
        f"paired as {cfg.get('agent_id')} -> {cfg.get('server_url')}",
    )


@check("central-policy")
def _check_policy() -> Dict:
    from defentra.policy import load_policy

    policy = load_policy()
    if not policy or all(not v for v in policy.values()):
        return _result(STATUS_WARN, "no central policy applied (stock behavior)")
    fields = ", ".join(sorted(k for k, v in policy.items() if v))
    return _result(STATUS_OK, f"policy active: {fields}")


# ------------------------------------------------------------------ runner


def run_doctor() -> List[Dict]:
    """Run every registered check; one check failing must not stop the rest."""
    reports = []
    for entry in CHECKS:
        try:
            res = entry["fn"]()
        except Exception as exc:  # noqa: BLE001 - diagnostics must not crash
            res = {"status": STATUS_FAIL, "detail": f"check crashed: {exc}"}
        reports.append({"check": entry["name"], **res})
    return reports


def render_text(reports: List[Dict]) -> str:
    marks = {STATUS_OK: "[ OK ]", STATUS_WARN: "[WARN]", STATUS_FAIL: "[FAIL]"}
    lines = []
    for r in reports:
        lines.append(f"{marks[r['status']]} {r['check'].ljust(16)} {r['detail']}")
    fails = sum(1 for r in reports if r["status"] == STATUS_FAIL)
    warns = sum(1 for r in reports if r["status"] == STATUS_WARN)
    summary = "all checks passed"
    if warns or fails:
        summary = f"{warns} warning(s), {fails} failure(s)"
    lines.append("-" * 72)
    lines.append(f"doctor: {summary}")
    return "\n".join(lines)
