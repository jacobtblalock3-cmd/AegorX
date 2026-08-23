"""Self-protection: audited shutdown, liveness heartbeat, trust-anchor sealing.

Userspace AV cannot prevent a root attacker from killing it (that requires
kernel support), but it can make every shutdown attempt *loud*, restart
automatically, and prove whether its trust anchors were touched:

  * install_signal_handlers - SIGTERM/SIGINT/SIGQUIT are recorded in the
    tamper-evident audit log before a clean stop; SIGHUP is ignored so a
    terminal hangup cannot silently end protection.
  * Heartbeat               - periodic liveness record consumed by
    `defentra watchdog`, which restarts the service when it goes stale.
  * seal/verify manifest    - pins SHA256 of trust anchors (bundled + user
    keys, agent config); drift means someone edited what the engine trusts.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import threading
import time
from typing import Callable, Dict, List, Optional

from defentra.utils import ensure_state_dir

HEARTBEAT_NAME = "heartbeat.json"
MANIFEST_NAME = "protection-manifest.json"
DEFAULT_HEARTBEAT_SECONDS = 30.0


def _state_path(name: str) -> str:
    return os.path.join(ensure_state_dir(), name)


# ---------------------------------------------------------------- heartbeat
class Heartbeat:
    """Writes pid+timestamp to the state directory on an interval."""

    def __init__(self, seconds: float = DEFAULT_HEARTBEAT_SECONDS):
        self.path = _state_path(HEARTBEAT_NAME)
        self.seconds = max(5.0, float(seconds))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _write(self) -> None:
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"pid": os.getpid(), "ts": time.time()}, fh)
        os.replace(tmp, self.path)

    def _loop(self) -> None:
        while not self._stop.wait(timeout=self.seconds):
            try:
                self._write()
            except OSError:
                pass

    def start(self) -> None:
        self._write()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="defentra-heartbeat")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


def read_heartbeat() -> Optional[Dict]:
    try:
        with open(_state_path(HEARTBEAT_NAME), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "pid" in data and "ts" in data:
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return None


def liveness(max_age_seconds: float = 90.0) -> Dict:
    """Assess agent health without side effects."""
    hb = read_heartbeat()
    if not hb:
        return {"healthy": False, "reason": "no heartbeat"}
    age = time.time() - float(hb["ts"])
    alive = _pid_alive(int(hb["pid"]))
    healthy = age <= max_age_seconds and alive
    return {"healthy": healthy, "pid": int(hb["pid"]), "age_seconds": round(age, 1), "process_alive": alive}


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def restart_service(unit: str = "defentra-monitor") -> bool:
    """Best-effort systemd restart; returns True when the restart was issued."""
    import subprocess

    try:
        result = subprocess.run(
            ["systemctl", "restart", unit],
            capture_output=True,
            timeout=30,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ------------------------------------------------------------------ signals
def install_signal_handlers(on_stop: Callable[[str], None], audit: Optional[Callable[[Dict], None]] = None) -> None:
    """Record termination attempts in the audit trail before stopping."""

    def make_handler(sig_name: str, should_stop: bool):
        def handler(signum, frame):  # pragma: no cover - signal timing
            if audit is not None:
                try:
                    audit({"event": "signal-received", "signal": sig_name, "pid": os.getpid()})
                except Exception:
                    pass
            if should_stop:
                on_stop(sig_name)

        return handler

    supported = {
        "SIGTERM": signal.SIGTERM,
        "SIGINT": signal.SIGINT,
        "SIGQUIT": getattr(signal, "SIGQUIT", None),
        "SIGHUP": getattr(signal, "SIGHUP", None),
    }
    for name, sig in supported.items():
        if sig is None:
            continue
        try:
            signal.signal(sig, make_handler(name, name != "SIGHUP"))
        except (ValueError, OSError):
            pass


# ------------------------------------------------------------------ sealing
def _candidate_targets() -> List[str]:
    targets: List[str] = []
    import glob as _glob

    from defentra.signing.keys import PACKAGE_TRUST_DIR

    targets.extend(sorted(_glob.glob(os.path.join(PACKAGE_TRUST_DIR, "*.pub"))))
    user_keys = os.path.join(ensure_state_dir(), "keys")
    targets.extend(sorted(_glob.glob(os.path.join(user_keys, "*.pub"))))
    agent_cfg = _state_path(AGENT_CONFIG_NAME)
    if os.path.exists(agent_cfg):
        targets.append(agent_cfg)
    return [t for t in targets if os.path.isfile(t)]


AGENT_CONFIG_NAME = "agent.json"


def seal() -> Dict:
    """Pin current hashes of trust anchors; returns the manifest."""
    entries = {}
    for path in _candidate_targets():
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        entries[path] = h.hexdigest()
    manifest = {"sealed_utc": time.time(), "entries": entries}
    raw = json.dumps(manifest, indent=2).encode("utf-8")
    path = _state_path(MANIFEST_NAME)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    return manifest


def verify() -> Dict:
    """Recompute hashes against the sealed manifest; reports any drift."""
    path = _state_path(MANIFEST_NAME)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"sealed": False, "ok": False, "changed": [], "missing": []}
    changed: List[str] = []
    missing: List[str] = []
    for target, expected in (manifest.get("entries") or {}).items():
        if not os.path.isfile(target):
            missing.append(target)
            continue
        h = hashlib.sha256()
        with open(target, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        if h.hexdigest() != expected:
            changed.append(target)
    return {
        "sealed": True,
        "ok": not changed and not missing,
        "changed": changed,
        "missing": missing,
    }
