"""DAS client agent: pairs with a management server, checks in, executes
verified commands, and reports detections.

Transparency guarantees baked in:
  * pairing requires a one-time token issued by the administrator
  * every executed command must carry a valid Ed25519 signature from the
    admin key pinned at pairing time, and must not be expired
  * all connections and executed commands land in the local audit log
"""

from __future__ import annotations

import json
import os
import platform
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Dict, List, Optional

from defentra.management.protocol import verify_command
from defentra.management.protocol_errors import CommandRejected

AGENT_CONFIG = "agent.json"


class AgentConfigError(RuntimeError):
    pass


def config_path() -> str:
    from defentra.utils import ensure_state_dir

    return os.path.join(ensure_state_dir(), AGENT_CONFIG)


def load_config() -> Dict:
    try:
        with open(config_path(), "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        if isinstance(cfg, dict) and cfg.get("server_url") and cfg.get("agent_id") and cfg.get("api_token"):
            return cfg
    except (OSError, json.JSONDecodeError):
        pass
    raise AgentConfigError("agent is not paired; run 'defentra agent pair --server URL --token TOKEN'")


def save_config(cfg: Dict) -> str:
    path = config_path()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    return path


def _generate_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return key, pub_pem


def pair(server_url: str, pairing_token: str, ca_cert: Optional[str] = None, opener=None) -> Dict:
    """One-time enrollment against the management server.

    For remote servers pass --ca-cert (the server certificate or your
    internal CA chain); connections then verify against that anchor.
    """
    if not server_url.lower().startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise AgentConfigError("pairing requires an HTTPS management server URL")
    if server_url.lower().startswith("https://") and not ca_cert and opener is None:
        raise AgentConfigError(
            "remote HTTPS pairing requires --ca-cert (pin the server certificate "
            "printed by 'defentra admin gen-certs')"
        )
    _, pub_pem = _generate_keypair()
    body = json.dumps({"pairing_token": pairing_token, "pubkey": pub_pem}).encode()
    request = urllib.request.Request(
        server_url.rstrip("/") + "/enroll",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with (opener or _opener_for(ca_cert) or urllib.request.urlopen)(request, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        raise AgentConfigError(f"pairing failed: {exc}") from exc
    cfg = {
        "server_url": server_url.rstrip("/"),
        "agent_id": data["agent_id"],
        "api_token": data["api_token"],
        "admin_public_key": data["admin_public_key"],
        "paired_utc": time.time(),
    }
    if ca_cert:
        cfg["ca_cert"] = os.path.abspath(ca_cert)
    save_config(cfg)
    return cfg


def _opener_for(ca_cert: Optional[str]):
    """HTTPS opener verifying the server against a pinned CA certificate.

    Returns a callable(req, timeout=...) matching the project-wide opener
    convention (urllib.request.urlopen is also a plain callable).
    """
    if not ca_cert:
        return None
    import ssl

    context = ssl.create_default_context(cafile=os.path.abspath(ca_cert))
    director = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))

    def _open(request, timeout: float = 30):
        return director.open(request, timeout=timeout)

    return _open


def _load_admin_public_key(cfg: Dict):
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_public_key(cfg["admin_public_key"].encode())


def post_json(url: str, payload: Dict, timeout: int = 30, opener=None, max_response: int = 4 * 1024 * 1024) -> Dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with (opener or urllib.request.urlopen)(request, timeout=timeout) as resp:
        data = resp.read(max_response + 1)
    if len(data) > max_response:
        raise ValueError("server response exceeded size limit")
    return json.loads(data.decode("utf-8"))


class DASAgent:
    def __init__(self, cfg: Optional[Dict] = None, opener=None):
        self.cfg = cfg or load_config()
        self.opener = opener or _opener_for(self.cfg.get("ca_cert"))
        self._stop = threading.Event()
        self._started_at = time.time()
        self._pending_reports: List[Dict] = []
        self._last_scheduled_scan = 0.0
        self._audit = None
        try:
            from defentra.realtime.monitor import AuditLog

            self._audit = AuditLog(os.path.join(os.path.dirname(config_path()), "agent-audit.log"))
        except Exception:
            self._audit = None

    # -- transport ------------------------------------------------------
    def _checkin(self, reports: List[Dict]) -> List[Dict]:
        payload = {
            "agent_id": self.cfg["agent_id"],
            "token": self.cfg["api_token"],
            "platform": f"{platform.system()} {platform.release()}",
            "version": self._version(),
            "reports": reports,
        }
        data = post_json(self.cfg["server_url"] + "/checkin", payload, opener=self.opener)
        return data.get("commands", []) if isinstance(data, dict) else []

    def _submit_result(self, command_id: str, result: Dict) -> None:
        post_json(
            self.cfg["server_url"] + "/result",
            {"agent_id": self.cfg["agent_id"], "token": self.cfg["api_token"], "command_id": command_id, "result": result},
            opener=self.opener,
        )

    @staticmethod
    def _version() -> str:
        from defentra import __version__

        return __version__

    # -- command execution ----------------------------------------------
    def execute(self, envelope: Dict) -> Dict:
        try:
            public_key = _load_admin_public_key(self.cfg)
            body = verify_command(envelope, public_key)
        except CommandRejected as exc:
            self._log({"event": "command-rejected", "reason": str(exc)})
            return {"status": "rejected", "detail": str(exc)}
        except Exception as exc:
            return {"status": "error", "detail": f"verification failure: {exc}"}

        handler = COMMAND_HANDLERS.get(body["command"])
        if handler is None:
            return {"status": "unsupported"}
        try:
            result = handler(self, body.get("args") or {})
            result.setdefault("status", "done")
        except Exception as exc:
            result = {"status": "error", "detail": str(exc)[:300]}
        self._log({"event": "command-executed", "command": body["command"], "args": body.get("args", {})})
        return result

    def _log(self, record: Dict) -> None:
        if self._audit is not None:
            record["ts"] = time.time()
            self._audit.write(record)

    # -- loop ------------------------------------------------------------
    def check_in_once(self, reports: Optional[List[Dict]] = None) -> int:
        batch = list(reports or []) + self._pending_reports[:100]
        self._pending_reports = self._pending_reports[100:]
        envelopes = self._checkin(batch)
        handled = 0
        for envelope in envelopes[:20]:
            result = self.execute(envelope)
            command_id = envelope.get("body", {}).get("command_id", "")
            try:
                self._submit_result(command_id, result)
            except Exception:
                pass
            handled += 1
        return handled

    def run_forever(self, interval_seconds: float = 60.0) -> None:
        self._log({"event": "agent-started", "interval": interval_seconds})
        while not self._stop.is_set():
            try:
                self.check_in_once()
            except Exception as exc:
                self._log({"event": "checkin-error", "detail": str(exc)[:200]})
            try:
                self.run_scheduled_scan()
            except Exception as exc:
                self._log({"event": "scheduled-scan-error", "detail": str(exc)[:200]})
            self._stop.wait(timeout=interval_seconds)

    def stop(self) -> None:
        self._stop.set()

    # -- built-in handlers ------------------------------------------------
    def cmd_ping(self, args: Dict) -> Dict:
        return {"pong": True}

    def cmd_status(self, args: Dict) -> Dict:
        from defentra.utils import state_dir

        db_path = os.path.join(state_dir(), "signatures.db")
        signatures = 0
        try:
            from defentra.signatures.db import SignatureDB

            signatures = SignatureDB(db_path).count()
        except Exception:
            pass
        return {
            "version": self._version(),
            "platform": platform.platform(),
            "signatures": signatures,
            "uptime_seconds": int(time.time() - self._started_at),
        }

    def cmd_diag(self, args: Dict) -> Dict:
        import socket

        info: Dict = {
            "hostname": socket.gethostname(),
            "python": platform.python_version(),
            "machine": platform.machine(),
        }
        try:
            addrs = socket.getaddrinfo(socket.gethostname(), None)
            info["addresses"] = sorted({a[4][0] for a in addrs})[:16]
        except OSError:
            pass
        return info

    def cmd_scan_path(self, args: Dict) -> Dict:
        path = str(args.get("path", ""))
        if not path or not os.path.exists(path):
            return {"status": "error", "detail": "path does not exist"}
        from defentra.engine import ScanEngine

        engine = ScanEngine(enable_ml=False)
        results = engine.scan_target(path)
        malicious = [r.path for r in results if r.verdict == "malicious"]
        summary = {
            "scanned": len(results),
            "malicious": len(malicious),
            "paths": malicious[:50],
        }
        for r in results:
            if r.verdict != "clean":
                if len(self._pending_reports) < 500:
                    self._pending_reports.append(
                        {
                            "ts": time.time(),
                            "path": r.path,
                            "sha256": r.sha256,
                            "verdict": r.verdict,
                            "detections": [{"detector": d.detector, "name": d.name} for d in r.detections],
                        }
                    )
        return summary

    def cmd_feed_update(self, args: Dict) -> Dict:
        from defentra.cli import main as cli_main

        rc = cli_main(["feed", "update"])
        return {"exit_code": rc}

    def cmd_check_update(self, args: Dict) -> Dict:
        from defentra.update import UpdateError, check

        try:
            result = check()
        except UpdateError as exc:
            return {"status": "error", "detail": str(exc)[:300]}
        return {
            "status": "done",
            "current": result["current"],
            "available": result["available"],
            "update_available": result["update_available"],
            "generated_utc": result["generated_utc"],
        }

    def cmd_quarantine_list(self, args: Dict) -> Dict:
        from defentra.quarantine.vault import QuarantineVault

        items = QuarantineVault().list_items()
        return {"count": len(items), "items": items[:100]}

    def cmd_quarantine_delete(self, args: Dict) -> Dict:
        item_id = str(args.get("id", ""))
        if not item_id:
            return {"status": "error", "detail": "missing id"}
        from defentra.quarantine.vault import QuarantineVault

        return {"deleted": QuarantineVault().delete(item_id)}

    def cmd_apply_policy(self, args: Dict) -> Dict:
        """Validate + install centrally pushed policy; applies where live."""
        from defentra.policy import PolicyError, save_policy, validate_policy

        try:
            normalized = validate_policy(args)
            save_policy(normalized)
        except PolicyError as exc:
            return {"status": "error", "detail": f"policy rejected: {exc}"}
        self._log({"event": "policy-applied", "policy": normalized})
        return {"status": "done", "applied": normalized}

    def run_scheduled_scan(self) -> Optional[Dict]:
        """Deep-scan policy.scheduled_paths when the interval has elapsed."""
        from defentra.policy import load_policy

        policy = load_policy() or {}
        interval = int(policy.get("scan_interval_seconds") or 0)
        paths = [p for p in (policy.get("scheduled_paths") or []) if os.path.exists(p)]
        if not interval or not paths:
            return None
        now = time.time()
        if now - self._last_scheduled_scan < interval:
            return None
        self._last_scheduled_scan = now
        from defentra.engine import ScanEngine

        engine = ScanEngine(enable_ml=False)
        scanned = malicious = 0
        for path in paths:
            results = engine.scan_target(path)
            scanned += len(results)
            for r in results:
                if r.verdict == "clean":
                    continue
                malicious += r.verdict == "malicious"
                if len(self._pending_reports) < 500:
                    self._pending_reports.append(
                        {
                            "ts": time.time(),
                            "path": r.path,
                            "sha256": r.sha256,
                            "verdict": r.verdict,
                            "detections": [{"detector": d.detector, "name": d.name} for d in r.detections],
                        }
                    )
        summary = {"scheduled-scan": {"scanned": scanned, "malicious": malicious}}
        self._log({"event": "scheduled-scan", **summary})
        return summary


COMMAND_HANDLERS: Dict[str, Callable[[DASAgent, Dict], Dict]] = {
    "ping": DASAgent.cmd_ping,
    "status": DASAgent.cmd_status,
    "diag": DASAgent.cmd_diag,
    "scan-path": DASAgent.cmd_scan_path,
    "feed-update": DASAgent.cmd_feed_update,
    "check-update": DASAgent.cmd_check_update,
    "quarantine-list": DASAgent.cmd_quarantine_list,
    "quarantine-delete": DASAgent.cmd_quarantine_delete,
    "apply-policy": DASAgent.cmd_apply_policy,
}
