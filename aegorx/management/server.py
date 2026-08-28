"""DAS management server: fleet registry, command queue, and result store.

A stdlib-only HTTP API. Agents authenticate with per-agent bearer tokens
issued during one-time token pairing; the server signs every queued command
with its Ed25519 key so agents can verify provenance offline.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple

from aegorx.management.protocol import (
    ALLOWED_COMMANDS,
    MAX_MESSAGE_BYTES,
    constant_time_eq,
    fingerprint,
    make_command,
    new_token,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    pubkey_pem TEXT NOT NULL,
    api_token_hash TEXT NOT NULL,
    enrolled_utc REAL NOT NULL,
    last_seen_utc REAL,
    last_ip TEXT,
    platform TEXT,
    das_version TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pairing (
    token_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_utc REAL NOT NULL,
    expires_utc REAL NOT NULL,
    used_utc REAL
);
CREATE TABLE IF NOT EXISTS commands (
    command_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    command TEXT NOT NULL,
    args_json TEXT NOT NULL,
    created_utc REAL NOT NULL,
    dispatched_utc REAL,
    result_utc REAL,
    status TEXT NOT NULL DEFAULT 'pending',
    result_json TEXT
);
CREATE TABLE IF NOT EXISTS detections (
    detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    seen_utc REAL NOT NULL,
    path TEXT,
    sha256 TEXT,
    verdict TEXT,
    detector TEXT,
    name TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);
"""


class FleetStore:
    def __init__(self, db_path: str):
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.RLock()
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- agents ---------------------------------------------------------
    def enroll(self, name: str, pubkey_pem: str) -> Tuple[str, str]:
        with self._lock:
            existing = self.conn.execute(
                "SELECT agent_id FROM agents WHERE name = ?", (name,)
            ).fetchone()
            if existing:
                raise ValueError(f"agent name already enrolled: {name}")
            agent_id = "das-" + new_token()[:8]
            api_token = new_token()
            self.conn.execute(
                "INSERT INTO agents (agent_id, name, pubkey_pem, api_token_hash, enrolled_utc)"
                " VALUES (?, ?, ?, ?, ?)",
                (agent_id, name, pubkey_pem, fingerprint(api_token), time.time()),
            )
            self.conn.commit()
            self.audit("server", "enroll", f"{name} -> {agent_id}")
            return agent_id, api_token

    def revoke(self, name: str) -> bool:
        """Revoke an agent's credentials; subsequent check-ins are rejected."""
        with self._lock:
            cur = self.conn.execute(
                "UPDATE agents SET revoked = 1 WHERE name = ? AND revoked = 0", (name,)
            )
            self.conn.commit()
        if cur.rowcount:
            self.audit("admin", "revoke", name)
        return bool(cur.rowcount)

    def issue_pairing_token(self, name: str, ttl_hours: float = 24.0) -> str:
        """Register a single-use pairing token bound to a device name.

        Tokens are persisted (hashed) so they survive server restarts and
        expire after ttl_hours. Only the raw token is shown once.
        """
        token = new_token()
        now = time.time()
        with self._lock:
            self.conn.execute(
                "INSERT INTO pairing (token_hash, name, created_utc, expires_utc)"
                " VALUES (?, ?, ?, ?)",
                (fingerprint(token), name, now, now + ttl_hours * 3600),
            )
            self.conn.commit()
        self.audit("admin", "pairing-issued", name)
        return token

    def consume_pairing(self, pairing_token: str) -> Optional[str]:
        """Single-use, expiring token -> bound device name."""
        digest = fingerprint(pairing_token)
        now = time.time()
        with self._lock:
            row = self.conn.execute(
                "SELECT name, expires_utc, used_utc FROM pairing WHERE token_hash = ?",
                (digest,),
            ).fetchone()
            if row is None or row["used_utc"] is not None or row["expires_utc"] < now:
                return None
            self.conn.execute(
                "UPDATE pairing SET used_utc = ? WHERE token_hash = ?", (now, digest)
            )
            self.conn.commit()
        return row["name"]

    def auth_agent(self, agent_id: str, api_token: str) -> Optional[sqlite3.Row]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        if row is None or row["revoked"]:
            return None
        if constant_time_eq(row["api_token_hash"], fingerprint(api_token)):
            return row
        return None

    def touch(self, agent_id: str, ip: str, platform: str, version: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE agents SET last_seen_utc = ?, last_ip = ?, platform = ?, das_version = ?"
                " WHERE agent_id = ?",
                (time.time(), ip, platform, version, agent_id),
            )
            self.conn.commit()

    def list_agents(self) -> List[Dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT agent_id, name, enrolled_utc, last_seen_utc, last_ip, platform,"
                " das_version FROM agents ORDER BY name"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_pubkey(self, agent_id: str) -> Optional[str]:
        with self._lock:
            row = self.conn.execute(
                "SELECT pubkey_pem FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        return row["pubkey_pem"] if row else None

    # -- commands -------------------------------------------------------
    def queue_command(self, agent_id: str, command: str, args: Dict, private_key) -> str:
        envelope = make_command(command, args, private_key=private_key)
        body = envelope["body"]
        with self._lock:
            self.conn.execute(
                "INSERT INTO commands (command_id, agent_id, command, args_json, created_utc)"
                " VALUES (?, ?, ?, ?, ?)",
                (body["command_id"], agent_id, command, json.dumps(envelope), time.time()),
            )
            self.conn.commit()
        self.audit("admin", "queue", f"{command} -> {agent_id}")
        return body["command_id"]

    def pending_for(self, agent_id: str) -> List[Dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT command_id, args_json FROM commands"
                " WHERE agent_id = ? AND status = 'pending' ORDER BY created_utc",
                (agent_id,),
            ).fetchall()
            if rows:
                self.conn.execute(
                    "UPDATE commands SET status='dispatched', dispatched_utc=?"
                    " WHERE agent_id=? AND status='pending'",
                    (time.time(), agent_id),
                )
                self.conn.commit()
        out = []
        for r in rows:
            try:
                out.append(json.loads(r["args_json"]))
            except json.JSONDecodeError:
                continue
        return out

    def store_result(self, agent_id: str, command_id: str, result: Dict) -> bool:
        with self._lock:
            cur = self.conn.execute(
                "UPDATE commands SET status='done', result_utc=?, result_json=?"
                " WHERE command_id=? AND agent_id=?",
                (time.time(), json.dumps(result)[:MAX_MESSAGE_BYTES], command_id, agent_id),
            )
            self.conn.commit()
            ok = cur.rowcount > 0
        if ok:
            self.audit(agent_id, "result", f"{command_id}: {str(result.get('summary', ''))[:200]}")
        return ok

    def results(self, agent_id: Optional[str] = None, limit: int = 50) -> List[Dict]:
        query = (
            "SELECT c.command_id, c.agent_id, a.name AS agent_name, c.command, c.status,"
            " c.created_utc, c.result_utc, c.result_json FROM commands c"
            " JOIN agents a ON a.agent_id = c.agent_id"
        )
        params: tuple = ()
        if agent_id:
            query += " WHERE c.agent_id = ?"
            params = (agent_id,)
        query += " ORDER BY c.created_utc DESC LIMIT ?"
        params = params + (limit,)
        with self._lock:
            rows = self.conn.execute(query, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                body = json.loads(d.pop("result_json") or "{}").get("body", {}).get("result")
                d["result"] = body
            except json.JSONDecodeError:
                d["result"] = None
            out.append(d)
        return out

    # -- detections / audit ---------------------------------------------
    def add_detections(self, agent_id: str, reports: List[Dict]) -> int:
        count = 0
        with self._lock:
            for rec in reports:
                if not isinstance(rec, dict):
                    continue
                self.conn.execute(
                    "INSERT INTO detections (agent_id, seen_utc, path, sha256, verdict, detector, name)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        agent_id,
                        float(rec.get("ts") or time.time()),
                        str(rec.get("path") or "")[:512],
                        str(rec.get("sha256") or ""),
                        str(rec.get("verdict") or ""),
                        str((rec.get("detections") or [{}])[0].get("detector") or "")
                        if isinstance(rec.get("detections"), list)
                        else "",
                        str(rec.get("reason") or "")[:256],
                    ),
                )
                count += 1
            self.conn.commit()
        return count

    def detections(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT d.*, a.name AS agent_name FROM detections d"
                " JOIN agents a ON a.agent_id = d.agent_id"
                " ORDER BY d.seen_utc DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def audit(self, actor: str, action: str, detail: str = "") -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO audit (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
                (time.time(), actor[:64], action[:64], detail[:400]),
            )
            self.conn.commit()


class ManagementServer:
    """HTTP(S) surface: /enroll, /checkin, /result. Bind to localhost by default.

    Provide tls_cert + tls_key (PEM) to serve HTTPS; agents pin the server
    certificate as their CA (`aegorx agent pair --ca-cert ...`).
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8477,
        db_path: Optional[str] = None,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
    ):
        from aegorx.utils import ensure_state_dir

        db_path = db_path or os.path.join(ensure_state_dir(), "fleet.db")
        self.store = FleetStore(db_path)
        self.host = host
        self.port = port
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.admin_private_key = self._load_or_create_admin_key()
        self.httpd = None

    def _load_or_create_admin_key(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from aegorx.utils import ensure_state_dir

        path = os.path.join(ensure_state_dir(), "management_admin.key")
        if os.path.exists(path):
            with open(path, "rb") as fh:
                key = serialization.load_pem_private_key(fh.read(), password=None)
            if isinstance(key, Ed25519PrivateKey):
                return key
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return key

    def admin_public_key_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return (
            self.admin_private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

    def issue_pairing_token(self, name: str, ttl_hours: float = 24.0) -> str:
        return self.store.issue_pairing_token(name, ttl_hours=ttl_hours)

    def _make_httpd(self) -> ThreadingHTTPServer:
        httpd = ThreadingHTTPServer((self.host, self.port), self._handler())
        httpd.daemon_threads = True
        if self.tls_cert and self.tls_key:
            import ssl

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(self.tls_cert, self.tls_key)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        return httpd

    # -- request handling -----------------------------------------------
    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):  # silence default stderr spam
                pass

            def _json(self, code: int, payload: Dict) -> None:
                data = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802 (stdlib interface)
                if self.path == "/health":
                    server.store.audit("anonymous", "health-check")
                    return self._json(200, {"status": "ok"})
                if self.path == "/admin.pub":
                    return self._json(200, {"public_key": server.admin_public_key_pem()})
                self._json(404, {"error": "not found"})

            def do_POST(self):  # noqa: N802
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except (ValueError, TypeError):
                    return self._json(400, {"error": "invalid Content-Length"})
                if length > MAX_MESSAGE_BYTES:
                    return self._json(413, {"error": "message too large"})
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    message = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    return self._json(400, {"error": "invalid json"})
                if not isinstance(message, dict):
                    return self._json(400, {"error": "invalid json"})

                if self.path == "/enroll":
                    return self._handle_enroll(message)
                if self.path == "/checkin":
                    return self._handle_checkin(message)
                if self.path == "/result":
                    return self._handle_result(message)
                self._json(404, {"error": "not found"})

            def _auth(self, message: Dict):
                agent_id = str(message.get("agent_id", ""))
                token = str(message.get("token", ""))
                if not agent_id or not token:
                    return None
                return server.store.auth_agent(agent_id, token)

            def _handle_enroll(self, message):
                pairing = str(message.get("pairing_token", ""))
                name = server.store.consume_pairing(pairing)
                if not name:
                    server.store.audit("anonymous", "enroll-rejected", "bad pairing token")
                    return self._json(403, {"error": "invalid, used, or expired pairing token"})
                pubkey = message.get("pubkey")
                if not isinstance(pubkey, str) or "BEGIN PUBLIC KEY" not in pubkey:
                    return self._json(400, {"error": "missing agent public key"})
                try:
                    agent_id, api_token = server.store.enroll(name, pubkey)
                except ValueError:
                    safe_name = name.replace("\n", "_").replace("\r", "")[:64]
                    server.store.audit("anonymous", "enroll-rejected", f"duplicate name {safe_name}")
                    return self._json(409, {"error": "device name already enrolled"})
                return self._json(
                    200,
                    {
                        "agent_id": agent_id,
                        "api_token": api_token,
                        "admin_public_key": server.admin_public_key_pem(),
                    },
                )

            def _handle_checkin(self, message):
                row = self._auth(message)
                if row is None:
                    server.store.audit("anonymous", "auth-failed", str(message.get("agent_id", ""))[:64])
                    return self._json(403, {"error": "authentication failed"})
                agent_id = row["agent_id"]
                server.store.touch(
                    agent_id,
                    self.client_address[0],
                    str(message.get("platform", ""))[:120],
                    str(message.get("version", ""))[:32],
                )
                reports = message.get("reports") if isinstance(message.get("reports"), list) else []
                if reports:
                    server.store.add_detections(agent_id, reports[-500:])
                pending = server.store.pending_for(agent_id)
                return self._json(200, {"commands": pending})

            def _handle_result(self, message):
                row = self._auth(message)
                if row is None:
                    return self._json(403, {"error": "authentication failed"})
                command_id = str(message.get("command_id", ""))
                result = message.get("result")
                if not command_id or not isinstance(result, dict):
                    return self._json(400, {"error": "missing command_id/result"})
                ok = server.store.store_result(row["agent_id"], command_id, {"body": {"result": result}})
                return self._json(200, {"accepted": ok})

        return Handler

    def serve_forever(self) -> None:
        self.httpd = self._make_httpd()
        self.httpd.serve_forever()

    def start_background(self) -> None:
        import threading as _t

        self.httpd = self._make_httpd()
        thread = _t.Thread(target=self.httpd.serve_forever, daemon=True, name="aegorx-mgmt")
        thread.start()

    @property
    def bound_port(self) -> int:
        return self.httpd.server_address[1] if self.httpd else self.port

    def shutdown(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
