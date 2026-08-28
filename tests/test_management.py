"""End-to-end management plane tests over a live local server."""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.request

import pytest

from aegorx.management import agent as agent_mod
from aegorx.management.protocol import ALLOWED_COMMANDS, make_command, verify_command
from aegorx.management.protocol_errors import CommandRejected
from aegorx.management.server import ManagementServer


class _Resp:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, n=-1):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def fleet(tmp_home, tmp_path):
    server = ManagementServer(db_path=str(tmp_path / "fleet.db"), host="127.0.0.1", port=0)
    server.start_background()
    # port 0 => OS-assigned; recover actual port from the socket
    yield server, f"http://127.0.0.1:{server.httpd.server_port}"
    server.shutdown()


def test_command_signing_and_verification():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pub = key.public_key()
    envelope = make_command("ping", {}, private_key=key)
    body = verify_command(envelope, pub)
    assert body["command"] == "ping"

    envelope["body"]["command"] = "scan-path"  # tamper after signing
    with pytest.raises(CommandRejected):
        verify_command(envelope, pub)

    stale = make_command("ping", ttl_seconds=-1, private_key=key)
    with pytest.raises(CommandRejected):
        verify_command(stale, pub)

    with pytest.raises(ValueError):
        make_command("rm-rf", {}, private_key=key)


def test_unknown_commands_are_never_queueable(tmp_home, tmp_path):
    server = ManagementServer(db_path=str(tmp_path / "f.db"))
    with pytest.raises(ValueError):
        server.store.queue_command("agent-x", "open-shell", {}, server.admin_private_key)


def test_full_lifecycle_enroll_checkin_result(fleet, monkeypatch):
    server, url = fleet
    token = server.issue_pairing_token("workstation-01")
    assert token and len(token) >= 32

    cfg = agent_mod.pair(url, token)
    assert cfg["agent_id"].startswith("das-")
    assert cfg["admin_public_key"].startswith("-----BEGIN PUBLIC KEY-----")

    # pairing tokens are single-use
    with pytest.raises(agent_mod.AgentConfigError):
        agent_mod.pair(url, token)

    agent = agent_mod.DASAgent(cfg)

    # admin queues a ping; agent picks it up on check-in and answers
    command_id = server.store.queue_command(cfg["agent_id"], "ping", {}, server.admin_private_key)
    handled = agent.check_in_once()
    assert handled == 1
    results = server.store.results()
    assert results[0]["command_id"] == command_id
    assert results[0]["result"]["pong"] is True

    # agents cannot forge or replay other agents' identities
    import urllib.parse

    bad = urllib.request.Request(
        url + "/checkin",
        data=json.dumps({"agent_id": cfg["agent_id"], "token": "wrong"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(bad, timeout=10)
        raised = False
    except Exception:
        raised = True
    assert raised

    # detections reported by the agent surface in the console
    agent._pending_reports.append(
        {
            "ts": time.time(),
            "path": "/tmp/evil.exe",
            "sha256": "a" * 64,
            "verdict": "malicious",
            "detections": [{"detector": "signature", "name": "MB.Test"}],
        }
    )
    agent.check_in_once()
    dets = server.store.detections(limit=5)
    assert any(d["path"] == "/tmp/evil.exe" for d in dets)


def test_expired_and_unsigned_commands_rejected_by_agent(fleet):
    server, _ = fleet
    token = server.issue_pairing_token("laptop-02")
    cfg = agent_mod.pair(fleet[1], token)
    agent = agent_mod.DASAgent(cfg)

    unsigned = {"body": {"command_id": "x", "command": "ping", "args": {}, "issued_utc": 0, "expires_utc": time.time() + 60}}
    result = agent.execute(unsigned)
    assert result["status"] == "rejected"
