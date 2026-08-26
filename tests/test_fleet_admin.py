"""Fleet administration loop: TLS enrollment, pairing lifecycle, revocation,
central policy push, and scheduled scans — exercised end to end in-process."""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.request

import pytest

from defentra.management import agent as agent_mod
from defentra.management.certs import generate_server_cert
from defentra.management.protocol import make_command
from defentra.management.server import ManagementServer
from defentra.policy import load_policy, validate_policy


@pytest.fixture
def fleet(tmp_path, tmp_home):
    cert_path, key_path = generate_server_cert(str(tmp_path / "certs"), hostname="fleet.test")
    server = ManagementServer(
        db_path=str(tmp_path / "fleet.db"),
        host="127.0.0.1",
        port=0,
        tls_cert=cert_path,
        tls_key=key_path,
    )
    server.start_background()
    yield {
        "server": server,
        "base_url": f"https://127.0.0.1:{server.bound_port}",
        "ca_cert": cert_path,
        "tmp": tmp_path,
    }
    server.shutdown()


def _ca_opener(ca_cert: str):
    return agent_mod._opener_for(ca_cert)


def _enrolled_agent(fleet, name="laptop-1"):
    token = fleet["server"].issue_pairing_token(name)
    cfg = agent_mod.pair(
        fleet["base_url"], token, ca_cert=fleet["ca_cert"], opener=_ca_opener(fleet["ca_cert"])
    )
    agent = agent_mod.DASAgent(cfg=cfg, opener=_ca_opener(fleet["ca_cert"]))
    return cfg, agent


# --- TLS enrollment ----------------------------------------------------------


def test_tls_pair_and_checkin_end_to_end(fleet):
    cfg, agent = _enrolled_agent(fleet)
    assert cfg["agent_id"].startswith("das-")
    assert cfg["ca_cert"].endswith("server.crt")

    handled = agent.check_in_once()  # authenticates over pinned TLS
    assert handled == 0
    agents = fleet["server"].store.list_agents()
    assert agents and agents[0]["name"] == "laptop-1"
    assert agents[0]["last_seen_utc"] is not None


def test_https_without_ca_pin_is_rejected_by_client_guard(fleet):
    with pytest.raises(agent_mod.AgentConfigError, match="ca-cert"):
        agent_mod.pair(fleet["base_url"], "any-token")


def test_wrong_ca_fails_handshake(fleet, tmp_path):
    other_cert, _ = generate_server_cert(str(tmp_path / "other"), hostname="other.test")
    with pytest.raises(agent_mod.AgentConfigError):
        agent_mod.pair(fleet["base_url"], "t", ca_cert=other_cert, opener=_ca_opener(other_cert))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_gen_certs_outputs_key_with_private_perms(tmp_path):
    cert, key = generate_server_cert(str(tmp_path / "c"), hostname="x.test")
    assert os.path.exists(cert)
    mode = os.stat(key).st_mode & 0o777
    assert mode == 0o600, f"private key must be 0600, got {oct(mode)}"


# --- pairing lifecycle --------------------------------------------------------


def test_pairing_token_single_use_and_persistent_across_restart(fleet, tmp_path):
    server = fleet["server"]
    token = server.issue_pairing_token("restart-survivor")

    # simulate a server restart on the same database: fresh process state,
    # persisted tokens must still work while in-memory ones would be lost.
    revived = ManagementServer(db_path=str(tmp_path / "fleet.db"), host="127.0.0.1", port=0)
    name = revived.store.consume_pairing(token)
    assert name == "restart-survivor"
    # second consume fails: single use
    assert revived.store.consume_pairing(token) is None


def test_expired_pairing_token_rejected(fleet, tmp_path):
    server = ManagementServer(db_path=str(tmp_path / "fleet.db"), host="127.0.0.1", port=0)
    token = server.issue_pairing_token("old-device", ttl_hours=-1)  # already expired
    assert server.store.consume_pairing(token) is None


def test_revoked_agent_cannot_check_in(fleet):
    _, agent = _enrolled_agent(fleet, name="fired-1")
    assert fleet["server"].store.revoke("fired-1") is True
    assert fleet["server"].store.revoke("fired-1") is False  # idempotent

    with pytest.raises(Exception):
        agent.check_in_once()


# --- central policy push -------------------------------------------------------


def test_apply_policy_command_end_to_end(fleet, tmp_home, monkeypatch):
    from defentra.engine import ScanEngine

    _, agent = _enrolled_agent(fleet)

    policy_doc = {
        "exclusions": ["/media/archive/*"],
        "scan_interval_seconds": 3600,
        "scheduled_paths": [str(fleet["tmp"])],
        "backend": "inotify",
        "suspicious_probability": 0.30,
    }
    envelope = make_command(
        "apply-policy", policy_doc, private_key=fleet["server"].admin_private_key
    )
    result = agent.execute(envelope)
    assert result["status"] == "done", result

    stored = load_policy()
    assert stored["exclusions"] == ["/media/archive/*"]
    assert stored["scan_interval_seconds"] == 3600

    # a NEW engine instance must honor pushed thresholds
    engine = ScanEngine(enable_ml=False)
    assert engine.suspicious_probability == 0.30

    # tampered/invalid policies are refused by the agent even when signed
    bad = make_command("apply-policy", {"scan_interval_seconds": -5}, private_key=fleet["server"].admin_private_key)
    result = agent.execute(bad)
    assert result["status"] == "error" and "rejected" in result["detail"]


def test_policy_validation_rejects_unknown_fields():
    with pytest.raises(ValueError, match="unknown policy"):
        validate_policy({"nukes": 1})


def test_monitor_merges_policy_exclusions(tmp_home):
    if not sys.platform.startswith("linux"):
        pytest.skip("backend selection requires Linux")
    from defentra.policy import save_policy
    from defentra.realtime.monitor import RealTimeMonitor
    from defentra.engine import ScanEngine

    save_policy({"exclusions": ["/opt/trusted/*"], "backend": "inotify"})
    monitor = RealTimeMonitor(ScanEngine(enable_ml=False), ["/tmp"])
    try:
        assert monitor.filter.excluded("/opt/trusted/sample.bin")
        assert not monitor.filter.excluded("/home/user/document.txt")
    finally:
        monitor.backend.stop()
        monitor.pool.shutdown(wait=False)


def test_scheduled_scan_honors_interval_and_reports(fleet, tmp_home, tmp_path):
    _, agent = _enrolled_agent(fleet, name="scanner-1")

    sample = tmp_path / "deep" / "eicar.com"
    sample.parent.mkdir(parents=True)
    sample.write_text("dummy-content-not-eicar")
    from conftest import EICAR

    sample.write_bytes(EICAR)

    agent.execute(
        make_command(
            "apply-policy",
            {"scan_interval_seconds": 0, "scheduled_paths": []},
            private_key=fleet["server"].admin_private_key,
        )
    )  # clears any prior policy

    doc = {"scan_interval_seconds": 100000, "scheduled_paths": [str(sample.parent)]}
    agent.execute(make_command("apply-policy", doc, private_key=fleet["server"].admin_private_key))

    first = agent.run_scheduled_scan()
    assert first and first["scheduled-scan"]["malicious"] == 1
    assert any(r.get("verdict") == "malicious" for r in agent._pending_reports)

    # interval not elapsed -> no second scan
    assert agent.run_scheduled_scan() is None


def test_unsigned_policy_command_rejected(fleet):
    from defentra.management.protocol_errors import CommandRejected

    _, agent = _enrolled_agent(fleet, name="paranoid-1")
    envelope = {"body": {"command_id": "x", "command": "apply-policy", "args": {}, "issued_utc": 0, "expires_utc": 9e18}}
    result = agent.execute(envelope)
    assert result["status"] == "rejected"


# --- admin CLI surface ----------------------------------------------------------


def test_admin_cli_gen_certs_and_revoke_flow(tmp_path, tmp_home, capsys):
    from defentra.cli import main as cli_main

    rc = cli_main(["admin", "gen-certs", "--out", str(tmp_path / "tls"), "--hostname", "fleet.test"])
    assert rc == 0
    assert os.path.exists(tmp_path / "tls" / "server.crt")

    server = ManagementServer(db_path=str(tmp_path / "fleet.db"), host="127.0.0.1", port=0)
    token = server.issue_pairing_token("cli-device")
    server.store.enroll("cli-device", "-----BEGIN PUBLIC KEY-----\nX\n")
    os.environ.setdefault("DEFENTRA_HOME", os.environ["DEFENTRA_HOME"])  # keep tmp_home
    import shutil
    shutil.copy(str(tmp_path / "fleet.db"), os.path.join(os.environ["DEFENTRA_HOME"], "fleet.db"))
    rc = cli_main(["admin", "revoke", "cli-device"])
    assert rc == 0


# --- stale-device filter -----------------------------------------------------


def test_stale_agents_filter_semantics(fleet):
    import time as _t

    _cfg, agent = _enrolled_agent(fleet, name="fresh-box")
    agent.check_in_once()

    store = fleet["server"].store
    # backdate the only device far into the past
    old_ts = _t.time() - 48 * 3600
    with store._lock:
        store.conn.execute("UPDATE agents SET last_seen_utc = ?", (old_ts,))
        store.conn.commit()

    agents = store.list_agents()
    assert all((_t.time() - a["last_seen_utc"]) > 24 * 3600 for a in agents)

    # never-seen devices must also count as stale
    token = fleet["server"].issue_pairing_token("ghost-box")
    ghost_cfg = agent_mod.pair(
        fleet["base_url"], token, ca_cert=fleet["ca_cert"], opener=_ca_opener(fleet["ca_cert"])
    )
    with store._lock:
        row = store.conn.execute(
            "SELECT last_seen_utc FROM agents WHERE agent_id = ?", (ghost_cfg["agent_id"],)
        ).fetchone()
    assert row is not None and row["last_seen_utc"] is None
