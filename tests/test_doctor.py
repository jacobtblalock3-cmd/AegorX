from __future__ import annotations

import json
import os
import time

import pytest

from aegorx.doctor import (
    STATUS_FAIL,
    STATUS_OK,
    STATUS_WARN,
    render_text,
    run_doctor,
)


def test_doctor_runs_all_checks_without_crashing(tmp_home):
    reports = run_doctor()
    names = [r["check"] for r in reports]
    assert "platform" in names and "trust-keys" in names and "signatures" in names
    for r in reports:
        assert r["status"] in (STATUS_OK, STATUS_WARN, STATUS_FAIL)
        assert isinstance(r["detail"], str) and r["detail"]


def test_doctor_signature_db_states(tmp_home):
    def sig():
        return next(r for r in run_doctor() if r["check"] == "signatures")

    # fresh state dir auto-seeds builtins -> usable
    assert sig()["status"] == STATUS_OK

    # corrupt database file -> FAIL, not crash
    from aegorx.signatures.db import SignatureDB

    SignatureDB(os.path.join(tmp_home, "signatures.db")).conn.close()
    with open(os.path.join(tmp_home, "signatures.db"), "wb") as fh:
        fh.write(b"not a database at all")
    report = sig()
    assert report["status"] == STATUS_FAIL


def test_doctor_feed_freshness_transitions(tmp_home):
    from aegorx.signing.feed import parse_utc

    state = os.path.join(tmp_home, "feed_state.json")

    def set_state(days_ago: float):
        generated = time.time() - days_ago * 86400
        iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(generated))
        parse_utc(iso)  # must be parseable by the real parser
        with open(state, "w") as fh:
            json.dump({"last_generated_utc": iso}, fh)

    def freshness():
        return next(r for r in run_doctor() if r["check"] == "feed-freshness")

    assert "no feed ever applied" in freshness()["detail"]
    set_state(1.0)
    assert freshness()["status"] == STATUS_OK
    set_state(45.0)
    assert freshness()["status"] == STATUS_WARN


def test_doctor_agent_pairing_states(tmp_home):
    def pairing():
        return next(r for r in run_doctor() if r["check"] == "agent-pairing")

    assert pairing()["status"] == STATUS_WARN  # unpaired by default

    os.makedirs(tmp_home, exist_ok=True)
    with open(os.path.join(tmp_home, "agent.json"), "w") as fh:
        json.dump(
            {
                "server_url": "https://console.example",
                "agent_id": "das-x",
                "api_token": "t",
                "admin_public_key": "x",
            },
            fh,
        )
    paired = pairing()
    assert paired["status"] == STATUS_OK
    assert "das-x" in paired["detail"]


def test_doctor_audit_chain_detects_tamper(tmp_home):
    log = os.path.join(tmp_home, "realtime.log")
    from aegorx.realtime.monitor import AuditLog

    audit = AuditLog(log)
    audit.write({"event": "one"})
    audit.write({"event": "two"})
    lines = open(log).read().splitlines()
    record = json.loads(lines[0])
    record["event"] = "tampered"
    lines[0] = json.dumps(record)
    with open(log, "w") as fh:
        fh.write("\n".join(lines) + "\n")

    report = next(r for r in run_doctor() if r["check"] == "audit-chain")
    assert report["status"] == STATUS_FAIL


def test_render_text_marks_and_exit_semantics():
    fake = [
        {"check": "a", "status": STATUS_OK, "detail": "fine"},
        {"check": "b", "status": STATUS_WARN, "detail": "meh"},
        {"check": "c", "status": STATUS_FAIL, "detail": "bad"},
    ]
    text = render_text(fake)
    assert "[ OK ] a" in text and "[WARN] b" in text and "[FAIL] c" in text
    assert "1 failure(s)" in text
