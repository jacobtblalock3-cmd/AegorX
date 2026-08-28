from __future__ import annotations

import json
import os
import time

import pytest

from aegorx import shield


def test_heartbeat_write_and_liveness(tmp_home):
    hb = shield.Heartbeat(seconds=5)
    hb.start()
    try:
        status = shield.liveness(max_age_seconds=90)
        assert status["healthy"] is True
        assert status["pid"] == os.getpid()
        assert status["process_alive"] is True
    finally:
        hb.stop()


def test_liveness_reports_missing_heartbeat(tmp_home):
    status = shield.liveness()
    assert status["healthy"] is False and status["reason"] == "no heartbeat"


def test_liveness_detects_stale_or_dead(tmp_home):
    home = os.environ["AEGORX_HOME"]
    os.makedirs(home, exist_ok=True)
    stale_path = os.path.join(home, "heartbeat.json")
    with open(stale_path, "w") as fh:
        json.dump({"pid": os.getpid(), "ts": time.time() - 9999}, fh)
    status = shield.liveness(max_age_seconds=90)
    assert status["healthy"] is False


def test_seal_and_verify_detects_tampering(tmp_home):
    key_dir = os.path.join(os.environ["AEGORX_HOME"], "keys")
    os.makedirs(key_dir)
    target = os.path.join(key_dir, "corp.pub")
    with open(target, "w") as fh:
        fh.write("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")

    shield.seal()
    report = shield.verify()
    assert report["ok"] is True

    with open(target, "a") as fh:
        fh.write("tampered\n")
    report = shield.verify()
    assert report["ok"] is False
    assert target in report["changed"]


def test_verify_flags_deleted_anchor(tmp_home):
    key_dir = os.path.join(os.environ["AEGORX_HOME"], "keys")
    os.makedirs(key_dir)
    target = os.path.join(key_dir, "gone.pub")
    open(target, "w").write("data")
    shield.seal()
    os.remove(target)
    report = shield.verify()
    assert report["ok"] is False and report["missing"] == [target]


def test_unsealed_state_is_reported(tmp_home):
    report = shield.verify()
    assert report["sealed"] is False and report["ok"] is False


def test_cli_watchdog_and_protect(tmp_home, capsys):
    from aegorx.cli import main as cli_main

    # no heartbeat yet -> unhealthy; --no-restart keeps it from shelling out
    rc = cli_main(["watchdog", "--no-restart"])
    assert rc == 2
    out = capsys.readouterr().out + capsys.readouterr().err

    hb = shield.Heartbeat(seconds=5)
    hb.start()
    try:
        rc = cli_main(["watchdog", "--no-restart"])
        assert rc == 0

        assert cli_main(["protect", "seal"]) == 0
        assert cli_main(["protect", "check"]) == 0
        capsys.readouterr()

        keys_dir = os.path.join(os.environ["AEGORX_HOME"], "keys")
        os.makedirs(keys_dir, exist_ok=True)
        anchor = os.path.join(keys_dir, "corp.pub")
        with open(anchor, "w") as fh:
            fh.write("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
        assert cli_main(["protect", "seal"]) == 0
        with open(anchor, "a") as fh:
            fh.write("x")
        rc = cli_main(["protect", "check"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "TAMPERED" in err or "MISSING" in err
    finally:
        hb.stop()
