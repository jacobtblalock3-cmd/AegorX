import json
import os

import pytest

from defentra.cli import main as cli_main
from defentra.signing.feed import new_feed, save_feed
from defentra.signing.keys import generate_keypair, trusted_key_paths


@pytest.fixture
def env(tmp_home):
    keydir = os.path.join(tmp_home, "pub")
    private_path, public_path = generate_keypair(keydir)
    return {
        "home": tmp_home,
        "private": private_path,
        "public": public_path,
        "feed": str(os.path.join(tmp_home, "feed.json")),
        "signed": str(os.path.join(tmp_home, "feed.json.signed.json")),
    }


def _make_feed(path):
    save_feed(new_feed([{"sha256": "c" * 64, "name": "Win32.CLIFeed", "severity": 7}]), path)


def test_keys_generate_and_list(env, capsys):
    assert cli_main(["keys", "generate", "--out", os.path.join(env["home"], "gen")]) == 0
    assert cli_main(["keys", "list"]) == 0
    out = capsys.readouterr().out
    assert "package" in out


def test_keys_trust_rejects_non_key(env, capsys):
    bad = os.path.join(env["home"], "notakey.pem")
    open(bad, "w").write("garbage")
    assert cli_main(["keys", "trust", bad]) == 3


def test_feed_sign_verify_update_flow(env, capsys, tmp_path):
    _make_feed(env["feed"])
    assert cli_main(["feed", "sign", env["feed"], "--key", env["private"]]) == 0
    assert os.path.exists(env["signed"])

    assert cli_main(["keys", "trust", env["public"]]) == 0
    assert cli_main(["feed", "verify", env["signed"]]) == 0
    out = capsys.readouterr().out
    assert "valid (key" in out and "1 signature(s)" in out

    assert cli_main(["feed", "update", "--file", env["signed"]]) == 0
    out = capsys.readouterr().out
    assert "applied 1 new signature(s)" in out

    from defentra.signatures.db import SignatureDB

    db = SignatureDB(None)
    assert db.lookup(sha256="c" * 64)["source"] == "feed"

    assert cli_main(["feed", "update", "--file", env["signed"]]) == 0
    out = capsys.readouterr().out
    assert "not newer" in out


def test_feed_verify_rejects_unsigned(env, capsys):
    _make_feed(env["feed"])
    assert cli_main(["feed", "verify", env["feed"]]) == 3
    err = capsys.readouterr().err
    assert "INVALID" in err


def test_feed_sign_missing_file(env):
    assert cli_main(["feed", "sign", "/nonexistent/feed.json", "--key", env["private"]]) == 3


def test_feed_verify_tampered(env, capsys):
    _make_feed(env["feed"])
    cli_main(["feed", "sign", env["feed"], "--key", env["private"]])
    doc = json.load(open(env["signed"]))
    doc["signatures"][0]["name"] = "Evil.Tampered"
    save_feed(doc, env["signed"])
    assert cli_main(["feed", "verify", env["signed"]]) == 3


def test_trust_user_key_then_verify(env, capsys):
    _make_feed(env["feed"])
    cli_main(["feed", "sign", env["feed"], "--key", env["private"]])
    fresh_home = {"DEFENTRA_HOME": os.path.join(env["home"], "fresh")}
    old = os.environ.get("DEFENTRA_HOME")
    os.environ["DEFENTRA_HOME"] = fresh_home["DEFENTRA_HOME"]
    try:
        assert cli_main(["feed", "verify", env["signed"]]) == 3
        assert cli_main(["keys", "trust", env["public"]]) == 0
        assert cli_main(["feed", "verify", env["signed"]]) == 0
    finally:
        if old is None:
            del os.environ["DEFENTRA_HOME"]
        else:
            os.environ["DEFENTRA_HOME"] = old
