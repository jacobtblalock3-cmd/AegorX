from __future__ import annotations

import json
import os
import time

import pytest

from defentra.engine import ScanEngine
from defentra.rules_store import RuleStoreError, current_rules, install_rules, rules_dir
from defentra.signing.feed import FeedError, new_feed, sanitize_rule_entries

GOOD_RULE = """
rule Feed_Test_Family_Generic
{
    meta:
        description = "Feed-delivered test rule"
        severity = 9
    strings:
        $marker = "DEFENTRA-FEED-RULE-MARKER-9f2c"
    condition:
        $marker
}
"""

BROKEN_RULE = "rule Broken { condition: $never_defined }"


def _entry(source=GOOD_RULE, name="Feed.Test", sha256=None, severity=8):
    import hashlib

    return {
        "name": name,
        "source": source,
        "sha256": sha256 or hashlib.sha256(source.encode()).hexdigest(),
        "severity": severity,
    }


def test_sanitize_normalizes_and_rejects_mismatch(tmp_home):
    entries = sanitize_rule_entries([_entry()])
    assert entries[0]["severity"] == 8
    assert len(entries[0]["sha256"]) == 64

    with pytest.raises(FeedError, match="does not match"):
        sanitize_rule_entries([_entry(sha256="0" * 64)])
    with pytest.raises(FeedError, match="empty source"):
        sanitize_rule_entries([_entry(source="   ")])
    with pytest.raises(FeedError, match="invalid severity"):
        sanitize_rule_entries([_entry(severity="high")])
    assert sanitize_rule_entries(None) == []


def test_new_feed_embeds_rules_and_signing_covers_them(tmp_path):
    from defentra.signing.feed import sign_document, verify_document
    from defentra.signing.keys import generate_keypair

    keypair = generate_keypair(str(tmp_path / "kp"))
    doc = new_feed([], rules=[_entry()], ttl_hours=24)
    signed = sign_document(doc, keypair[0])

    # tampering with a rule body invalidates the whole feed signature
    signed["rules"][0]["source"] = GOOD_RULE + "\n// evil"
    with pytest.raises(FeedError, match="did not verify"):
        verify_document(signed, extra_trusted_keys=[keypair[1]])


def test_install_rules_writes_files_and_manifest(tmp_home):
    summary = install_rules([_entry()])
    assert summary["installed"] == 1 and summary["compiled"] in (True, None)
    files = [f for f in os.listdir(rules_dir()) if f.endswith(".yar")]
    assert len(files) == 1
    manifest = current_rules()
    assert "Feed.Test" in manifest


def test_install_rules_full_sync_removes_stale(tmp_home):
    install_rules([_entry(name="Feed.Old")])
    old_file = [f for f in os.listdir(rules_dir()) if f.endswith(".yar")]
    assert len(old_file) == 1

    new_source = GOOD_RULE.replace("9f2c", "aa01")
    summary = install_rules([_entry(source=new_source, name="Feed.New")])
    assert summary["removed"] == 1 and summary["installed"] == 1
    assert set(current_rules()) == {"Feed.New"}


def test_install_rejects_uncompilable_set_atomically(tmp_home):
    pytest.importorskip("yara")
    install_rules([_entry(name="Feed.KnownGood")])
    before_files = sorted(os.listdir(rules_dir()))

    with pytest.raises(RuleStoreError, match="failed to compile"):
        install_rules([_entry(name="Feed.Broken", source=BROKEN_RULE)])

    # active set untouched
    assert sorted(os.listdir(rules_dir())) == before_files
    assert set(current_rules()) == {"Feed.KnownGood"}


def test_engine_detects_sample_via_feed_delivered_rule(tmp_home, tmp_path):
    sample = tmp_path / "implant.bin"
    sample.write_bytes(b"benign-padding" + b"DEFENTRA-FEED-RULE-MARKER-9f2c" + b"payload")

    pre = ScanEngine(rules_dirs=[], enable_ml=False)
    assert pre.scan_file(str(sample)).verdict == "clean"

    install_rules([_entry()])
    post = ScanEngine(rules_dirs=[], enable_ml=False)
    result = post.scan_file(str(sample))
    if not post.yara.available:
        pytest.skip("yara unavailable")
    assert result.verdict == "malicious"
    assert any(d.detector == "yara" for d in result.detections)


def test_yara_scanner_hot_reload(tmp_home):
    pytest.importorskip("yara")
    from defentra.scanner.yara_scanner import YaraScanner

    live_dir = rules_dir()
    scanner = YaraScanner(rules_dirs=[live_dir])
    assert scanner.available is False or scanner.rule_count == 0

    path = os.path.join(live_dir, "hot.yar")
    with open(path, "w") as fh:
        fh.write(GOOD_RULE)
    os.utime(path, (time.time() + 5, time.time() + 5))
    assert scanner.maybe_reload() is True
    assert scanner.rule_count == 1
    matches = scanner.rules.match(data=b"x DEFENTRA-FEED-RULE-MARKER-9f2c y")
    assert any(m.rule == "Feed_Test_Family_Generic" for m in matches)


def test_feed_update_cli_installs_rules(tmp_home, tmp_path, capsys):
    from defentra.cli import main as cli_main
    from defentra.signing.feed import new_feed, save_feed, sign_document
    from defentra.signing.keys import generate_keypair, trust_public_key

    _, public_key = generate_keypair(str(tmp_path / "keys"))
    trust_public_key(public_key)
    doc = new_feed(
        [{"sha256": "d" * 64, "name": "Win32.FeedSig"}],
        rules=[_entry()],
        ttl_hours=24,
    )
    signed = sign_document(doc, str(tmp_path / "keys" / "signing_private.pem"))
    feed_file = str(tmp_path / "feed.json")
    save_feed(signed, feed_file)

    assert cli_main(["feed", "update", "--file", feed_file]) == 0
    out = capsys.readouterr().out
    assert "rules installed=1" in out
    assert "Feed.Test" in current_rules()

    # a follow-up feed WITHOUT rules clears the rule set (full-state sync)
    empty = new_feed([], rules=[], ttl_hours=24)
    signed_empty = sign_document(empty, str(tmp_path / "keys" / "signing_private.pem"))
    empty_file = str(tmp_path / "feed2.json")
    save_feed(signed_empty, empty_file)

    future = time.time() + 3600
    payload = dict(signed_empty)
    body = dict(payload["body"]) if False else None  # placeholder; replay guard uses generated_utc
    signed_empty_generated = json.loads(open(feed_file).read())["generated_utc"]
    # ensure newer generated_utc so replay check passes
    doc3 = new_feed([], rules=[], ttl_hours=24)
    doc3["generated_utc"] = "2099-01-01T00:00:00+00:00"
    doc3["expires_utc"] = "2099-02-01T00:00:00+00:00"
    from defentra.signing.feed import sign_document as sd

    resigned = sd(doc3, str(tmp_path / "keys" / "signing_private.pem"))
    save_feed(resigned, empty_file)
    assert cli_main(["feed", "update", "--file", empty_file]) == 0
    assert current_rules() == {}
