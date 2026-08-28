import json
import os

import pytest

import build_feed as bf
from aegorx.signing.feed import load_feed, sign_document, verify_document


@pytest.fixture
def keypair(tmp_path):
    from aegorx.signing.keys import generate_keypair

    return generate_keypair(str(tmp_path / "keys"))


@pytest.fixture
def extra_file(tmp_path):
    path = os.path.join(tmp_path, "extra.json")
    with open(path, "w") as fh:
        json.dump(
            {
                "signatures": [
                    {"sha256": "a" * 64, "name": "Win32.Curated.A", "severity": 9},
                    {"sha256": "b" * 64, "name": "Win32.Curated.B", "family": "curated"},
                    {"sha256": "nothex", "name": "invalid-entry"},
                ]
            },
            fh,
        )
    return path


def test_collect_entries_merges_and_dedupes(extra_file):
    eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    entries = bf.collect_entries([extra_file])
    hashes = {e["sha256"] for e in entries}
    assert eicar in hashes
    assert {"a" * 64, "b" * 64} <= hashes
    assert all(len(e["sha256"]) == 64 for e in entries)


def test_later_sources_override_conflicts(tmp_path):
    first = os.path.join(tmp_path, "1.json")
    second = os.path.join(tmp_path, "2.json")
    with open(first, "w") as fh:
        json.dump({"signatures": [{"sha256": "c" * 64, "name": "Old.Name"}]}, fh)
    with open(second, "w") as fh:
        json.dump({"signatures": [{"sha256": "c" * 64, "name": "New.Name"}]}, fh)
    entries = bf.collect_entries([first, second])
    by_hash = {e["sha256"]: e for e in entries if e["sha256"] == "c" * 64}
    assert len(by_hash) == 1
    assert by_hash["c" * 64]["name"] == "New.Name"


def test_build_feed_document_shape(extra_file):
    doc = bf.build_feed([extra_file], ttl_hours=24)
    assert doc["format"] == "aegorx-signature-feed"
    assert doc["feed_version"] == 1
    assert "signature" not in doc
    from datetime import datetime

    generated = datetime.fromisoformat(doc["generated_utc"])
    expires = datetime.fromisoformat(doc["expires_utc"])
    assert (expires - generated).total_seconds() == 24 * 3600


def test_signed_feed_verifies_with_signing_key(tmp_path, extra_file, keypair):
    doc = bf.build_feed([extra_file])
    signed = sign_document(doc, keypair[0])
    out = os.path.join(tmp_path, "signatures.json")
    saved = bf.save_feed(signed, out)
    assert saved == out
    fingerprint = verify_document(load_feed(out), extra_trusted_keys=[keypair[1]])
    assert len(fingerprint) == 16


def test_repo_community_feed_is_valid_json_array():
    repo_feeds = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "feeds"
    )
    files = [f for f in os.listdir(repo_feeds) if f.endswith(".json")]
    assert files, "feeds/ should ship at least one curated list file"
    for name in files:
        with open(os.path.join(repo_feeds, name)) as fh:
            data = json.load(fh)
        assert isinstance(data.get("signatures"), list)
        for entry in data["signatures"]:
            assert len(entry["sha256"]) == 64
