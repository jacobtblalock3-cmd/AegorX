from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from aegorx.signatures.db import SignatureDB
from aegorx.signing.feed import (
    FeedError,
    FeedExpired,
    apply_feed,
    canonical_payload,
    check_expiry,
    check_replay,
    fetch_feed,
    load_feed,
    new_feed,
    record_applied,
    save_feed,
    sign_document,
    utc_now_iso,
    verify_document,
)
from aegorx.signing.keys import (
    default_signing_dir,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_fingerprint,
    trust_public_key,
    trusted_key_paths,
)

SIG_A = {
    "sha256": "e" * 64,
    "md5": "a" * 32,
    "sha1": "b" * 40,
    "name": "Win32.FeedTest.A",
    "family": "testfamily",
    "severity": 9,
}


@pytest.fixture
def keypair(tmp_path):
    d = str(tmp_path / "signing")
    return generate_keypair(d)


@pytest.fixture
def second_keypair(tmp_path):
    d = str(tmp_path / "signing2")
    return generate_keypair(d)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_generate_keypair_files_and_permissions(keypair):
    private_path, public_path = keypair
    assert os.path.exists(private_path) and os.path.exists(public_path)
    mode = stat.S_IMODE(os.stat(private_path).st_mode)
    assert mode & 0o077 == 0
    load_private_key(private_path)
    load_public_key(public_path)


def test_sign_verify_roundtrip(tmp_path, keypair):
    feed = new_feed([SIG_A])
    signed = sign_document(feed, keypair[0])
    path = save_feed(signed, str(tmp_path / "f.json"))
    loaded = load_feed(path)
    fingerprint = verify_document(loaded, extra_trusted_keys=[keypair[1]])
    assert len(fingerprint) == 16


def test_canonical_payload_excludes_signature():
    doc = {"format": "x", "signature": "AAAA", "z": 1, "a": 2}
    payload = canonical_payload(doc)
    assert b'"a":2' in payload and b"AAAA" not in payload


def test_tampered_payload_rejected(tmp_path, keypair):
    feed = new_feed([SIG_A])
    signed = sign_document(feed, keypair[0])
    signed["signatures"][0]["name"] = "Benign.Renamed"
    with pytest.raises(FeedError, match="did not verify"):
        verify_document(signed, extra_trusted_keys=[keypair[1]])


def test_wrong_key_rejected(keypair, second_keypair):
    feed = new_feed([SIG_A])
    signed = sign_document(feed, second_keypair[0])
    with pytest.raises(FeedError):
        verify_document(signed, extra_trusted_keys=[keypair[1]])


def test_missing_or_corrupt_signature_rejected():
    with pytest.raises(FeedError):
        verify_document({"format": "aegorx-signature-feed", "feed_version": 1})
    with pytest.raises(FeedError, match="base64"):
        verify_document({"format": "aegorx-signature-feed", "feed_version": 1, "signature": "!!!"})
    with pytest.raises(FeedError, match="bad 'format'"):
        verify_document({"format": "other"})


def test_expiry_enforcement():
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    expired_doc = {"generated_utc": past, "expires_utc": past}
    fresh_doc = {"generated_utc": utc_now_iso(), "expires_utc": future}
    noexpiry_doc = {}
    with pytest.raises(FeedExpired):
        check_expiry(expired_doc)
    check_expiry(fresh_doc)
    check_expiry(expired_doc, allow_expired=True)
    check_expiry(noexpiry_doc)
    with pytest.raises(FeedError, match="timestamp"):
        check_expiry({"expires_utc": "not-a-date"})


def test_replay_protection_and_force(tmp_home):
    old = {"generated_utc": "2026-01-01T00:00:00+00:00"}
    newer = {"generated_utc": "2026-06-01T00:00:00+00:00"}
    record_applied(old)
    assert not os.environ.get("AEGORX_HOME") or True
    assert check_replay(newer) is True
    assert check_replay({"generated_utc": "2025-12-31T23:59:59+00:00"}) is False
    assert check_replay({"generated_utc": "2020-01-01T00:00:00+00:00"}, force=True) is True


def test_apply_feed_into_db(tmp_path, keypair):
    feed = new_feed([SIG_A, {"sha256": "", "name": "skipped-no-hash"}, {"name": "no-hash-either"}])
    signed = sign_document(feed, keypair[0])
    db = SignatureDB(str(tmp_path / "sigs.db"))
    added = apply_feed(db, signed)
    assert added == 1
    row = db.lookup(sha256=SIG_A["sha256"])
    assert row["name"] == SIG_A["name"]
    assert row["source"] == "feed"


def test_scan_detects_hash_from_applied_feed(tmp_path, rules_dir, keypair):
    from aegorx.engine import ScanEngine

    target = tmp_path / "dropper.exe"
    target.write_bytes(b"MZ" + b"\x90" * 128)
    import hashlib

    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    feed = new_feed([{"sha256": digest, "name": "Win32.FeedDropper", "severity": 9}])
    signed = sign_document(feed, keypair[0])

    db = SignatureDB(str(tmp_path / "sigs.db"))
    apply_feed(db, signed)
    engine = ScanEngine(db_path=str(tmp_path / "sigs.db"), rules_dirs=[rules_dir], enable_ml=False)
    results = engine.scan_target(str(target))
    assert any(r.verdict == "malicious" for r in results)


def test_fetch_feed_with_fake_opener():
    payload = json.dumps({"format": "aegorx-signature-feed", "feed_version": 1}).encode()

    class FakeResp:
        def __init__(self, data):
            self._data = data

        def read(self, n=-1):
            out, self._data = self._data[: n if n > 0 else None], self._data[n if n > 0 else None :]
            return out

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    doc = fetch_feed("https://feeds.example/sig.json", opener=lambda url, timeout=0: FakeResp(payload))
    assert doc["format"] == "aegorx-signature-feed"
    with pytest.raises(FeedError, match="download failed"):
        fetch_feed("https://feeds.example/x", opener=lambda url, timeout=0: (_ for _ in ()).throw(OSError("down")))


def test_bundled_package_root_key_exists():
    package_keys = [p for p in trusted_key_paths() if "/trusted_keys/" in p]
    assert package_keys, "package trust dir must contain at least one bundled root key"
    fp = public_key_fingerprint(load_public_key(package_keys[0]))
    assert len(fp) == 16


def test_user_trust_store_roundtrip(tmp_home, keypair):
    _, public_path = keypair
    before = set(trusted_key_paths())
    installed = trust_public_key(public_path)
    after = set(trusted_key_paths())
    assert installed in after and before | {installed} == after
    assert all("/keys/" in p for p in after - before)


def test_default_signing_dir_under_state(tmp_home):
    assert default_signing_dir() == os.path.join(os.environ["AEGORX_HOME"], "signing")
