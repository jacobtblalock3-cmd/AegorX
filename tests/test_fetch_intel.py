import argparse
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

import build_feed as bf
import fetch_intel as fi
from defentra.signing.feed import new_feed, sign_document, verify_document


MB_OK = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": "A" * 64,
            "md5_hash": "1" * 32,
            "sha1_hash": "2" * 40,
            "signature": "AgentTesla",
            "first_seen_utc": "2026-08-20 10:00:00",
        },
        {"sha256_hash": "B" * 64},
        {"sha256_hash": "short", "signature": "bad"},
    ],
}

MB_AUTH_ERROR = {"query_status": "no_auth_key"}

UH_OK = {
    "payloads": [
        {
            "sha256": "C" * 64,
            "md5": "3" * 32,
            "signature": None,
            "tags": ["heodo", "elf"],
            "first_seen": "2026-08-21T09:30:11Z",
        },
        {"sha256": "D" * 64, "signature": "Nemucod"},
    ]
}


def test_parse_malwarebazaar():
    entries = fi.parse_malwarebazaar(MB_OK)
    assert len(entries) == 2
    first = [e for e in entries if e["sha256"] == "a" * 64][0]
    assert first["name"] == "MB.AgentTesla"
    assert first["family"] == "agenttesla"
    assert first["first_seen"] == "2026-08-20"
    assert first["severity"] == 8
    second = [e for e in entries if e["sha256"] == "b" * 64][0]
    assert second["name"] == "MB.Unknown"


def test_parse_malwarebazaar_rejects_bad_status():
    with pytest.raises(fi.IntelSourceError, match="no_auth_key"):
        fi.parse_malwarebazaar(MB_AUTH_ERROR)
    with pytest.raises(fi.IntelSourceError, match="MALWAREBAZAAR_KEY"):
        fi.parse_malwarebazaar({"query_status": "error_needs_auth_key"})
    with pytest.raises(fi.IntelSourceError, match="non-object"):
        fi.parse_malwarebazaar([1, 2, 3])


def test_parse_urlhaus_tags_as_family_fallback():
    entries = fi.parse_urlhaus(UH_OK)
    assert len(entries) == 2
    by_hash = {e["sha256"]: e for e in entries}
    assert by_hash["c" * 64]["name"] == "UH.heodo"
    assert by_hash["d" * 64]["name"] == "UH.Nemucod"
    assert by_hash["c" * 64]["first_seen"] == "2026-08-21"


def test_merge_dedupes_and_fills_gaps_without_clobbering():
    existing = [{"sha256": "a" * 64, "name": "MB.Old", "family": "old"}]
    incoming = [
        {"sha256": "a" * 64, "name": "MB.New", "family": "", "first_seen": "2026-08-01"},
        {"sha256": "b" * 64, "name": "MB.Other", "family": "other"},
    ]
    merged, added = fi.merge_entries(existing, incoming)
    assert added == 1 and len(merged) == 2
    kept = [e for e in merged if e["sha256"] == "a" * 64][0]
    assert kept["name"] == "MB.Old"
    assert kept["first_seen"] == "2026-08-01"


def test_prune_by_first_seen(tmp_path):
    old_date = (datetime.now(timezone.utc) - timedelta(days=200)).strftime("%Y-%m-%d")
    recent_date = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%d")
    entries = [
        {"sha256": "a" * 64, "first_seen": old_date},
        {"sha256": "b" * 64, "first_seen": recent_date},
        {"sha256": "c" * 64},
    ]
    pruned, dropped = fi.prune_entries(entries, keep_days=90)
    assert dropped == 1
    hashes = {e["sha256"] for e in pruned}
    assert hashes == {"b" * 64, "c" * 64}


def test_run_offline_fixtures_end_to_end(tmp_path):
    mb_file = tmp_path / "mb.json"
    uh_file = tmp_path / "uh.json"
    mb_file.write_text(json.dumps(MB_OK))
    uh_file.write_text(json.dumps(UH_OK))
    store = str(tmp_path / "malwarebazaar.json")

    args = argparse.Namespace(
        store=store,
        source="malwarebazaar,urlhaus",
        prune_days=90,
        auth_key=None,
        mb_response=str(mb_file),
        uh_response=str(uh_file),
    )
    assert fi.run(args) == 0
    saved = json.load(open(store))
    assert {e["sha256"][:1] for e in saved["signatures"]} == {"a", "b", "c", "d"}

    args2 = argparse.Namespace(
        store=store,
        source="urlhaus",
        prune_days=90,
        auth_key=None,
        mb_response=None,
        uh_response=str(uh_file),
    )
    cap = {}
    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()) as fh:
        assert fi.run(args2) == 0
    assert "new 0," in fh.getvalue()


def test_all_sources_fail_with_empty_store_returns_error(tmp_path):
    args = argparse.Namespace(
        store=str(tmp_path / "store.json"),
        source="malwarebazaar",
        prune_days=90,
        auth_key=None,
        mb_response=str(tmp_path / "missing.json"),
        uh_response=None,
    )
    assert fi.run(args) == 3


class FakeResp:
    def __init__(self, payload: bytes):
        self._data = payload

    def read(self, n=-1):
        out, self._data = (self._data[:n] if n > 0 else self._data), (
            self._data[n:] if n > 0 else b""
        )
        return out

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_live_fetch_via_injected_opener(tmp_path):
    calls = []

    def opener(request, timeout=0):
        calls.append(request.full_url)
        if "mb-api" in request.full_url:
            body = request.data.decode()
            assert "query=get_recent" in body
            return FakeResp(json.dumps(MB_OK).encode())
        return FakeResp(json.dumps(UH_OK).encode())

    args = argparse.Namespace(
        store=str(tmp_path / "store.json"),
        source="malwarebazaar,urlhaus",
        prune_days=90,
        auth_key="testkey",
        mb_response=None,
        uh_response=None,
    )
    assert fi.run(args, opener=opener) == 0
    assert len(calls) == 2
    assert json.load(open(str(tmp_path / "store.json")))["signatures"]


def test_store_feeds_into_signed_feed_pipeline(tmp_path):
    """The full chain: intel store -> build_feed -> sign -> verify."""
    store = {
        "signatures": [
            {"sha256": "e" * 64, "name": "MB.Ransom", "family": "ransom", "severity": 8}
        ]
    }
    store_path = tmp_path / "malwarebazaar.json"
    store_path.write_text(json.dumps(store))

    doc = bf.build_feed([str(store_path)])
    from defentra.signing.keys import generate_keypair

    keypair = generate_keypair(str(tmp_path / "keys"))
    signed = sign_document(doc, keypair[0])
    out = bf.save_feed(signed, str(tmp_path / "signatures.json"))
    fp = verify_document(json.load(open(out)), extra_trusted_keys=[keypair[1]])
    assert len(fp) == 16
