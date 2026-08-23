"""Fuzz-style robustness tests for every attacker-influenced parser.

Property under test: malformed/truncated/random input must produce either a
clean domain exception or a valid result -- never an unhandled crash type
(struct.error, IndexError, OverflowError, etc.).
"""

from __future__ import annotations

import random

import pytest

from defentra.ml import elf_features as elf_mod
from defentra.ml import pe_features as pe_mod
from defentra.ml.ember_map import ember_record_to_features
from defentra.realtime.fanotify_backend import parse_metadata
from defentra.realtime.inotify_backend import parse_events
from defentra.signing.feed import FeedError, canonical_payload, verify_document

RANDOM = random.Random(0xDEF7)


def _random_bytes(n: int) -> bytes:
    return bytes(RANDOM.randrange(256) for _ in range(n))


def _mutations(data: bytes):
    yield b""
    yield data[: len(data) // 2]
    yield data + _random_bytes(RANDOM.randrange(1, 64))
    for _ in range(12):
        blob = bytearray(data)
        for _ in range(RANDOM.randrange(1, 8)):
            if blob:
                pos = RANDOM.randrange(len(blob))
                blob[pos] = RANDOM.randrange(256)
        yield bytes(blob)
    for _ in range(6):
        yield _random_bytes(RANDOM.randrange(0, 512))


def test_fuzz_inotify_event_parser():
    header = (1).to_bytes(4, "little") + (0x108).to_bytes(4, "little")
    header += (0).to_bytes(4, "little") + (8).to_bytes(4, "little") + b"evil\x00\x00\x00"
    for blob in _mutations(header * 3):
        events = parse_events(blob)
        assert isinstance(events, list)


def test_fuzz_fanotify_metadata_parser():
    import struct

    base = struct.pack("IBBHQii", 24, 5, 0, 24, 0x10000, 7, 1234)
    for blob in _mutations(base * 2):
        events = parse_metadata(blob)
        assert isinstance(events, list)
        assert all(set(e) == {"mask", "fd", "pid", "event_len"} for e in events)


def test_fuzz_pe_parser_domain_errors_only():
    good = b"MZ" + b"\x00" * 0x38 + (64).to_bytes(4, "little") + b"PE\x00\x00"
    good += b"\x00" * 160 + b".text\x00\x00\x00" + b"\x00" * 32
    for blob in _mutations(good):
        try:
            result = pe_mod.parse_pe(blob)
            assert isinstance(result, dict)
        except pe_mod.NotPEError:
            pass


def test_fuzz_elf_parser_domain_errors_only():
    good = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9 + b"\x00" * 48
    for blob in _mutations(good):
        try:
            result = elf_mod.parse_elf(blob)
            assert isinstance(result, dict)
        except elf_mod.NotElfError:
            pass


def test_fuzz_ember_mapper_tolerates_anything():
    keys = ["general", "header", "section", "imports", "exports", "data_directories", "overlay", "label"]
    for _ in range(60):
        rec = {k: RANDOM.choice([None, {}, [], "", 0, "x", {"size": -5}, [{"entropy": None}], [1, 2]]) for k in keys}
        feats = ember_record_to_features(rec if RANDOM.random() < 0.8 else {})
        assert set(feats) >= {
            "file_size",
            "is_pe",
        }
        for value in feats.values():
            assert isinstance(value, float)


def test_fuzz_feed_verifier_rejects_garbage():
    doc = {"format": "defentra-signature-feed", "feed_version": 1, "signature": "QUJD"}
    for _ in range(40):
        mutated = dict(doc)
        for _ in range(RANDOM.randrange(1, 4)):
            key = RANDOM.choice(list(mutated) + ["extra"])
            mutated[key] = RANDOM.choice([None, 0, "x", b"bytes", {"nested": True}, [1]])
        try:
            verify_document(mutated, extra_trusted_keys=[])
        except FeedError:
            pass


def test_canonical_payload_is_stable_and_injection_safe():
    weird = {"a": "\u2028\u0000</script>", "b": ["\x1b[31m"], "signature": "drop"}
    payload = canonical_payload(weird)
    assert b"signature" not in payload
    assert canonical_payload(dict(reversed(list(weird.items())))) == payload


def test_path_filter_never_raises_on_hostile_patterns():
    from defentra.realtime.events import PathFilter

    filt = PathFilter(["*", "[!", "**/../../x", "(?i)y", "/[a-", "\\"])
    for path in ["", "/", "\x1b]0;pwn", "a" * 5000, "../../etc/passwd"]:
        assert isinstance(filt.excluded(path), bool)
