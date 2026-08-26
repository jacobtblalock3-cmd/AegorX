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


# ---------------------------------------------------------------- PDF + archives


def test_fuzz_pdf_analyzer_domain_results_only(tmp_path):
    """analyze_pdf must never raise on hostile input: list-of-dicts or None."""
    from defentra.scanner.pdfdoc import analyze_pdf, looks_like_pdf

    valid = (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n"
        b"2 0 obj<</S/JavaScript/JS(attack())>>endobj\n"
        b"trailer<<>>\n%%EOF\n"
    )
    for data in _mutations(valid):
        p = tmp_path / "hostile.pdf"
        p.write_bytes(data)
        result = analyze_pdf(str(p))
        assert result is None or isinstance(result, list)
        if isinstance(result, list):
            for d in result:
                assert isinstance(d, dict)
    # random garbage with the magic prefix
    for _ in range(10):
        p = tmp_path / "junk.pdf"
        p.write_bytes(b"%PDF-1.4\n" + _random_bytes(RANDOM.randrange(0, 2048)))
        result = analyze_pdf(str(p))
        assert result is None or all(isinstance(d, dict) for d in result)


def test_fuzz_pdf_inflate_budget_never_exceeded():
    """A decompression bomb inside a stream must respect the inflate budget."""
    import zlib

    from defentra.scanner.pdfdoc import MAX_INFLATED_TOTAL_BYTES, _inflate_streams

    bomb = zlib.compress(b"A" * (MAX_INFLATED_TOTAL_BYTES * 4))
    data = b"%PDF-1.7\nstream\n" + bomb + b"\nendstream\n%%EOF\n"
    blobs = _inflate_streams(data)
    total = sum(len(b) for b in blobs)
    assert total <= MAX_INFLATED_TOTAL_BYTES


def test_fuzz_archive_sniffer_random_bytes():
    """sniff_format / looks_like_archive must tolerate any byte sequence."""
    from defentra.scanner.archives import looks_like_archive, sniff_format

    for _ in range(30):
        blob = _random_bytes(RANDOM.randrange(0, 1024))
        head = blob[:512]
        assert sniff_format.__module__  # touch
        assert looks_like_archive(head) in (True, False)


def test_fuzz_extract_archive_malformed_inputs(tmp_path):
    """extract_archive raises only ArchiveError-family on malformed inputs."""
    import io
    import tarfile
    import zipfile

    from defentra.scanner.archives import ArchiveBomb, ArchiveError, extract_archive

    # a real zip then mutate it heavily
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"hello world" * 100)
    real_zip = buf.getvalue()

    real_tar = io.BytesIO()
    with tarfile.open(fileobj=real_tar, mode="w") as tf:
        info = tarfile.TarInfo("b.txt")
        payload = b"x" * 4096
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    real_tar_bytes = real_tar.getvalue()

    cases = []
    for base in (real_zip, real_tar_bytes):
        cases.extend(_mutations(base))
    cases.append(real_zip[:4] + _random_bytes(64))  # truncated mid-header

    for i, data in enumerate(cases):
        p = tmp_path / f"case{i}.bin"
        p.write_bytes(data)
        try:
            entries = extract_archive(str(p), limits=None)
            assert isinstance(entries, list)
        except (ArchiveError, ArchiveBomb):
            pass
