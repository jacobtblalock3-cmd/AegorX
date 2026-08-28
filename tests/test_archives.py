from __future__ import annotations

import gzip
import io
import os
import tarfile
import tempfile
import zipfile

import pytest

from conftest import EICAR
from aegorx.engine import ScanEngine
from aegorx.scanner import archives, office

BENIGN = b"hello aegorx\n" * 20


@pytest.fixture
def engine(tmp_home):
    eng = ScanEngine(enable_ml=False)
    eng.archive_limits = archives.ArchiveLimits(max_entries=100, max_total_bytes=4 * 1024 * 1024,
                                                max_entry_bytes=2 * 1024 * 1024,
                                                max_depth=3, timeout_seconds=30)
    return eng


def _zip_bytes(payloads, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in payloads:
            zf.writestr(name, data)
    return buf.getvalue()


def _write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _detection_names(result):
    return [d.name for d in result.detections]


# --- core detection through containers -------------------------------------


def test_eicar_inside_zip_is_detected(engine, tmp_path):
    archive = _write(tmp_path / "bundle.zip", _zip_bytes([("docs/readme.txt", BENIGN), ("eicar.com", EICAR)]))
    result = engine.scan_file(archive)
    assert result.verdict == "malicious"
    names = _detection_names(result)
    assert any(n.startswith(("EICAR",)) for n in names)
    entry_tagged = [d for d in result.detections if d.details.get("entry") == "eicar.com"]
    assert entry_tagged, "inner hit must record its archive entry path"
    assert all(d.detector.startswith("archive:") for d in entry_tagged)


def test_clean_zip_stays_clean(engine, tmp_path):
    archive = _write(tmp_path / "clean.zip", _zip_bytes([("a.txt", BENIGN), ("b/c.log", b"x" * 100)]))
    result = engine.scan_file(archive)
    assert result.verdict == "clean"
    assert result.detections == []


def test_nested_zip_two_levels_deep(engine, tmp_path):
    inner = _zip_bytes([("deep/eicar.com", EICAR)])
    outer = _zip_bytes([("inner.zip", inner)])
    result = engine.scan_file(_write(tmp_path / "outer.zip", outer))
    assert result.verdict == "malicious"
    assert any(d.details.get("entry") == "deep/eicar.com" for d in result.detections)


def test_tar_gz_with_threat_detected(engine, tmp_path):
    path = str(tmp_path / "pack.tar.gz")
    with tarfile.open(path, "w:gz") as tf:
        data = EICAR
        info = tarfile.TarInfo("payload/eicar.com")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        benign = tarfile.TarInfo("notes.txt")
        benign.size = len(BENIGN)
        tf.addfile(benign, io.BytesIO(BENIGN))
    result = engine.scan_file(path)
    assert result.verdict == "malicious"


def test_single_gzip_payload_detected(engine, tmp_path):
    path = str(tmp_path / "sample.txt.gz")
    with gzip.open(path, "wb") as fh:
        fh.write(EICAR)
    result = engine.scan_file(path)
    assert result.verdict == "malicious"


# --- safety rails -----------------------------------------------------------


def test_zip_bomb_budget_raises_suspicious_not_hang(engine, tmp_path):
    big = b"\x00" * (32 * 1024 * 1024)
    archive = _write(tmp_path / "bomb.zip", _zip_bytes([("zeros.bin", big)]))
    engine.archive_limits.max_total_bytes = 1024 * 1024
    result = engine.scan_file(archive)
    assert "Archive.BombSuspected" in _detection_names(result)
    assert result.verdict == "suspicious"


def test_nesting_beyond_depth_limit_reports_and_skips(engine, tmp_path):
    # four containers: l4 is itself an archive at depth 3 == limit -> guarded
    l4 = _zip_bytes([("eicar.com", EICAR)])
    l3 = _zip_bytes([("l4.zip", l4)])
    l2 = _zip_bytes([("l3.zip", l3)])
    l1 = _zip_bytes([("l2.zip", l2)])
    result = engine.scan_file(_write(tmp_path / "l1.zip", l1))
    assert result.verdict != "malicious", "payload past depth limit must not be silently trusted either way"
    flat = " ".join(_detection_names(result))
    assert "Archive.NestedTooDeep" in flat


def test_depth_three_payload_within_limit_detected(engine, tmp_path):
    # eicar sits in the THIRD container: its plain-file contents are scanned at depth 3 == allowed.
    l3 = _zip_bytes([("eicar.com", EICAR)])
    l2 = _zip_bytes([("l3.zip", l3)])
    l1 = _zip_bytes([("l2.zip", l2)])
    result = engine.scan_file(_write(tmp_path / "l1.zip", l1))
    assert result.verdict == "malicious"


def test_entry_count_cap(engine, tmp_path):
    payloads = [(f"f{i}.txt", b"x") for i in range(10)]
    archive = _write(tmp_path / "many.zip", _zip_bytes(payloads))
    engine.archive_limits.max_entries = 5
    result = engine.scan_file(archive)
    assert "Archive.BombSuspected" in _detection_names(result)


def test_traversal_entry_name_cannot_escape(engine, tmp_path):
    evil_name = "../../../aegorx_pwned.txt"
    archive = _write(tmp_path / "slip.zip", _zip_bytes([(evil_name, BENIGN)]))
    result = engine.scan_file(archive)
    assert result.verdict == "clean"
    outside = os.path.join(os.path.dirname(archive), "aegorx_pwned.txt")
    assert not os.path.exists(outside)


def test_corrupt_zip_yields_error_verdict(engine, tmp_path):
    archive = _write(tmp_path / "broken.zip", b"PK\x03\x04truncated-garbage")
    result = engine.scan_file(archive)
    assert result.verdict == "error"
    assert "unscannable" in (result.error or "")


def test_encrypted_zip_reported_unreadable(engine, tmp_path, monkeypatch):
    archive = _write(tmp_path / "locked.zip", _zip_bytes([("secret.txt", BENIGN)]))

    def locked_open(self, member, *args, **kwargs):
        raise RuntimeError("encrypted, password required")

    monkeypatch.setattr(zipfile.ZipFile, "open", locked_open)
    result = engine.scan_file(archive)
    assert result.verdict == "error"
    assert "unscannable" in (result.error or "")
    monkeypatch.undo()
    assert engine.scan_file(archive).verdict == "clean"


def test_no_temp_dirs_leaked_after_scan(engine, tmp_path):
    archive = _write(tmp_path / "leak.zip", _zip_bytes([("eicar.com", EICAR)]))
    engine.scan_file(archive)
    leftovers = [d for d in os.listdir(tempfile.gettempdir()) if d.startswith("aegorx-arch-")]
    assert leftovers == []


# --- office/VBA heuristics --------------------------------------------------


def test_office_magic_sniffing():
    assert office.looks_like_office(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest")
    assert not archives.looks_like_archive(b"\xd0\xcf\x11\xe0")


def test_vba_autoexec_chain_scores_malicious():
    sources = [
        'Private Sub Document_Open()\nShell "cmd.exe /c powershell -enc AAAA"\nEnd Sub',
        "Sub AutoOpen()\nCreateObject(\"WScript.Shell\").Run Environ(\"TEMP\") & \"\\\\x.exe\"\nEnd Sub",
    ]
    hits = office.analyze_vba_sources(sources)
    assert hits[0]["name"] == "VBA.AutoExec.Chain"
    assert hits[0]["severity"] == 8


def test_vba_risky_apis_without_autoexec_score_suspicious():
    hits = office.analyze_vba_sources(['Sub t()\nCreateObject("MSXML2.XMLHTTP").open "GET", "http://x/y"\nEnd Sub'])
    assert hits[0]["name"] == "VBA.RiskyAPIs"
    assert hits[0]["severity"] == 6


def test_benign_macros_are_info_only():
    hits = office.analyze_vba_sources(["Sub FormatDoc()\nSelection.Font.Bold = True\nEnd Sub"])
    assert hits[0]["name"] == "Document.ContainsMacros"
    assert hits[0]["severity"] == 3


def test_no_sources_no_detections():
    assert office.analyze_vba_sources([]) == []


def test_obfuscation_alone_is_suspicious():
    hits = office.analyze_vba_sources(["s = Chr(104) & Chr(101) & StrReverse(\"lol\")"])
    assert hits[0]["name"] == "VBA.RiskyAPIs"


class _FakeVbaParser:
    """Stands in for oletools so we test our plumbing, not the library."""

    def __init__(self, macros):
        self._macros = macros

    def detect_vba_macros(self):
        return bool(self._macros)

    def extract_macros(self):
        return [(None, None, name, code) for name, code in self._macros]

    def close(self):
        pass


def _fake_office(monkeypatch, macros):
    monkeypatch.setattr(office, "OFFICE_AVAILABLE", True)
    monkeypatch.setattr(office, "VBA_Parser", lambda _p: _FakeVbaParser(macros))


def test_engine_flags_macro_document(engine, tmp_path, monkeypatch):
    _fake_office(monkeypatch, [("Module1", 'Sub Document_Open()\nShell "cmd.exe /c calc"\nEnd Sub')])
    doc = _write(tmp_path / "invoice.doc", office.MAGIC_OLE + b"\x00" * 512)
    result = engine.scan_file(doc)
    assert result.verdict == "malicious"
    assert any(d.detector == "office" and d.name == "VBA.AutoExec.Chain" for d in result.detections)


def test_docx_style_zip_with_embedded_ole_vba(engine, tmp_path, monkeypatch):
    _fake_office(monkeypatch, [("Module1", 'Sub AutoOpen()\nCreateObject("WScript.Shell").Run "calc"\nEnd Sub')])
    vba_bin = office.MAGIC_OLE + b"\x00" * 256
    archive = _write(
        tmp_path / "report.docx",
        _zip_bytes([("[Content_Types].xml", b"<xml/>"), ("word/vbaProject.bin", vba_bin)]),
    )
    result = engine.scan_file(archive)
    assert result.verdict == "malicious"
    assert any(d.detector.startswith("archive:office") for d in result.detections)


def test_analyze_document_without_macros_returns_empty(monkeypatch, tmp_path):
    _fake_office(monkeypatch, [])
    doc = _write(tmp_path / "plain.doc", office.MAGIC_OLE + b"\x00" * 64)
    assert office.analyze_document(str(doc)) == []


def test_analyze_document_when_office_extra_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(office, "OFFICE_AVAILABLE", False)
    doc = _write(tmp_path / "m.doc", office.MAGIC_OLE + b"\x00" * 64)
    assert office.analyze_document(str(doc)) is None


# --- plumbing ---------------------------------------------------------------


def test_capabilities_advertise_archives(engine):
    caps = engine.capabilities
    assert caps["archives"] is True
    assert isinstance(caps["office_macros"], bool)


def test_sniff_format_dispatch(tmp_path):
    z = _write(tmp_path / "a.zip", _zip_bytes([("x", b"y")]))
    g = tmp_path / "b.bin.gz"
    with gzip.open(g, "wb") as fh:
        fh.write(BENIGN)
    assert archives.sniff_format(z) == "zip"
    assert archives.sniff_format(str(g)) == "gzip"
