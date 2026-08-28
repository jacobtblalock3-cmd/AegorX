from __future__ import annotations

import io
import os
import zipfile
import zlib

import pytest

from aegorx.engine import ScanEngine
from aegorx.scanner import pdfdoc


@pytest.fixture(scope="module")
def engine():
    import tempfile

    old = os.environ.get("AEGORX_HOME")
    os.environ["AEGORX_HOME"] = tempfile.mkdtemp(prefix="aegorx-pdf-")
    try:
        yield ScanEngine(enable_ml=False)
    finally:
        if old is None:
            os.environ.pop("AEGORX_HOME", None)
        else:
            os.environ["AEGORX_HOME"] = old


def _scan(tmp_path, name, data, engine):
    path = tmp_path / name
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    return engine.scan_file(str(path))


def _names(result):
    return {d.name for d in result.detections}


CLEAN_PDF = """%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /Contents 4 0 R >> endobj
4 0 obj << /Length 46 >> stream
BT /F1 12 Tf 72 720 Td (Quarterly report) Tj ET
endstream endobj
trailer << /Root 1 0 R >>
%%EOF"""

AUTOEXEC_JS_PDF = """%PDF-1.7
1 0 obj << /Type /Catalog /OpenAction 5 0 R >> endobj
5 0 obj << /S /JavaScript /JS (app.launchURL("file:///C:/Windows/System32/calc.exe");) >> endobj
trailer << /Root 1 0 R >>
%%EOF"""


def test_magic_sniffing():
    assert pdfdoc.looks_like_pdf(b"%PDF-1.7 rest")
    assert not pdfdoc.looks_like_pdf(b"%PDX")


def test_clean_pdf_is_clean(engine, tmp_path):
    result = _scan(tmp_path, "report.pdf", CLEAN_PDF, engine)
    assert result.verdict == "clean"
    assert result.detections == []


def test_autoexec_javascript_chain_malicious(engine, tmp_path):
    result = _scan(tmp_path, "invoice.pdf", AUTOEXEC_JS_PDF, engine)
    assert "PDF.AutoExec.Chain" in _names(result)
    assert result.verdict == "malicious"


def test_payload_hidden_in_compressed_stream_detected(engine, tmp_path):
    hidden = zlib.compress(b"/OpenAction << /S /JavaScript /JS (x); >>")
    body = (
        "%PDF-1.7\n"
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        "9 0 obj << /Filter /FlateDecode /Length "
        + str(len(hidden))
        + " >> stream\n"
    ).encode() + hidden + b"\nendstream endobj\ntrailer << /Root 1 0 R >>\n%%EOF"
    result = _scan(tmp_path, "packed.pdf", body, engine)
    assert "PDF.AutoExec.Chain" in _names(result)


def test_launch_without_autoexec_is_suspicious_only(engine, tmp_path):
    body = "%PDF-1.7\n1 0 obj << /Type /Action /S /Launch /File (cmd.exe) >> endobj\n%%EOF"
    result = _scan(tmp_path, "launcher.pdf", body, engine)
    assert "PDF.ActiveContent" in _names(result)
    assert result.verdict == "suspicious"


def test_embedded_file_alone_is_informational(engine, tmp_path):
    body = "%PDF-1.6\n3 0 obj << /Type /Filespec /EF << /F 4 0 R >> >>\n4 0 obj << /Subtype /EmbeddedFile /Length 5 >> stream\nabcde\nendstream endobj\n%%EOF"
    result = _scan(tmp_path, "portfolio.pdf", body, engine)
    assert "PDF.PassiveExtras" in _names(result)
    assert result.verdict == "clean"


def test_submit_form_informational(engine, tmp_path):
    body = "%PDF-1.7\n1 0 obj << /A << /S /SubmitForm /F (http://forms.example/x) >> >> endobj\n%%EOF"
    result = _scan(tmp_path, "form.pdf", body, engine)
    assert _names(result) == {"PDF.PassiveExtras"}
    assert result.verdict == "clean"


def test_garbage_pdf_magic_degrades_gracefully(engine, tmp_path):
    result = _scan(tmp_path, "broken.pdf", b"%PDF-1.9\xff\xfe\x00garbage-no-structure", engine)
    assert result.detections == []
    assert result.verdict == "clean"


def test_pdf_inside_zip_composes_with_archive_layer(engine, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("docs/urgent.pdf", AUTOEXEC_JS_PDF)
    result = _scan(tmp_path, "bundle.zip", buf.getvalue(), engine)
    assert result.verdict == "malicious"
    assert any(d.detector.startswith("archive:pdf") for d in result.detections)


def test_capabilities_advertise_pdf(engine):
    assert engine.capabilities["pdf"] is True


def test_inflate_budget_bounded():
    # a stream claiming huge decompressed size cannot blow the budget
    bomb = zlib.compress(b"\x00" * (pdfdoc.MAX_INFLATED_TOTAL_BYTES + 1024 * 1024))
    data = b"%PDF-1.7\n9 0 obj << /Filter /FlateDecode >> stream\n" + bomb + b"\nendstream endobj\n%%EOF"
    blobs = pdfdoc._inflate_streams(data)
    assert sum(len(b) for b in blobs) <= pdfdoc.MAX_INFLATED_TOTAL_BYTES + 256 * 1024
