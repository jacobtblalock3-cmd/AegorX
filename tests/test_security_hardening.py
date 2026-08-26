from __future__ import annotations

import json
import os
import stat

import pytest

from defentra.ml.elf_features import NotElfError, parse_elf
from defentra.ml.pe_features import NotPEError, parse_pe
from defentra.quarantine.vault import QuarantineVault
from defentra.report import sanitize
from defentra.realtime.monitor import AuditLog, verify_audit_log


@pytest.fixture
def vault(tmp_home):
    return QuarantineVault()


def _sample(tmp_path, name="mal.exe", content=b"MZ" + b"A" * 256):
    p = tmp_path / name
    p.write_bytes(content)
    return str(p)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_state_dir_is_owner_only(tmp_home):
    from defentra.utils import ensure_state_dir

    ensure_state_dir()
    mode = stat.S_IMODE(os.stat(tmp_home).st_mode)
    assert mode & 0o077 == 0


def test_vault_key_lives_outside_blob_dir(vault):
    assert not os.path.exists(os.path.join(vault.base_dir, "vault.key"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_vault_blobs_are_0600(vault, tmp_path):
    entry = vault.quarantine(_sample(tmp_path), reason="test")
    blob = os.path.join(vault.base_dir, entry["blob"])
    assert stat.S_IMODE(os.stat(blob).st_mode) & 0o077 == 0


def test_restore_rejects_forged_blob_names(vault, tmp_path):
    forged = [
        {"id": "x", "blob": "../../etc/passwd", "original_path": "/tmp/evil"},
        {"id": "y", "blob": "/etc/passwd", "original_path": "/tmp/evil"},
        {"id": "z", "blob": "sub/dir.quar", "original_path": "/tmp/evil"},
    ]
    vault._write_index(forged)
    for item in forged:
        with pytest.raises(ValueError):
            vault.restore(item["id"])
        with pytest.raises(ValueError):
            vault.delete(item["id"])


def test_quarantine_roundtrip_large_file_chunked(vault, tmp_path):
    payload = os.urandom(3 * 1024 * 1024 + 17)
    path = _sample(tmp_path, content=payload)
    if vault.encryption != "fernet":
        pytest.skip("cryptography backend unavailable")
    entry = vault.quarantine(path, reason="big")
    assert entry["chunked"] is True
    restored = vault.restore(entry["id"], destination=str(tmp_path / "restored.bin"))
    with open(restored, "rb") as fh:
        assert fh.read() == payload
    assert not os.path.exists(path)


def test_tampered_chunked_blob_fails_authentication(vault, tmp_path):
    path = _sample(tmp_path)
    entry = vault.quarantine(path)
    if not entry.get("chunked"):
        pytest.skip("no crypto backend")
    blob = os.path.join(vault.base_dir, entry["blob"])
    raw = bytearray(open(blob, "rb").read())
    raw[-1] ^= 0xFF
    open(blob, "wb").write(bytes(raw))
    with pytest.raises(Exception):
        vault.restore(entry["id"], destination=str(tmp_path / "out.bin"))


def test_audit_log_hash_chain_detects_tampering(tmp_home):
    log = os.path.join(tmp_home, "audit.log")
    writer = AuditLog(log)
    for i in range(5):
        writer.write({"event": f"e{i}", "path": f"/f{i}"})
    ok, seq = verify_audit_log(log)
    assert ok and seq == 5

    lines = open(log).read().splitlines()
    rec = json.loads(lines[2])
    rec["path"] = "/forged"
    lines[2] = json.dumps(rec)
    open(log, "w").write("\n".join(lines) + "\n")
    ok, broken = verify_audit_log(log)
    assert not ok and broken >= 3


def test_audit_log_deletion_breaks_chain(tmp_home):
    import hashlib as _h

    log = os.path.join(tmp_home, "audit.log")
    writer = AuditLog(log)
    for i in range(4):
        writer.write({"event": i})

    lines = open(log).read().splitlines()
    del lines[1]
    open(log, "w").write("\n".join(lines) + "\n")

    raw = open(log).read().splitlines()
    tampered = []
    for line in raw:
        rec = json.loads(line)
        stored = rec.pop("hash")
        actual = _h.sha256(json.dumps(rec, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
        assert stored == actual
        tampered.append(line)
    ok, _ = verify_audit_log(log)
    assert ok is False


def test_audit_log_rotation_preserves_chain(tmp_home):
    log = os.path.join(tmp_home, "audit.log")
    writer = AuditLog(log, max_bytes=300, backups=3)
    for i in range(40):
        writer.write({"event": f"e{i}", "pad": "x" * 20})

    segments = [p for p in (f"{log}.{i}" for i in range(1, 4)) if os.path.exists(p)]
    assert segments, "rotation never produced a segment"
    assert os.path.getsize(log) < 10 * 1024 * 1024

    # chain must verify continuously ACROSS segments (the old verifier broke here)
    ok, last_seq = verify_audit_log(log)
    assert ok, f"post-rotation chain invalid at seq {last_seq}"
    assert last_seq == 40

    # restart scenario: new instance resumes continuity from newest record anywhere
    resumed = AuditLog(log, max_bytes=300, backups=3)
    resumed.write({"event": "after-restart"})
    ok, last_seq = verify_audit_log(log)
    assert ok and last_seq == 41


def test_audit_log_tamper_in_rotated_segment_detected(tmp_home):
    log = os.path.join(tmp_home, "audit.log")
    writer = AuditLog(log, max_bytes=200, backups=3)
    for i in range(30):
        writer.write({"event": f"e{i}", "pad": "y" * 20})
    segments = sorted(
        (p for p in (f"{log}.{i}" for i in range(1, 4)) if os.path.exists(p)),
        key=lambda p: -int(p.rsplit(".", 1)[1]),
    )
    victim = segments[0]  # oldest segment
    lines = open(victim).read().splitlines()
    rec = json.loads(lines[0])
    rec["event"] = "forged"
    lines[0] = json.dumps(rec)
    open(victim, "w").write("\n".join(lines) + "\n")

    ok, broken_seq = verify_audit_log(log)
    assert not ok
    assert broken_seq == json.loads(lines[0])["seq"] or broken_seq >= 1


def test_sanitize_neutralizes_terminal_escapes():
    evil = "\x1b]0;pwned\x07C:\\evil.exe"
    clean = sanitize(evil)
    assert "\x1b" not in clean and "\x07" not in clean
    assert sanitize("normal/path.txt") == "normal/path.txt"


MALFORMED_PE = b"MZ" + (0xFFFFFF).to_bytes(4, "little") + b"\xff" * 40 + b"PE"
TRUNCATED_DIRS = (
    b"MZ" + (64).to_bytes(4, "little") + b"PE\x00\x00"
    + b"\x00" * 16 + (1).to_bytes(2, "little") + (2).to_bytes(2, "little")
    + b"\x00" * 4 + (224).to_bytes(2, "little") + (0xFFFF).to_bytes(2, "little")
    + b"\x0b\x01" + b"\x00" * 70 + (99).to_bytes(4, "little")
)


def test_malformed_pe_raises_domain_error_only():
    for blob in (MALFORMED_PE, TRUNCATED_DIRS, b"MZ", b"MZ" + b"\x00" * 63):
        with pytest.raises((NotPEError, ValueError)):
            parse_pe(blob)


def test_truncated_data_directories_do_not_crash():
    try:
        result = parse_pe(TRUNCATED_DIRS)
        assert isinstance(result["num_data_dirs"], int)
    except NotPEError:
        pass


def test_malformed_elf_raises_domain_error_only():
    for blob in (b"\x7fELF", b"\x7fELF\x09\x00", b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 30):
        with pytest.raises((NotElfError, ValueError)):
            parse_elf(blob)


def test_engine_survives_crafted_executable(tmp_home, rules_dir, tmp_path):
    from defentra.engine import ScanEngine

    crafted = tmp_path / "crafted.exe"
    crafted.write_bytes(b"MZ" + b"\xcc" * 300)

    engine = ScanEngine(rules_dirs=[rules_dir], enable_ml=True, db_path=str(tmp_path / "db.sqlite"))
    result = engine.scan_file(str(crafted))
    assert result.verdict in ("clean", "error", "suspicious")


def test_cli_audit_verify_command(tmp_home, capsys):
    from defentra.cli import main as cli_main

    assert cli_main(["audit"]) == 3
    missing = os.path.join(tmp_home, "none.log")
    assert cli_main(["audit", "verify", missing]) == 3

    log = os.path.join(tmp_home, "realtime.log")
    w = AuditLog(log)
    w.write({"a": 1})
    w.write({"a": 2})
    assert cli_main(["audit", "verify"]) == 0
    out = capsys.readouterr().out
    assert "intact through record 2" in out
