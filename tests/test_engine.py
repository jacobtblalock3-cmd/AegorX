import json

import pytest

from defentra.engine import ScanEngine


@pytest.fixture
def engine(tmp_home, rules_dir):
    return ScanEngine(
        db_path=None,
        rules_dirs=[rules_dir],
        enable_ml=False,
    )


def test_eicar_detected_by_signature_and_yara(engine, eicar_file):
    result = engine.scan_file(eicar_file)
    assert result.verdict == "malicious"
    detectors = {d.detector for d in result.detections}
    assert "signature" in detectors


def test_clean_file_is_clean(engine, benign_file):
    result = engine.scan_file(benign_file)
    assert result.verdict == "clean"
    assert result.detections == []
    assert result.ml_probability is None


def test_directory_recursive_scan(tmp_home, rules_dir, tmp_path, eicar_file, benign_file):
    sub = tmp_path / "nested"
    sub.mkdir()
    (sub / "inner.txt").write_text("nothing bad")
    engine = ScanEngine(rules_dirs=[rules_dir], enable_ml=False)
    results = engine.scan_target(str(tmp_path))
    verdicts = {r.verdict for r in results}
    assert len(results) >= 2
    assert "malicious" in verdicts
    assert "clean" in verdicts


def test_missing_target_reports_error(engine):
    results = engine.scan_target("/nonexistent/path/xyz")
    assert results[0].verdict == "error"


def test_capabilities(tmp_home):
    caps = ScanEngine(enable_ml=False).capabilities
    assert caps["signature_db"] >= 1
    assert "hash_backend" in caps


def test_json_report_shape(engine, tmp_path, eicar_file):
    from defentra.report import to_dict

    results = engine.scan_target(eicar_file)
    payload = to_dict(results, eicar_file, 0.01)
    blob = json.dumps(payload)
    assert payload["summary"]["malicious"] == 1
    assert '"verdict": "malicious"' in blob
    f = payload["files"][0]
    assert f["detections"][0]["detector"] in ("signature", "yara")


def test_quarantine_roundtrip(tmp_home, engine, eicar_file):
    from defentra.quarantine.vault import QuarantineVault

    vault = QuarantineVault()
    entry = vault.quarantine(eicar_file, reason="test scan hit")
    assert not __import__("os").path.exists(eicar_file)
    items = vault.list_items()
    assert items and items[0]["id"] == entry["id"]
    restored = vault.restore(entry["id"], destination=eicar_file + ".restored")
    with open(restored, "rb") as fh:
        content = fh.read()
    assert content.startswith(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")
    assert vault.list_items() == []


def test_quarantine_delete(tmp_home, eicar_file):
    import os

    from defentra.quarantine.vault import QuarantineVault

    vault = QuarantineVault()
    entry = vault.quarantine(eicar_file)
    assert vault.delete(entry["id"]) is True
    assert vault.delete(entry["id"]) is False
    assert vault.get(entry["id"]) is None
    assert not os.path.exists(os.path.join(vault.base_dir, entry["blob"]))
