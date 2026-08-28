import json

from aegorx.signatures.db import SignatureDB


def test_fresh_db_is_seeded_with_eicar(tmp_path):
    db = SignatureDB(str(tmp_path / "sigs.db"))
    assert db.count() >= 1
    hit = db.lookup(sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert hit is not None
    assert hit["name"] == "EICAR-Test-File"


def test_lookup_by_md5(tmp_path):
    db = SignatureDB(str(tmp_path / "sigs.db"))
    hit = db.lookup(md5="44d88612fea8a8f36de82e1278abb02f")
    assert hit and hit["family"] == "test"


def test_add_and_lookup(tmp_path):
    db = SignatureDB(str(tmp_path / "sigs.db"))
    n = db.add(
        sha256="a" * 64,
        name="Test.Threat.A",
        md5="b" * 32,
        family="testfam",
        severity=9,
    )
    assert n == 1
    assert db.lookup(sha256="a" * 64)["severity"] == 9


def test_import_export_roundtrip(tmp_path):
    db_path = str(tmp_path / "sigs.db")
    db = SignatureDB(db_path)
    payload = {
        "signatures": [
            {"sha256": "c" * 64, "name": "Imported.Threat", "severity": 10},
            {"name": "missing-hash"},
        ]
    }
    src = tmp_path / "in.json"
    src.write_text(json.dumps(payload))
    imported = db.import_json(str(src))
    assert imported == 1
    out = tmp_path / "out.json"
    exported = db.export_json(str(out))
    assert exported == db.count()
    restored = json.loads(out.read_text())["signatures"]
    assert any(r["name"] == "Imported.Threat" for r in restored)


def test_severity_clamped(tmp_path):
    db = SignatureDB(str(tmp_path / "sigs.db"))
    db.add(sha256="d" * 64, name="Clamp", severity=99)
    assert db.lookup(sha256="d" * 64)["severity"] == 10
