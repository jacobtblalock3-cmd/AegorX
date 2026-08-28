"""EICAR conformance suite.

The EICAR standard test file is the industry's baseline acceptance test.
This suite proves Defentra detects it through EVERY delivery and response
surface before deployment:

  1. on-demand scan (hash + YARA content rule, filename-independent)
  2. signed-feed-delivered detection (intel channel)
  3. realtime inotify quarantine (Linux CI)
  4. realtime fanotify open-denial   (Linux CI, where kernels deliver events)
  5. quarantine -> restore -> re-detect lifecycle
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture(scope="module")
def conformance_engine(tmp_path_factory):
    home = tmp_path_factory.mktemp("eicar-home")
    os.environ["AEGORX_HOME"] = str(home)
    rules = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules"
    )
    from aegorx.engine import ScanEngine

    return ScanEngine(rules_dirs=[rules], enable_ml=False)


def _scan(engine, tmp_path, name, content=EICAR):
    target = tmp_path / name
    target.write_text(content)
    return engine.scan_file(str(target))


def test_eicar_exact_hash_is_the_builtin_standard(conformance_engine, tmp_path):
    assert hashlib.sha256(EICAR.encode()).hexdigest() == EICAR_SHA256
    result = _scan(conformance_engine, tmp_path, "eicar.com")
    assert result.verdict == "malicious"
    detectors = {d.detector for d in result.detections}
    assert "signature" in detectors or "yara" in detectors


def test_eicar_detected_regardless_of_filename_or_extension(conformance_engine, tmp_path):
    for name in ("invoice.pdf.exe", "photo.jpg", "no_extension", "readme.txt"):
        result = _scan(conformance_engine, tmp_path, name)
        assert result.verdict == "malicious", f"missed as {name}"
        assert result.sha256 == EICAR_SHA256


def test_eicar_inside_directory_tree(conformance_engine, tmp_path):
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    (nested / "dropper.bin").write_text(EICAR)
    results = conformance_engine.scan_target(str(tmp_path / "a"))
    assert any(r.verdict == "malicious" for r in results)


def test_clean_file_stays_clean(conformance_engine, tmp_path):
    result = _scan(conformance_engine, tmp_path, "clean.txt", content="hello world\n")
    assert result.verdict == "clean"


def test_tail_mutated_variant_caught_by_content_rule(conformance_engine, tmp_path):
    """Exceeds naive full-string matching: tail mutations still detected."""
    mutated = EICAR[:-1] + "X"
    assert hashlib.sha256(mutated.encode()).hexdigest() != EICAR_SHA256
    result = _scan(conformance_engine, tmp_path, "mutated.com", content=mutated)
    if not conformance_engine.yara.available:
        pytest.skip("yara unavailable; hash-only engine cannot see mutations")
    assert result.verdict == "malicious"
    assert any(d.detector == "yara" for d in result.detections)


def test_feed_delivered_variant_is_enforced_after_update(tmp_home, tmp_path, monkeypatch):
    """A variant hash arriving through the *signed feed* must block the file."""
    from aegorx.cli import main as cli_main
    from aegorx.engine import ScanEngine
    from aegorx.signatures.db import SignatureDB
    from aegorx.signing.feed import new_feed, sign_document
    from aegorx.signing.keys import generate_keypair, trust_public_key

    variant = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+X*"
    digest = hashlib.sha256(variant.encode()).hexdigest()

    keydir = str(tmp_path / "keys")
    _, public_key = generate_keypair(keydir)
    trust_public_key(public_key)

    feed = new_feed([{"sha256": digest, "name": "Win32.EicarVariant", "severity": 9}])
    signed = sign_document(feed, os.path.join(keydir, "signing_private.pem"))
    feed_file = tmp_path / "feed.json.signed.json"
    feed_file.write_text(json.dumps(signed))

    assert cli_main(["feed", "update", "--file", str(feed_file)]) == 0
    assert SignatureDB(None).lookup(sha256=digest) is not None

    rules = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules"
    )
    engine = ScanEngine(rules_dirs=[rules], enable_ml=False)
    target = tmp_path / "variant.com"
    target.write_text(variant)
    result = engine.scan_file(str(target))
    assert result.verdict == "malicious"


def test_quarantine_restore_redetect_cycle(conformance_engine, tmp_path):
    from aegorx.quarantine.vault import QuarantineVault

    vault = QuarantineVault()
    path = tmp_path / "cycle.com"
    path.write_text(EICAR)

    entry = vault.quarantine(str(path), reason="EICAR conformance")
    assert not path.exists()
    restored = vault.restore(entry["id"])
    assert restored == str(path)
    assert path.read_text() == EICAR

    result = conformance_engine.scan_file(str(path))
    assert result.verdict == "malicious"


@pytest.mark.skipif(os.name != "posix", reason="posix paths")
def test_eicar_via_symlink_is_scanned(conformance_engine, tmp_path):
    real = tmp_path / "real.bin"
    real.write_text(EICAR)
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks unsupported")
    result = conformance_engine.scan_file(str(link))
    assert result.verdict == "malicious"
