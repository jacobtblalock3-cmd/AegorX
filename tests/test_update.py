from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

from aegorx.management.agent import DASAgent
from aegorx.management.protocol import ALLOWED_COMMANDS, make_command, verify_command
from aegorx.signing.feed import sign_document
from aegorx.signing.keys import generate_keypair, trust_public_key
from aegorx.update import (
    DEFAULT_MANIFEST_URL,
    UpdateError,
    apply_update,
    build_manifest,
    check,
    download_artifact,
    fetch_manifest,
    parse_version,
    verify_manifest,
)


@pytest.fixture
def signing(tmp_path, tmp_home):
    """Generate a keypair and trust it in the isolated user store."""
    priv, pub = generate_keypair(str(tmp_path / "keys"))
    trust_public_key(pub)
    return priv


def signed_manifest(priv, version="99.0.0", url="https://releases.example/aegorx-99.0.0.whl"):
    data = b"aegorx-fake-artifact-payload"
    doc = build_manifest(
        version,
        [
            {
                "url": url,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        ],
        ttl_hours=24,
    )
    return sign_document(doc, priv), data


def test_build_manifest_requires_known_kind_and_fields():
    with pytest.raises(UpdateError):
        build_manifest("1.0.0", [])
    with pytest.raises(UpdateError):
        build_manifest("1.0.0", [{"url": "https://x/file.exe", "sha256": "a" * 64, "size": 1}])
    with pytest.raises(UpdateError):
        build_manifest("1.0.0", [{"url": "https://x/f.whl", "size": 1}])
    doc = build_manifest("1.0.0", [{"url": "https://x/aegorx-1.0.0-py3-none-any.whl", "sha256": "b" * 64, "size": 5}])
    assert doc["artifacts"]["wheel"]["url"].endswith(".whl")
    assert doc["format"] == "aegorx-update-manifest"


def test_verify_manifest_round_trip_and_tamper(tmp_path, signing):
    doc, _ = signed_manifest(signing)
    fp = verify_manifest(doc)
    assert len(fp) == 16
    tampered = json.loads(json.dumps(doc))
    tampered["artifacts"]["wheel"]["sha256"] = "0" * 64
    with pytest.raises(UpdateError, match="did not verify"):
        verify_manifest(tampered)
    bad_format = dict(doc)
    bad_format["format"] = "something-else"
    with pytest.raises(UpdateError, match="bad 'format'"):
        verify_manifest(bad_format)
    unsigned = {k: v for k, v in doc.items() if k != "signature"}
    with pytest.raises(UpdateError, match="no signature"):
        verify_manifest(unsigned)
    with pytest.raises(UpdateError, match="non-HTTPS"):
        verify_manifest({**doc, "artifacts": {"wheel": {"url": "http://x/y.whl", "sha256": "a" * 64, "size": 1}}})


class FakeResp:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, n=-1):
        take = self._data if n < 0 else self._data[:n]
        self._data = self._data[len(take):]
        return take

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _fake_opener(payload: bytes, seen=None):
    def opener(url, timeout=30):
        if seen is not None:
            seen.append(url)
        return FakeResp(payload)

    return opener


def test_check_reports_newer_version(tmp_path, signing):
    doc, _ = signed_manifest(signing, version="99.0.0")
    payload = json.dumps(doc).encode()
    result = check(current="0.9.0", opener=_fake_opener(payload))
    assert result["update_available"] is True
    assert result["available"] == "99.0.0"
    assert result["current"] == "0.9.0"
    same = check(current="99.0.0", opener=_fake_opener(payload))
    assert same["update_available"] is False
    older = check(current="100.0.0", opener=_fake_opener(payload))
    assert older["update_available"] is False


def test_check_rejects_unsigned_and_bad_signature(tmp_path, signing):
    doc, _ = signed_manifest(signing)
    broken = dict(doc)
    broken["signature"] = "AAAA"
    with pytest.raises(UpdateError):
        check(current="0.1.0", opener=_fake_opener(json.dumps(broken).encode()))
    raw = {"format": "aegorx-update-manifest", "manifest_version": 1}
    with pytest.raises(UpdateError, match="bad 'format'|no artifacts|no signature"):
        verify_manifest(raw)


def test_check_expired_manifest(tmp_path, signing):
    from datetime import datetime, timedelta, timezone

    doc, _ = signed_manifest(signing)
    doc["generated_utc"] = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(timespec="seconds")
    doc["expires_utc"] = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    doc = sign_document(doc, signing)
    payload = json.dumps(doc).encode()
    with pytest.raises(UpdateError, match="expired"):
        check(current="0.1.0", opener=_fake_opener(payload))
    ok = check(current="0.1.0", opener=_fake_opener(payload), allow_expired=True)
    assert ok["available"] == "99.0.0"


def test_fetch_manifest_rejects_non_https_default_guard():
    with pytest.raises(UpdateError, match="download failed"):
        fetch_manifest(url="http://insecure.example/manifest.json")
    assert DEFAULT_MANIFEST_URL.startswith("https://")


def test_download_artifact_verifies_hash_size_and_suffix(tmp_path, signing):
    _, data = signed_manifest(signing)
    entry = {
        "url": "https://releases.example/aegorx-99.0.0-py3-none-any.whl",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }
    dest = download_artifact(entry, str(tmp_path), opener=_fake_opener(data))
    assert open(dest, "rb").read() == data
    wrong_hash = dict(entry, sha256="0" * 64)
    with pytest.raises(UpdateError, match="checksum mismatch"):
        download_artifact(wrong_hash, str(tmp_path), opener=_fake_opener(data))
    wrong_size = dict(entry, size=len(data) + 1)
    with pytest.raises(UpdateError, match="size mismatch"):
        download_artifact(wrong_size, str(tmp_path), opener=_fake_opener(data))
    bad_name = dict(entry, url="https://releases.example/payload.bin")
    with pytest.raises(UpdateError, match="known suffix"):
        download_artifact(bad_name, str(tmp_path), opener=_fake_opener(data))
    insecure = dict(entry, url="http://releases.example/x.whl")
    with pytest.raises(UpdateError, match="non-HTTPS"):
        download_artifact(insecure, str(tmp_path), opener=_fake_opener(data))


def test_download_artifact_enforces_max_bytes(tmp_path, monkeypatch):
    from aegorx import update as upd

    monkeypatch.setattr(upd, "MAX_ARTIFACT_BYTES", 8)
    entry = {
        "url": "https://releases.example/big.whl",
        "sha256": hashlib.sha256(b"x" * 32).hexdigest(),
        "size": 32,
    }
    with pytest.raises(UpdateError, match="maximum size"):
        upd.download_artifact(entry, str(tmp_path), opener=_fake_opener(b"x" * 32))


def test_parse_version():
    assert parse_version("v1.2.3") == (1, 2, 3)
    assert parse_version("0.10.0") > parse_version("0.9.0")
    assert parse_version("1.0.0rc1") == (1, 0, 0)
    with pytest.raises(UpdateError):
        parse_version("banana")


def test_apply_update_downgrade_guard_and_installer(tmp_path):
    artifact = tmp_path / "f.whl"
    artifact.write_bytes(b"x")
    from aegorx import __version__

    with pytest.raises(UpdateError, match="downgrade"):
        apply_update(str(artifact), "0.0.1")
    outcome = apply_update(
        str(artifact),
        "0.0.1",
        force=True,
        installer_cmd=[sys.executable, "-c", "print('installer-ran')"],
    )
    assert outcome["returncode"] == 0
    assert "installer-ran" in outcome["output_tail"]
    failing = [sys.executable, "-c", "import sys; sys.exit(3)"]
    bad = apply_update(str(artifact), "0.0.1", force=True, installer_cmd=failing)
    assert bad["returncode"] == 3


def test_installer_selection(monkeypatch):
    import shutil

    from aegorx.update import _installer_for

    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/apt-get")
    cmd = _installer_for("/tmp/x_1.0_all.deb")
    assert cmd and cmd[0] == "apt-get"
    pip_cmd = _installer_for("/tmp/whl/dist.whl")
    assert pip_cmd and pip_cmd[-1] == "/tmp/whl/dist.whl" and "pip" in pip_cmd
    assert _installer_for("/tmp/random.bin") is None


def test_fleet_check_update_command(tmp_path, signing, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    doc, _ = signed_manifest(signing, version="99.0.0")

    def fake_check(**kw):
        return {
            "current": "0.9.0",
            "available": doc["version"],
            "update_available": True,
            "generated_utc": doc["generated_utc"],
        }

    monkeypatch.setattr("aegorx.update.check", fake_check)

    key = Ed25519PrivateKey.generate()
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    agent = DASAgent(
        cfg={
            "server_url": "https://console.example",
            "agent_id": "das-test",
            "api_token": "tok",
            "admin_public_key": pub_pem,
        }
    )
    assert "check-update" in ALLOWED_COMMANDS
    envelope = make_command("check-update", {}, private_key=key)
    body = verify_command(envelope, serialization.load_pem_public_key(pub_pem.encode()))
    result = agent.execute(envelope)
    assert body["command"] == "check-update"
    assert result["status"] == "done"
    assert result["available"] == "99.0.0"


def test_auto_apply_flow_with_fake_opener(tmp_path, signing, monkeypatch):
    import sys

    from aegorx import update as upd

    doc, data = signed_manifest(signing, version="99.0.0")
    manifest_payload = json.dumps(doc).encode()
    ran = {}

    def routing_opener(url, timeout=30):
        if url.endswith(".json"):
            return FakeResp(manifest_payload)
        return FakeResp(data)

    def fake_apply(path, target_version, force=False, **kw):
        ran["path"] = path
        ran["version"] = target_version
        ran["bytes"] = open(path, "rb").read()
        return {"returncode": 0, "output_tail": "", "error_tail": ""}

    monkeypatch.setattr(upd, "apply_update", fake_apply)
    outcome = upd.auto_apply(opener=routing_opener, dest_dir=str(tmp_path / "dl"))
    assert outcome["returncode"] == 0
    assert ran["version"] == "99.0.0"
    assert ran["bytes"] == data

    forced = upd.auto_apply(opener=routing_opener, force=True, dest_dir=str(tmp_path / "dl"))
    assert forced["target_version"] == "99.0.0"
