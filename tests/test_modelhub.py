import hashlib
import json
import os

import pytest

from aegorx.ml import modelhub


class FakeResp:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, n=-1):
        if n == -1 or n >= len(self._data):
            out, self._data = self._data, b""
            return out
        out, self._data = self._data[:n], self._data[n:]
        return out

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def make_opener(model_bytes, meta_bytes, seen_urls):
    def opener(url, timeout=0):
        seen_urls.append(url)
        if url.endswith(".meta.json"):
            return FakeResp(meta_bytes)
        return FakeResp(model_bytes)

    return opener


def test_fetch_installs_model_and_meta(tmp_home, monkeypatch):
    monkeypatch.setenv("AEGORX_MODEL_DIR", os.path.join(tmp_home, "models"))
    model_bytes = b"\x00lgbm-fake-weights\x00"
    meta = {
        "source": "EMBER 2018",
        "model_sha256": hashlib.sha256(model_bytes).hexdigest(),
        "test_auc": 0.99,
    }
    seen = []
    dest = modelhub.fetch(
        url="https://example.test/model.lgbm",
        opener=make_opener(model_bytes, json.dumps(meta).encode(), seen),
    )
    assert dest.endswith("malware.lgbm")
    assert open(dest, "rb").read() == model_bytes
    loaded = json.loads(open(dest + ".meta.json").read())
    assert loaded["test_auc"] == 0.99
    assert seen == ["https://example.test/model.lgbm", "https://example.test/model.lgbm.meta.json"]
    assert not os.path.exists(dest + ".tmp")


def test_fetch_rejects_checksum_mismatch(tmp_home, monkeypatch):
    monkeypatch.setenv("AEGORX_MODEL_DIR", os.path.join(tmp_home, "models"))
    bad_meta = json.dumps({"model_sha256": "f" * 64}).encode()
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        modelhub.fetch(
            url="https://example.test/m.lgbm",
            opener=make_opener(b"corrupt", bad_meta, []),
        )
    assert modelhub.installed_models() == []


def test_fetch_without_meta_still_installs(tmp_home, monkeypatch):
    monkeypatch.setenv("AEGORX_MODEL_DIR", os.path.join(tmp_home, "models"))

    def opener(url, timeout=0):
        if url.endswith(".meta.json"):
            raise OSError("no such asset")
        return FakeResp(b"model-bytes")

    dest = modelhub.fetch(url="https://example.test/m.lgbm", opener=opener)
    assert os.path.exists(dest)
    assert not os.path.exists(dest + ".meta.json")


def test_installed_models_listing(tmp_home, monkeypatch):
    d = os.path.join(tmp_home, "models")
    monkeypatch.setenv("AEGORX_MODEL_DIR", d)
    os.makedirs(d)
    open(os.path.join(d, "a.lgbm"), "wb").write(b"x")
    open(os.path.join(d, "b.lgbm.meta.json"), "w").write("{}")
    open(os.path.join(d, "notes.txt"), "w").write("x")
    listed = [os.path.basename(p) for p in modelhub.installed_models()]
    assert listed == ["a.lgbm"]


def test_cli_model_fetch_wiring(tmp_home, monkeypatch):
    from aegorx.cli import main as cli_main

    monkeypatch.setenv("AEGORX_MODEL_DIR", os.path.join(tmp_home, "models"))
    called = {}

    def fake_fetch(url=None, **kwargs):
        called["url"] = url
        dest_dir = os.environ["AEGORX_MODEL_DIR"]
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, "malware.lgbm")
        open(dest, "wb").write(b"x")
        return dest

    monkeypatch.setattr(modelhub, "fetch", fake_fetch)
    rc = cli_main(["model", "fetch", "--url", "https://custom.example/m.lgbm"])
    assert rc == 0
    assert called["url"] == "https://custom.example/m.lgbm"


def test_classifier_picks_up_metadata_sidecar(tmp_home, tmp_path, monkeypatch):
    import sys
    import types

    from aegorx.ml.classifier import MalwareClassifier

    d = os.path.join(tmp_path, "models")
    os.makedirs(d)
    model_path = os.path.join(d, "malware.lgbm")
    with open(model_path, "wb") as fh:
        fh.write(b"fake-booster")
    meta = {"source": "EMBER 2018", "test_auc": 0.98}
    with open(model_path + ".meta.json", "w") as fh:
        fh.write(json.dumps(meta))

    captured = {}

    class FakeBooster:
        def __init__(self, model_file=None):
            captured["path"] = model_file

        def num_feature(self):
            return 35

        def predict(self, X):
            return [0.9 for _ in X]

    fake_lgb = types.ModuleType("lightgbm")
    fake_lgb.Booster = FakeBooster
    monkeypatch.setitem(sys.modules, "lightgbm", fake_lgb)

    clf = MalwareClassifier(model_path=model_path)
    assert clf.available is True
    assert clf.metadata["test_auc"] == 0.98
    assert clf.info()["metadata"]["source"] == "EMBER 2018"
    assert clf.predict_proba([0.0] * 35) == pytest.approx(0.9)


def test_classifier_ignores_wrong_feature_count(tmp_path, monkeypatch):
    import sys
    import types

    from aegorx.ml.classifier import MalwareClassifier

    model_path = str(tmp_path / "bad.lgbm")
    open(model_path, "wb").write(b"x")

    class WrongBooster:
        def __init__(self, model_file=None):
            pass

        def num_feature(self):
            return 1234

    fake_lgb = types.ModuleType("lightgbm")
    fake_lgb.Booster = WrongBooster
    monkeypatch.setitem(sys.modules, "lightgbm", fake_lgb)

    clf = MalwareClassifier(model_path=model_path)
    assert clf.available is False
