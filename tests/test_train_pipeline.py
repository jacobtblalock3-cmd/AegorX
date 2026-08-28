import hashlib
import json
import os

import pytest

import train_ember as te


def write_jsonl(path, records):
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def ember_record(label, entropy, size, imports):
    return {
        "label": label,
        "general": {"size": size},
        "header": {
            "coff": {"timestamp": 0, "machine": 0x14C, "characteristics": ["EXECUTABLE_IMAGE"]},
            "optional": {"subsystem": 2, "dll_characteristics": [], "address_of_entry_point": 4096},
        },
        "section": [{"name": ".text", "size": size, "entropy": entropy, "virtual_size": size, "virtual_address": 4096}],
        "imports": imports,
        "data_directories": {"IMAGE_DIRECTORY_ENTRY_IMPORT": {"virtual_address": 1, "size": 10}},
        "overlay": {"offset": size, "size": 0},
    }


class FakeModel:
    instances = []

    def __init__(self, params):
        self.params = params
        FakeModel.instances.append(self)

    def fit(self, X, y):
        self.fitted_X = X
        self.fitted_y = list(y)
        return self

    def predict_proba(self, X):
        return [0.5 for _ in range(len(X))]

    def save_model(self, path):
        with open(path, "wb") as fh:
            fh.write(b"fake-booster-weights")


def test_roc_auc_perfect_and_reversed_and_half():
    assert te.roc_auc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == 1.0
    assert te.roc_auc([1, 1, 0, 0], [0.1, 0.2, 0.8, 0.9]) == 0.0
    assert te.roc_auc([0, 1], [0.5, 0.5]) == 0.5


def test_roc_auc_handles_ties():
    auc = te.roc_auc([0, 1, 0, 1], [0.4, 0.4, 0.6, 0.6])
    assert auc == 0.5


def test_iter_xy_filters_unlabeled_and_caps(tmp_path):
    recs = [
        ember_record(1, 7.5, 100, {"a.dll": ["WriteProcessMemory"]}),
        ember_record(0, 3.0, 200, {"b.dll": ["CreateFile"]}),
        ember_record(-1, 9.9, 300, {}),
        ember_record("junk", 9.9, 400, {}),
    ]
    path = str(tmp_path / "t.jsonl")
    write_jsonl(path, recs)
    X, y, counts = te.iter_xy(path)
    assert counts == {"benign": 1, "malicious": 1}
    assert sorted(y) == [0, 1]
    assert all(len(row) == len(te.FEATURE_NAMES) for row in X)

    capped = te.iter_xy(path, max_per_class=0)
    assert capped[2] == {"benign": 0, "malicious": 0}


def test_run_training_end_to_end_with_fake_booster(tmp_path):
    train = tmp_path / "train.jsonl"
    test = tmp_path / "test.jsonl"
    write_jsonl(train, [ember_record(1, 7.5, 100, {"k.dll": ["WinExec"]}), ember_record(0, 2.0, 500, {})] * 5)
    write_jsonl(test, [ember_record(1, 8.0, 120, {"k.dll": ["VirtualAllocEx"]}), ember_record(0, 2.5, 600, {})] * 3)

    out_dir = tmp_path / "out"
    meta = te.run_training(
        str(train),
        str(test),
        str(out_dir),
        rounds=5,
        model_factory=lambda params: FakeModel(params),
    )

    model_file = out_dir / "malware-ember.lgbm"
    meta_file = out_dir / "malware-ember.lgbm.meta.json"
    sums = out_dir / "SHA256SUMS"
    assert model_file.read_bytes() == b"fake-booster-weights"
    assert meta_file.exists() and sums.exists()

    assert meta["format"] == "aegorx-model-meta"
    assert meta["source"] == "EMBER 2018"
    assert meta["num_features"] == 35
    assert meta["test_auc"] == pytest.approx(0.5)
    assert meta["train_samples"] == {"benign": 5, "malicious": 5}
    expected_sha = hashlib.sha256(model_file.read_bytes()).hexdigest()
    assert meta["model_sha256"] == expected_sha
    assert f"{expected_sha}  malware-ember.lgbm" in sums.read_text()


def test_run_training_requires_both_classes(tmp_path):
    train = tmp_path / "train.jsonl"
    write_jsonl(train, [ember_record(0, 2.0, 100, {})])
    with pytest.raises(RuntimeError, match="both train and test"):
        te.run_training(str(train), str(train), str(tmp_path / "o"), model_factory=lambda p: FakeModel(p))


def test_meta_thresholds_present(tmp_path):
    train = tmp_path / "train.jsonl"
    test = tmp_path / "test.jsonl"
    write_jsonl(train, [ember_record(1, 7.5, 100, {}), ember_record(0, 2.0, 500, {})])
    write_jsonl(test, [ember_record(1, 8.0, 100, {}), ember_record(0, 2.5, 500, {})])
    meta = te.run_training(
        str(train), str(test), str(tmp_path / "out"), rounds=1, model_factory=lambda p: FakeModel(p)
    )
    assert meta["thresholds"]["malicious"] == 0.85


def test_iter_xy_rejects_precomputed_vectors(tmp_path):
    vec_file = tmp_path / "train_features_0.jsonl"
    with open(vec_file, "w") as fh:
        fh.write(json.dumps({"x": [0.1] * 2351, "y": 1}) + "\n")
    with pytest.raises(te.RawRecordsRequiredError, match="PRECOMPUTED"):
        te.iter_xy(str(vec_file))
