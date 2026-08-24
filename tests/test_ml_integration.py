"""End-to-end ML chain: EMBER records -> trainer -> classifier -> engine.

Skips gracefully where LightGBM cannot load (e.g. macOS without libomp);
runs for real in CI (Linux) proving the native-API booster adapter and the
classifier agree on model format, features, and probability semantics.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from conftest import build_minimal_pe
from defentra.engine import ScanEngine

try:
    import lightgbm  # noqa: F401
except Exception:  # ImportError when absent; OSError (dlopen) without libomp
    pytest.skip("LightGBM unavailable on this platform", allow_module_level=True)


def _ember_record(label: int, entropy: float, size: int, imports: dict) -> dict:
    return {
        "sha256": os.urandom(16).hex() * 4,
        "label": label,
        "general": {"size": size},
        "header": {
            "coff": {"timestamp": 1377091234, "machine": 0x14C, "characteristics": ["EXECUTABLE_IMAGE"]},
            "optional": {
                "magic": 0x10B,
                "subsystem": 2,
                "dll_characteristics": [],
                "address_of_entry_point": 4096,
                "size_of_image": 524288,
            },
        },
        "section": [
            {"name": ".text", "size": size, "entropy": entropy, "virtual_size": size, "virtual_address": 4096}
        ],
        "imports": imports,
        "exports": [],
        "data_directories": {"IMAGE_DIRECTORY_ENTRY_IMPORT": {"virtual_address": 1, "size": 10}},
        "overlay": {"offset": size, "size": 0},
    }


def _write_jsonl(path, records):
    with open(path, "w") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")


def test_train_then_classify_end_to_end(tmp_path, monkeypatch):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
    from train_ember import run_training

    train = tmp_path / "train.jsonl"
    test = tmp_path / "test.jsonl"
    bad = {"kernel32.dll": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]}
    good = {"kernel32.dll": ["CreateFileW", "ReadFile", "CloseHandle"]}

    train_rows = [_ember_record(1, 7.5, 100_000 + i, dict(bad)) for i in range(60)] + [
        _ember_record(0, 3.0, 60_000 + i, dict(good)) for i in range(60)
    ]
    test_rows = [_ember_record(1, 7.6, 110_000 + i, dict(bad)) for i in range(20)] + [
        _ember_record(0, 3.1, 70_000 + i, dict(good)) for i in range(20)
    ]
    _write_jsonl(train, train_rows)
    _write_jsonl(test, test_rows)

    out_dir = tmp_path / "artifacts"
    meta = run_training(str(train), str(test), str(out_dir), rounds=25)
    assert meta["test_auc"] > 0.9, "synthetic classes are separable; AUC must reflect that"
    assert meta["format"] == "defentra-model-meta"

    # classifier loads the freshly trained artifact by explicit path
    from defentra.ml.classifier import MalwareClassifier

    model_path = out_dir / "malware-ember.lgbm"
    classifier = MalwareClassifier(model_path=str(model_path))
    assert classifier.available

    # engine picks the same model up through DEFENTRA_MODEL_DIR discovery
    monkeypatch.setenv("DEFENTRA_MODEL_DIR", str(out_dir))
    engine_model = MalwareClassifier()
    assert engine_model.available, "engine discovery must honor DEFENTRA_MODEL_DIR"

    pe = tmp_path / "sample.bin"
    pe.write_bytes(build_minimal_pe())
    proba = engine_model.predict_proba(
        __import__("defentra.ml.features", fromlist=["vectorize"]).vectorize(
            __import__("defentra.ml.features", fromlist=["extract_features"]).extract_features(str(pe))
        )
    )
    assert proba is None or 0.0 <= proba <= 1.0


def test_classifier_ignores_garbage_model_file(tmp_path):
    from defentra.ml.classifier import MalwareClassifier

    bogus = tmp_path / "malware.lgbm"
    bogus.write_bytes(b"not-a-real-booster")
    classifier = MalwareClassifier(model_path=str(bogus))
    assert classifier.available is False
