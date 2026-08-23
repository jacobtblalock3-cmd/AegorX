#!/usr/bin/env python3
"""Train the Defentra reference ML detector on the EMBER 2018 dataset.

Downloads are NOT handled here; fetch the dataset first:

    curl -LO https://ember.elastic.co/ember_dataset.tar.bz2
    tar -xjf ember_dataset.tar.bz2        # -> ember2018/{train,test}.jsonl

Then:

    python scripts/train_ember.py \
        --train ember2018/train.jsonl --test ember2018/test.jsonl \
        --out-dir models/release

Outputs malware-ember.lgbm plus a signed-content metadata sidecar
(malware-ember.lgbm.meta.json) and SHA256SUMS. Attach the model to a GitHub
release as `defentra-ember-reference.lgbm` so users can run `defentra model fetch`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from defentra.ml.ember_map import ember_record_to_features, parse_label
from defentra.ml.features import FEATURE_NAMES, FEATURE_VERSION, vectorize

MODEL_FILENAME = "malware-ember.lgbm"
META_SUFFIX = ".meta.json"


def iter_xy(path: str, max_per_class: Optional[int] = None) -> Tuple[List[List[float]], List[int], Dict[str, int]]:
    counts = {"benign": 0, "malicious": 0}
    X: List[List[float]] = []
    y: List[int] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = parse_label(record.get("label"))
            if label is None:
                continue
            if label == 1:
                if max_per_class is not None and counts["malicious"] >= max_per_class:
                    continue
                counts["malicious"] += 1
            else:
                if max_per_class is not None and counts["benign"] >= max_per_class:
                    continue
                counts["benign"] += 1
            X.append(vectorize(ember_record_to_features(record)))
            y.append(label)
    return X, y, counts


def roc_auc(y_true: List[int], scores: List[float]) -> float:
    """Ties-aware AUC via the Mann-Whitney U statistic (no sklearn dependency)."""
    n = len(y_true)
    order = sorted(range(n), key=lambda i: scores[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1
    positives = sum(1 for v in y_true if v == 1)
    negatives = n - positives
    if positives == 0 or negatives == 0:
        return 0.5
    rank_sum = sum(r for r, v in zip(ranks, y_true) if v == 1)
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class RealModel:
    """LightGBM-backed trainer conforming to the injectable model interface."""

    def __init__(self, params: Dict):
        import lightgbm as lgb

        self._clf = lgb.LGBMClassifier(**params)

    def fit(self, X, y) -> "RealModel":
        self._clf.fit(X, y)
        return self

    def predict_proba(self, X) -> List[float]:
        return [float(p) for p in self._clf.predict_proba(X)[:, 1]]

    def save_model(self, path: str) -> None:
        self._clf.booster_.save_model(path)


def default_params(rounds: int) -> Dict:
    return {
        "n_estimators": rounds,
        "learning_rate": 0.05,
        "num_leaves": 63,
        "min_child_samples": 20,
        "colsample_bytree": 0.9,
        "subsample": 0.9,
        "subsample_freq": 1,
        "objective": "binary",
        "random_state": 42,
    }


def write_meta(out_dir: str, test_auc: float, counts_train: Dict, counts_test: Dict) -> Dict:
    model_path = os.path.join(out_dir, MODEL_FILENAME)
    meta = {
        "format": "defentra-model-meta",
        "meta_version": 1,
        "source": "EMBER 2018",
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "feature_version": FEATURE_VERSION,
        "num_features": len(FEATURE_NAMES),
        "model_file": MODEL_FILENAME,
        "model_sha256": sha256_file(model_path),
        "train_samples": counts_train,
        "test_samples": counts_test,
        "test_auc": round(test_auc, 6),
        "thresholds": {"malicious": 0.85, "suspicious": 0.60},
    }
    meta_path = os.path.join(out_dir, MODEL_FILENAME + META_SUFFIX)
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    sums_path = os.path.join(out_dir, "SHA256SUMS")
    with open(sums_path, "w", encoding="utf-8") as fh:
        fh.write(f"{meta['model_sha256']}  {MODEL_FILENAME}\n")
    return meta


def run_training(
    train_path: str,
    test_path: str,
    out_dir: str,
    rounds: int = 300,
    max_per_class: Optional[int] = None,
    model_factory: Optional[Callable[[Dict], object]] = None,
) -> Dict:
    import numpy as np

    print(f"[+] loading train set: {train_path}")
    X, y, counts_train = iter_xy(train_path, max_per_class=max_per_class)
    print(f"    benign={counts_train['benign']} malicious={counts_train['malicious']}")
    print(f"[+] loading held-out test set: {test_path}")
    Xt, yt, counts_test = iter_xy(test_path, max_per_class=max_per_class)
    print(f"    benign={counts_test['benign']} malicious={counts_test['malicious']}")

    if not X or not Xt or len(set(y)) < 2 or len(set(yt)) < 2:
        raise RuntimeError("both train and test sets need labeled benign AND malicious samples")

    factory = model_factory or (lambda params: RealModel(params))
    print("[+] training LightGBM...")
    model = factory(default_params(rounds)).fit(np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int32))

    probs = model.predict_proba(np.asarray(Xt, dtype=np.float32))
    auc = roc_auc(yt, probs)
    print(f"[+] test AUC: {auc:.4f}")

    os.makedirs(out_dir, exist_ok=True)
    model_path = os.path.join(out_dir, MODEL_FILENAME)
    model.save_model(model_path)
    print(f"[+] saved {model_path}")

    meta = write_meta(out_dir, auc, counts_train, counts_test)
    print(f"[+] wrote metadata ({meta['num_features']} features, sha256={meta['model_sha256'][:16]}...)")
    print(f"[+] publish: attach as release asset named 'defentra-ember-reference.lgbm'")
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True, help="path to ember train.jsonl")
    parser.add_argument("--test", required=True, help="path to ember test.jsonl")
    parser.add_argument("--out-dir", default="models/release")
    parser.add_argument("--rounds", type=int, default=300)
    parser.add_argument("--max-per-class", type=int, default=None, help="cap samples per class (smoke tests)")
    args = parser.parse_args()

    try:
        run_training(args.train, args.test, args.out_dir, rounds=args.rounds, max_per_class=args.max_per_class)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
