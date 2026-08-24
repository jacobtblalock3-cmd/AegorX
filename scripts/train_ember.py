#!/usr/bin/env python3
"""Train the Defentra classifier from the EMBER 2018 dataset.

Streams EMBER's raw JSONL records through defentra.ml.ember_map, projecting
them into the exact runtime feature schema the scanner uses — a million-scale
supervised signal with zero drift between training and inference.

    python scripts/train_ember.py --data-dir ember/ --out-dir artifacts \
        [--rounds 500] [--max-per-class 300000] [--sign-key signing.pem]

Artifacts: malware-ember.lgbm + Ed25519-signable .meta.json + SHA256SUMS.
"""

from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import json
import os
import sys
import time
from typing import Callable, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from defentra.ml.ember_map import ember_record_to_features, parse_label
from defentra.ml.features import FEATURE_NAMES, FEATURE_VERSION, vectorize

MALICIOUS_THRESHOLD = 0.85
SUSPICIOUS_THRESHOLD = 0.60
DEFAULT_MODEL_NAME = "malware-ember.lgbm"


class RawRecordsRequiredError(RuntimeError):
    """Raised when an input file holds precomputed vectors instead of raw records."""


def _is_precomputed_vector(record: dict) -> bool:
    return isinstance(record.get("x"), list)


def iter_xy(
    path: str, max_per_class: Optional[int] = None
) -> Tuple[List[List[float]], List[int], dict]:
    """Stream one JSONL file into (X, y, counts).

    Unlabeled rows (EMBER uses -1) and malformed labels are skipped. When
    max_per_class is set, each class stops contributing after that many rows;
    0 disables collection entirely (useful for probing file contents).
    """
    X: List[List[float]] = []
    y: List[int] = []
    counts = {"benign": 0, "malicious": 0}
    taken = {0: 0, 1: 0}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            if _is_precomputed_vector(record):
                raise RawRecordsRequiredError(
                    f"{path}: PRECOMPUTED vector records are not trainable; "
                    "Defentra needs raw EMBER records with general/header/"
                    "section/imports groups"
                )
            label = parse_label(record.get("label"))
            if label is None:
                continue
            if max_per_class is not None and taken[label] >= max_per_class:
                continue
            taken[label] += 1
            X.append(vectorize(ember_record_to_features(record)))
            y.append(label)
            counts["malicious" if label == 1 else "benign"] += 1
    return X, y, counts


def roc_auc(y_true: List[int], scores: List[float]) -> float:
    """Rank-based AUC with tie handling (Mann-Whitney statistic)."""
    pos = sum(1 for v in y_true if v == 1)
    neg = sum(1 for v in y_true if v == 0)
    if pos == 0 or neg == 0:
        return 0.5
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(order)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg_rank = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1
    rank_sum = sum(r for r, v in zip(ranks, y_true) if v == 1)
    return (rank_sum - pos * (pos + 1) / 2) / (pos * neg)


class _NativeBooster:
    """sklearn-style fit/predict_proba/save_model over LightGBM's native API.

    Keeps scikit-learn out of the [ml] extra — inference (ml/classifier.py)
    also uses the native booster, so training and deployment stay aligned.
    """

    def __init__(self, params: dict):
        self._rounds = params["n_estimators"]
        self._params = {
            "objective": params.get("objective", "binary"),
            "learning_rate": params["learning_rate"],
            "num_leaves": params["num_leaves"],
            "min_data_in_leaf": params["min_child_samples"],
            "feature_fraction": params["colsample_bytree"],
            "bagging_fraction": params["subsample"],
            "bagging_freq": params["subsample_freq"],
            "verbose": -1,
        }
        self.booster = None

    def fit(self, X, y):
        import lightgbm as lgb

        dtrain = lgb.Dataset(X, label=y)
        self.booster = lgb.train(self._params, dtrain, num_boost_round=self._rounds)
        return self

    def predict_proba(self, X):
        import numpy as np

        positive = self.booster.predict(X)
        return np.column_stack([1.0 - positive, positive])

    def save_model(self, path: str) -> None:
        self.booster.save_model(path)


def _default_model_factory(params: dict):
    import lightgbm as lgb  # noqa: F401  (fail fast with a clear message)

    return _NativeBooster(params)


def _proba_column(proba) -> List[float]:
    rows = list(proba)
    if rows and isinstance(rows[0], (list, tuple)):
        return [float(row[1]) for row in rows]
    return [float(p) for p in rows]


def _collect(paths, X: list, y: list, max_per_class: Optional[int]) -> dict:
    totals = {"benign": 0, "malicious": 0}
    taken = {0: 0, 1: 0}
    if isinstance(paths, str):
        paths = [paths]
    for path in paths:
        Xp, yp, counts = iter_xy(path, max_per_class=None)
        for vec, label in zip(Xp, yp):
            if max_per_class is not None and taken[label] >= max_per_class:
                continue
            taken[label] += 1
            X.append(vec)
            y.append(label)
        totals["benign"] += counts["benign"]
        totals["malicious"] += counts["malicious"]
        print(f"[+] {path}: {counts}")
    return totals


def run_training(
    train,
    test,
    out_dir: str,
    rounds: int = 400,
    max_per_class: Optional[int] = None,
    learning_rate: float = 0.05,
    sign_key: Optional[str] = None,
    model_factory: Optional[Callable[[dict], object]] = None,
) -> dict:
    """Train on `train`, evaluate on `test`, write artifacts into `out_dir`.

    `train`/`test` are JSONL paths (str or list of str for multi-part sets).
    Returns the metadata dict written next to the model. Raises RuntimeError
    unless both classes appear in both splits.
    """
    os.makedirs(out_dir, exist_ok=True)
    X_train: List[List[float]] = []
    y_train: List[int] = []
    X_test: List[List[float]] = []
    y_test: List[int] = []

    train_counts = _collect(train, X_train, y_train, max_per_class)
    test_counts = _collect(test, X_test, y_test, None)

    if not ({0, 1}.issubset(set(y_train)) and {0, 1}.issubset(set(y_test))):
        raise RuntimeError(
            "both train and test splits must contain benign and malicious "
            f"samples (train={train_counts}, test={test_counts})"
        )

    import numpy as np

    params = {
        "n_estimators": rounds,
        "learning_rate": learning_rate,
        "num_leaves": 63,
        "min_child_samples": 20,
        "colsample_bytree": 0.9,
        "subsample": 0.9,
        "subsample_freq": 1,
        "objective": "binary",
    }
    factory = model_factory or _default_model_factory
    model = factory(params)
    started = time.time()
    model.fit(np.asarray(X_train, dtype=np.float32), np.asarray(y_train, dtype=np.int32))
    elapsed = time.time() - started

    proba = _proba_column(model.predict_proba(np.asarray(X_test, dtype=np.float32)))
    auc = roc_auc(y_test, proba)

    def metrics_at(threshold: float) -> dict:
        tp = fp = fn = tn = 0
        for score, actual in zip(proba, y_test):
            predicted_malicious = score >= threshold
            if predicted_malicious and actual == 1:
                tp += 1
            elif predicted_malicious:
                fp += 1
            elif actual == 1:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fp / max(1, fp + tn), 6),
        }

    model_path = os.path.join(out_dir, DEFAULT_MODEL_NAME)
    model.save_model(model_path)
    digest = hashlib.sha256(open(model_path, "rb").read()).hexdigest()

    meta = {
        "format": "defentra-model-meta",
        "source": "EMBER 2018",
        "model_sha256": digest,
        "feature_version": FEATURE_VERSION,
        "num_features": len(FEATURE_NAMES),
        "train_samples": {"benign": train_counts["benign"], "malicious": train_counts["malicious"]},
        "test_samples": {"benign": test_counts["benign"], "malicious": test_counts["malicious"]},
        "test_auc": round(auc, 4),
        "thresholds": {
            "malicious": MALICIOUS_THRESHOLD,
            "suspicious": SUSPICIOUS_THRESHOLD,
        },
        "metrics_at_thresholds": {
            "malicious": metrics_at(MALICIOUS_THRESHOLD),
            "suspicious": metrics_at(SUSPICIOUS_THRESHOLD),
        },
        "train_seconds": round(elapsed, 1),
        "trained_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if sign_key:
        from defentra.signing.keys import load_private_key

        payload = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
        meta["signature"] = base64.b64encode(load_private_key(sign_key).sign(payload)).decode("ascii")

    meta_path = model_path + ".meta.json"
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
        fh.write("\n")

    sums_path = os.path.join(out_dir, "SHA256SUMS")
    with open(sums_path, "w", encoding="utf-8") as fh:
        for name in (DEFAULT_MODEL_NAME, DEFAULT_MODEL_NAME + ".meta.json"):
            blob = open(os.path.join(out_dir, name), "rb").read()
            fh.write(f"{hashlib.sha256(blob).hexdigest()}  {name}\n")

    print(f"[+] test AUC={meta['test_auc']} | malicious@{MALICIOUS_THRESHOLD}: {meta['metrics_at_thresholds']['malicious']}")
    print(f"[+] saved {model_path}")
    return meta


def _resolve_split(data_dir: str, kind: str) -> List[str]:
    # Recursive: archives commonly nest the JSONL parts one or more levels deep.
    primary = sorted(glob.glob(os.path.join(data_dir, "**", f"{kind}_features_*.jsonl"), recursive=True))
    fallback = [
        p
        for p in sorted(glob.glob(os.path.join(data_dir, "**", f"{kind}*.jsonl"), recursive=True))
        if p not in primary
    ]
    paths = primary or fallback
    if not paths:
        raise FileNotFoundError(f"no '{kind}*' JSONL files under {data_dir}")
    return paths


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=None, help="directory containing EMBER *.jsonl")
    parser.add_argument("--train", default=None, help="explicit training JSONL path(s), comma-separated")
    parser.add_argument("--test", default=None, help="explicit held-out JSONL path(s), comma-separated")
    parser.add_argument("--out-dir", default=None, help="artifact directory (default ~/.defentra/models)")
    parser.add_argument("--rounds", type=int, default=400)
    parser.add_argument("--max-per-class", type=int, default=None, help="cap per class (0 disables the cap)")
    parser.add_argument("--sign-key", default=None, help="Ed25519 private key PEM to sign the metadata sidecar")
    args = parser.parse_args(argv)

    if args.train or args.test:
        if not (args.train and args.test):
            parser.error("--train and --test must be provided together")
        trains = args.train.split(",")
        tests = args.test.split(",")
    elif args.data_dir:
        trains = _resolve_split(args.data_dir, "train")
        tests = _resolve_split(args.data_dir, "test")
    else:
        parser.error("provide --data-dir or explicit --train/--test")

    out_dir = args.out_dir or os.path.join(os.path.expanduser("~"), ".defentra", "models")
    cap = args.max_per_class if args.max_per_class else None
    try:
        meta = run_training(
            trains,
            tests,
            out_dir,
            rounds=args.rounds,
            max_per_class=cap,
            sign_key=args.sign_key,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    print(f"[+] model sha256 {meta['model_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
