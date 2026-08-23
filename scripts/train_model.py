#!/usr/bin/env python3
"""Train the Defentra static-analysis malware classifier.

Builds a LightGBM model from two directories of labeled binaries:

    python scripts/train_model.py --benign /usr/bin --malicious ./malware-samples

The trained model is written to ~/.defentra/models/malware.lgbm and is picked up
automatically by the engine on the next scan.

For a larger corpus, the EMBER 2018 dataset (https://ember.readthedocs.io)
provides >1M labeled PE files; adapt the loader in main() to its JSONL format.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from defentra.ml.features import FEATURE_NAMES, extract_features, vectorize


def collect(root: str, label: int):
    X, y = [], []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                feats = extract_features(path)
            except OSError:
                continue
            if feats["is_pe"] == 0.0 and feats["is_elf"] == 0.0:
                continue
            X.append(vectorize(feats))
            y.append(label)
    return X, y


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign", required=True, help="directory of known-good binaries")
    parser.add_argument("--malicious", required=True, help="directory of known-bad samples")
    parser.add_argument("--out", default=None, help="output .lgbm path (default ~/.defentra/models)")
    parser.add_argument("--rounds", type=int, default=300)
    args = parser.parse_args()

    try:
        import numpy as np
        import lightgbm as lgb
    except Exception:
        print("error: install ML deps first: pip install 'defentra[ml]'", file=sys.stderr)
        return 3

    print(f"[+] extracting features from benign corpus: {args.benign}")
    X_benign, y_benign = collect(args.benign, 0)
    print(f"    {len(X_benign)} executable(s)")
    print(f"[+] extracting features from malicious corpus: {args.malicious}")
    X_mal, y_mal = collect(args.malicious, 1)
    print(f"    {len(X_mal)} sample(s)")

    if not X_benign or not X_mal:
        print("error: both corpora must contain at least one executable", file=sys.stderr)
        return 3

    X = np.asarray(X_benign + X_mal, dtype=np.float32)
    y = np.asarray(y_benign + y_mal, dtype=np.int32)

    model = lgb.LGBMClassifier(
        n_estimators=args.rounds,
        learning_rate=0.05,
        num_leaves=63,
        min_child_samples=10,
        colsample_bytree=0.9,
        subsample=0.9,
        subsample_freq=1,
        objective="binary",
    )
    print("[+] training LightGBM classifier...")
    model.fit(X, y)

    if args.out:
        out_path = args.out
    else:
        from defentra.utils import state_dir

        out_dir = os.path.join(state_dir(), "models")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "malware.lgbm")
    model.booster_.save_model(out_path)

    train_acc = model.score(X, y)
    print(f"[+] saved model to {out_path}")
    print(f"[+] training accuracy: {train_acc:.4f} over {len(FEATURE_NAMES)} features")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
