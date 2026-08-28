# Reference Model Distribution

AegorX's out-of-the-box ML detection ships as a **release artifact**, not in
git: LightGBM binaries do not belong in version control and users should always
be able to verify what they download.

## Dataset availability (important)

AegorX trains on **raw** EMBER 2018 records (JSONL with
`general`/`header`/`section`/`imports` fields) so that training features are
identical to what the runtime extractor computes at scan time.

As of August 2026, the original raw archive is no longer served by its primary
hosts:

| Source | Status |
|---|---|
| `pubdata.endgame.com/ember/ember_dataset.tar.bz2` | dead (domain retired) |
| `data.srimmer.xyz/ember/ember_dataset.tar.bz2` | dead |
| `ember.elastic.co/ember_dataset.tar.bz2` | serves **precomputed 2351-dim vectors only** (`train_features_*.jsonl`) — NOT trainable by AegorX |

The trainer and CI workflow detect vector-only inputs and fail with a clear
message instead of training a model that could never be loaded at runtime.

To run the training workflow, supply a raw-format archive via the
`dataset_url` dispatch input. Known acquisition paths for the raw records:
Kaggle mirrors of EMBER 2018 (requires Kaggle account), Academic Torrents,
or re-hosting an archived copy of the original tarball. If you operate a
public mirror of the raw dataset, open an issue/PR and we will point the
default workflow input at it.

## How the reference model is produced

1. Trigger **Actions -> Train reference model** (workflow_dispatch) on GitHub.
   The runner downloads EMBER 2018 (~800 MB compressed, >1M labeled PE files),
   maps every record onto AegorX's runtime feature schema
   (`aegorx/ml/ember_map.py`), trains LightGBM, evaluates AUC on the official
   held-out test split, and uploads `malware-ember.lgbm` +
   `malware-ember.lgbm.meta.json` + `SHA256SUMS` as build artifacts.
2. Download the artifacts locally and publish:

   ```bash
   gh release create model-YYYYMMDD --draft \
       --title "EMBER reference model" \
       --notes "AUC=<from meta>; trained per models/README.md"
   cp malware-ember.lgbm aegorx-ember-reference.lgbm
   gh release upload model-YYYYMMDD \
       aegorx-ember-reference.lgbm malware-ember.lgbm.meta.json
   ```

   The asset name `aegorx-ember-reference.lgbm` is what
   `aegorx model fetch` resolves against the latest release.

## What users get

```bash
aegorx model fetch     # downloads latest release asset into ~/.aegorx/models/
aegorx model info      # provenance: source dataset, AUC, feature version, sha256
```

`fetch` verifies the downloaded file against the SHA256 recorded in the
metadata sidecar before installing; a mismatch aborts the install. The engine
picks the model up automatically on the next scan or monitor session.

## Trust model & limitations

- The metadata sidecar is plain JSON fetched over HTTPS from the same release;
  it provides integrity (accidental corruption) but is not a cryptographic
  signature chain. For stronger guarantees, pin a specific release tag URL:
  `aegorx model fetch --url https://github.com/.../download/<tag>/...`.
- EMBER 2018 covers Windows PE samples up to 2018. It will not catch post-2018
  families reliably; treat it as a baseline, not a substitute for signature
  feeds and YARA rules. Retrain periodically on fresher corpora.
