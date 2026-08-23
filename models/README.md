# Reference Model Distribution

Defentra's out-of-the-box ML detection ships as a **release artifact**, not in
git: LightGBM binaries do not belong in version control and users should always
be able to verify what they download.

## How the reference model is produced

1. Trigger **Actions -> Train reference model** (workflow_dispatch) on GitHub.
   The runner downloads EMBER 2018 (~800 MB compressed, >1M labeled PE files),
   maps every record onto Defentra's runtime feature schema
   (`defentra/ml/ember_map.py`), trains LightGBM, evaluates AUC on the official
   held-out test split, and uploads `malware-ember.lgbm` +
   `malware-ember.lgbm.meta.json` + `SHA256SUMS` as build artifacts.
2. Download the artifacts locally and publish:

   ```bash
   gh release create model-YYYYMMDD --draft \
       --title "EMBER reference model" \
       --notes "AUC=<from meta>; trained per models/README.md"
   cp malware-ember.lgbm defentra-ember-reference.lgbm
   gh release upload model-YYYYMMDD \
       defentra-ember-reference.lgbm malware-ember.lgbm.meta.json
   ```

   The asset name `defentra-ember-reference.lgbm` is what
   `defentra model fetch` resolves against the latest release.

## What users get

```bash
defentra model fetch     # downloads latest release asset into ~/.defentra/models/
defentra model info      # provenance: source dataset, AUC, feature version, sha256
```

`fetch` verifies the downloaded file against the SHA256 recorded in the
metadata sidecar before installing; a mismatch aborts the install. The engine
picks the model up automatically on the next scan or monitor session.

## Trust model & limitations

- The metadata sidecar is plain JSON fetched over HTTPS from the same release;
  it provides integrity (accidental corruption) but is not a cryptographic
  signature chain. For stronger guarantees, pin a specific release tag URL:
  `defentra model fetch --url https://github.com/.../download/<tag>/...`.
- EMBER 2018 covers Windows PE samples up to 2018. It will not catch post-2018
  families reliably; treat it as a baseline, not a substitute for signature
  feeds and YARA rules. Retrain periodically on fresher corpora.
