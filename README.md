# Defentra

**Open-source AI-assisted antivirus engine** — the flagship project of the Defentra
cybersecurity suite. Linux-first, with a Python scan core and a Rust performance layer.

```
$ defentra scan ./suspicious-downloads/
Defentra scan report
Target : ./suspicious-downloads

  [MALICIOUS] ./suspicious-downloads/eicar.com
    sha256 : 275a021bbfb6489e54d471899f7db9d6324ae490a1527ddd0a3f97c17cd4a6c15
    hit    : [signature] EICAR-Test-File (severity 8)

--------------------------------------------------------------
2 file(s) scanned in 0.01s | clean=1 suspicious=0 malicious=1 error=0
THREATS FOUND
engines: signatures=1 | yara=2 rule file(s) | ml=not found (train with scripts/train_model.py) | hash=python
```

## Architecture

| Layer      | Tech                | Role                                                        |
|------------|---------------------|-------------------------------------------------------------|
| CLI        | argparse            | `scan`, `db`, `quarantine`, `model`, `monitor` commands       |
| Engine     | Python              | Orchestrates detectors, computes verdicts                    |
| Real-time  | ctypes (Linux)      | fanotify blocking on-access + inotify watch mode             |
| Signatures | SQLite              | MD5/SHA-1/SHA-256 known-threat lookups (JSON import/export)  |
| YARA       | yara-python         | Pattern/rule-based detection (`rules/*.yar`)                 |
| ML         | LightGBM            | Static-feature malware classifier (PE + ELF)                 |
| Model hub  | urllib              | Release-asset reference model, SHA256-verified install       |
| Features   | Pure Python         | PE/ELF header parsing, section entropy, import analysis      |
| Quarantine | Fernet (optional)   | Encrypted vault with restore/audit trail                     |
| Fast path  | Rust + PyO3         | Streaming SHA-256 for large files (`rust-core/`)             |

### Detection flow per file

1. **Hash lookup** — SHA-256 → SHA-1 → MD5 against the signature DB.
2. **YARA rules** — compiled from `rules/` directories.
3. **ML classifier** — if the file is a PE/ELF and a trained model exists,
   ~35 static features (entropy, section flags, suspicious imports, NX/PIE, …)
   feed a LightGBM booster that outputs a malware probability.
4. **Verdict policy**
   - `malicious`: severity ≥ 8 or ML ≥ 0.85
   - `suspicious`: severity ≥ 5 or ML ≥ 0.60
   - `clean`: otherwise

Exit codes: `0` clean · `1` suspicious · `2` malicious · `3` error.

## Quickstart

```bash
git clone https://github.com/defentra/defentra && cd defentra
python -m venv .venv && source .venv/bin/activate
pip install -e ".[yara,ml,quarantine,dev]"

defentra scan /path/to/check          # on-demand scan
defentra db stats                     # signature database info
defentra model fetch                  # install the EMBER reference model (ML out-of-the-box)
defentra model info                   # ML model status + provenance
defentra quarantine list              # vault contents
```

### Real-time protection (Linux)

```bash
# blocking on-access mode (root): malicious files are DENIED at open time
sudo defentra monitor --backend fanotify /

# watch mode (unprivileged): scans new/modified files, quarantines threats
defentra monitor ~/Downloads ~/tmp --backend inotify

# exclude paths (repeatable fnmatch patterns)
sudo defentra monitor / --exclude '/mnt/nfs/*' --exclude '*.iso'
```

| Backend    | Privileges | Behavior                                                        |
|------------|------------|-----------------------------------------------------------------|
| `fanotify` | root       | Blocks file opens until scanned; denies malicious access         |
| `inotify`  | any user   | Scans on close-write/move; quarantines detected threats          |
| `auto`     | —          | fanotify when running as root on Linux, else inotify             |

Detections print to the console and append to a JSONL audit log
(`~/.defentra/realtime.log` by default). Run persistently with the provided
unit file:

```bash
sudo cp packaging/systemd/defentra-monitor.service /etc/systemd/system/
sudo systemctl enable --now defentra-monitor
```

### Train your own ML detector

The published EMBER reference model gives you ML detection immediately
(`defentra model fetch` — see [models/README.md](models/README.md) for the
trust model). To train on your own corpora:

```bash
# two folders of labeled executables:
python scripts/train_model.py \
    --benign /usr/bin --malicious ~/datasets/malware-samples
# model is saved to ~/.defentra/models/malware.lgbm and auto-loaded
```

For the full-scale reference model, trigger **Actions -> Train reference model**
(GitHub Actions downloads EMBER 2018, >1M labeled PE files, trains, and emits a
checksummed release artifact), or run it yourself:

```bash
curl -LO https://pubdata.endgame.com/ember/ember_dataset.tar.bz2
tar -xjf ember_dataset.tar.bz2
python scripts/train_ember.py \
    --train ember2018/train.jsonl --test ember2018/test.jsonl --out-dir models/release
```

### Build the Rust fast-hash core (optional)

```bash
pip install maturin && cd rust-core && maturin develop --release
```

The engine uses `_defentra_core.stream_sha256` automatically when present.

## Roadmap

- [x] Signature DB + YARA + static ML pipeline + quarantine vault + CLI
- [x] Real-time on-access scanning (fanotify blocking mode / inotify watch mode)
- [x] EMBER training pipeline + `model fetch` installer (reference artifact published via CI)
- [ ] Signature update service (signed feeds)
- [ ] Behavioral detection (eBPF process telemetry)
- [ ] Windows/macOS support; daemon mode + REST API
- [ ] Web protection & browser integration

## Contributing & Security

PRs welcome — open an issue first for large changes. Report vulnerabilities
privately to security@defentra.example (do not open public issues).

## Disclaimer

Defentra is in early alpha. It is **not yet a replacement** for a mature
commercial endpoint product. Always test against the
[EICAR](https://www.eicar.org) standard before trusting any AV deployment.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
