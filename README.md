# Defentra

**Open-source AI-assisted antivirus engine** — the flagship project of the Defentra
cybersecurity suite. Linux first program, with a Python scan core and a Rust performance layer.

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
| CLI        | argparse            | `scan`, `db`, `quarantine`, `model`, `monitor`, `keys`, `feed` commands |
| Engine     | Python              | Orchestrates detectors, computes verdicts                    |
| Real-time  | ctypes (Linux)      | fanotify blocking on-access + inotify watch mode             |
| Updates    | Ed25519 + urllib    | Signed signature feeds, verified against pinned root keys    |
| Signatures | SQLite              | MD5/SHA-1/SHA-256 known-threat lookups (JSON import/export)  |
| YARA       | yara-python         | Pattern/rule-based detection (`rules/*.yar`)                 |
| ML         | LightGBM            | Static-feature malware classifier (PE + ELF)                 |
| Model hub  | urllib              | Release-asset reference model, SHA256-verified install       |
| Features   | Pure Python         | PE/ELF header parsing, section entropy, import analysis      |
| Archives   | stdlib              | Bounded zip/tar/gz inspection: nested payloads, bomb guards  |
| Office     | oletools (optional) | VBA macro risk analysis for OLE documents (`office` extra)   |
| PDF        | stdlib              | Auto-exec/Launch/JS heuristics incl. compressed streams      |
| Quarantine | Fernet (optional)   | Encrypted vault with restore/audit trail                     |
| Fast path  | Rust + PyO3         | Streaming SHA-256 for large files (`rust-core/`)             |

### Detection flow per file

1. **Hash lookup** — SHA-256 → SHA-1 → MD5 against the signature DB.
2. **YARA rules** — compiled from `rules/` directories. The starter set ships
   generic coverage for LOLBin cradles (PowerShell/certutil/mshta/regsvr32),
   credential-dumping tooling, webshells (PHP/ASPX/JSP), ransomware note and
   shadow-copy sabotage markers, obfuscated script droppers, and UPX packing
   (informational). Every family has a positive fixture *and* a benign-corpus
   false-positive gate in `tests/test_detection_content.py`.
3. **ML classifier** — if the file is a PE/ELF and a trained model exists,
   ~35 static features (entropy, section flags, suspicious imports, NX/PIE, …)
   feed a LightGBM booster that outputs a malware probability.
4. **Archives** — zip, tar (+gz/bz2/xz), and single-file gzip payloads are
   extracted under hard resource caps and every entry is scanned recursively
   (nested archives up to depth 3). Zip-slip is structurally impossible:
   entries are re-written under digest names. Compression-ratio and
   byte-budget breaches raise `Archive.BombSuspected` instead of grinding.
5. **Office macros** — OLE documents get VBA risk analysis when the optional
   `office` extra is installed (`pip install 'defentra[office]'`): auto-exec
   chains that combine an entrypoint with process execution score malicious;
   risky APIs alone score suspicious; benign macros are noted info-level.
6. **PDF** — auto-execution analysis: `/OpenAction`/`/AA` combined with
   `/JS`//`Launch` scores malicious (code runs on open), active content alone
   scores suspicious, embedded files and form submission are informational.
   Compressed (FlateDecode) streams are inflated under budget before scoring,
   so payloads hidden from plain-text YARA are still caught.
7. **Verdict policy**
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

Detections print to the console and append to a hash-chained audit log
(`~/.defentra/realtime.log` by default). Run persistently with the provided
unit file:

```bash
sudo cp packaging/systemd/defentra-monitor.service /etc/systemd/system/
sudo systemctl enable --now defentra-monitor
```

### Terminal dashboard

```bash
defentra ui
```

A minimal Linux-console experience: rounded panels over a dark canvas,
engine/protection/quarantine status at a glance, recent detections in the
left pane, and a row of **floating action buttons** along the bottom —
`[S]can`, `[F]eed update`, `[R]ules`, `[P]rotect`, `[W]atchdog`, `[Q]uit` —
rendered with drop-shadows so they hover above the interface. Keyboard-first
(press the highlighted letter) with mouse-click support where the terminal
allows it.

### Signature feed updates

Threat intelligence ships as **signed feeds** (Ed25519). Every install trusts
the bundled root key (`defentra/signing/trusted_keys/`); feeds are verified,
expiry-checked, and replay-protected before a single signature touches your
DB. Feeds also carry **YARA rules** — the daily build embeds the current
ruleset, and `feed update` swaps it in atomically (compile-validated first),
so detection content improves on every machine without upgrading Defentra
itself. Running monitors hot-reload the new rules automatically:

```bash
defentra feed update                     # fetch official feed, verify, apply
defentra feed verify my-feed.json        # check any signed feed locally
defentra keys list                       # show trusted keys + fingerprints
```

Publishing your own feed:

```bash
defentra keys generate --out ~/signing   # once; keep the private key offline
python - <<'EOF'
from defentra.signing.feed import new_feed, save_feed
save_feed(new_feed([{"sha256": "<hash>", "name": "Win32.Family", "severity": 8}]), "feed.json")
EOF
defentra feed sign feed.json --key ~/signing/signing_private.pem
defentra keys trust ~/signing/signing_public.pem   # recipients run this
```

The **official feed** is rebuilt and signed daily by GitHub Actions
(`update-signature-feed` workflow): curated lists from [`feeds/`](feeds/) are
merged with the builtin seeds, signed with the project root key held as an
encrypted Actions secret, self-verified against the bundled public key, and
published to a rolling `signature-feed` release. Contribute intelligence via a
PR to `feeds/community.json`.

Run updates automatically with the provided timer:

```bash
sudo cp packaging/systemd/defentra-feed-update.{service,timer} /etc/systemd/system/
sudo systemctl enable --now defentra-feed-update.timer
```

### Central administration (DAS Management Plane)

For managed estates, Defentra ships a client/admin split: every endpoint runs a
**visible** `agent` service; your console sees the whole fleet and issues
security-operations commands.

```bash
# --- console side -----------------------------------------------------------
defentra admin gen-certs --out /etc/defentra/tls --hostname console.corp
defentra admin serve --host 0.0.0.0 --port 8477 \
    --tls-cert /etc/defentra/tls/server.crt --tls-key /etc/defentra/tls/server.key
defentra admin enroll-token --name workstation-01 --ttl-hours 8  # one-time token
defentra admin agents                                # fleet status / last-seen
defentra admin send workstation-01 scan-path --arg path=/home/alice
defentra admin policy workstation-01 --file policy.json   # central exclusions/thresholds/schedule
defentra admin revoke workstation-01                 # cut a device off immediately
defentra admin results                               # command outcomes
defentra admin detections                            # fleet-wide detections feed

# --- client side (once, then as a service) ----------------------------------
sudo defentra agent pair --server https://console.corp:8477 \
    --ca-cert server.crt --token <TOKEN>
sudo systemctl enable --now defentra-agent
```

Security properties: pairing is token-gated, single-use, persisted server-side
(survives restarts) and expires; every queued command is **Ed25519-signed by
the console** and rejected by the agent if the signature fails or the command
expired; both sides keep tamper-evident audit logs; agents authenticate with
per-device bearer tokens that admins can **revoke instantly**; transport is
TLS with the server certificate pinned client-side (`--ca-cert`); the command
set is scoped to security operations plus signed `apply-policy` pushes and is
extensible only server-side.

**Central policy** (pushed via `admin policy`) controls per-device: scan
exclusions, ML verdict thresholds, preferred kernel backend, and a scheduled
deep-scan interval + paths executed by the agent between check-ins.

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
curl -LO https://ember.elastic.co/ember_dataset.tar.bz2
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
- [x] Signed signature-feed update service (Ed25519, expiry + replay protection)
- [ ] On-access scanning for macOS/Windows endpoints
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

## Security posture

See [SECURITY.md](SECURITY.md) for the full threat model and disclosure
policy. Highlights:

- **Signed updates everywhere**: signature feeds *and* ML model metadata are
  Ed25519-signed against keys pinned inside the package; downloads are
  HTTPS-only, size-capped, checksum-verified, and replay/expiry protected.
- **Crash-safe parsing**: PE/ELF parsers are fuzz-tested — hostile binaries
  yield clean error verdicts, never crashes (a scanner crash is a DoS vector).
- **Hardened quarantine**: strict blob-name validation blocks path traversal,
  `O_NOFOLLOW` on all writes, 0700 state dir / 0600 blobs / key stored apart,
  atomic index updates, chunked encryption to bound memory.
- **Tamper-evident audit log**: realtime events land in a hash-chained JSONL
  (`defentra audit verify`), with rotation.
- **Terminal-escape-safe output**: malicious filenames cannot control your
  terminal via ANSI sequences.
- **Supply chain**: CI runs tests on Python 3.9–3.13 plus bandit SAST,
  pip-audit dependency scanning, and secrets pattern scanning; GitHub Actions
  are pinned by commit SHA; Dependabot watches Actions and pip.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
