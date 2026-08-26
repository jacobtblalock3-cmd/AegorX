# Changelog

All notable changes to Defentra. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [1.0.0] — 2026-08-26

First stable release, validated for deployment and testing on real devices:
blocking on-access enforcement is CI-proven on current Linux kernels on every
push, all distribution channels (PyPI, deb, GitHub Releases) are live, and
clients keep themselves current through the signed self-update channel.

### Added
- `defentra doctor` — read-only health/suitability report across privileges,
  fanotify, detection content, trust anchors, audit chain, vault, pairing,
  and policy; scriptable exit codes for cron/monitoring.
- `admin agents --stale-hours N` — surface devices that stopped checking in.
- Scan-throughput benchmark (`scripts/bench_scan.py`).
- CLI reference generated from the live parser (`docs/CLI.md`) with a
  CI-enforced drift guard.
- CONTRIBUTING.md with the full local gate matrix.

### Fixed
- Audit-log hash-chain verification now spans rotated segments with
  retained-anchor semantics (previously every post-rotation log failed
  verification); writers resume sequence continuity after restarts.

### Changed
- Rust acceleration core: pyo3 bindings feature-gated so `cargo test` runs
  without libpython; NIST SHA-256 vector tests; fmt/clippy/test gate added
  to CI.
- Fuzz coverage extended to the PDF analyzer (incl. inflate-bomb budget) and
  archive extraction hostile inputs.

## [0.9.0] — 2026-08-25

### Added
- **Signed self-update channel**: every release publishes an Ed25519-signed
  `update-manifest.json`; `defentra update check|apply` verifies provenance
  against pinned root keys, enforces signed sha256 + size on download, and
  refuses downgrades without `--force`.
- Fleet remote command `check-update` — consoles can ask any device for its
  current vs. available release through the verified command pipeline.
- `defentra doctor` — read-only one-shot health report (privileges, fanotify,
  signature DB, ML model, feed freshness, trust keys, audit chain, vault,
  pairing, policy) with scriptable exit codes.
- Operations Runbook (`docs/OPERATIONS.md`): console deployment, endpoint
  enrollment, fleet administration, incident response, troubleshooting.
- systemd units for the management console and the realtime watchdog timer.

### Fixed
- Audit-log verification falsely failed after any size rotation; chains now
  verify across retained segments with anchor semantics, and writers resume
  sequence continuity after restarts.

### Changed
- License: GPL-3.0-or-later → **Apache-2.0**.

## [0.8.0] — 2026-08-24

### Added
- PDF inspection: stdlib auto-exec/Launch/JS heuristics with compressed-stream
  inflation, wired into the engine.
- EMBER-trained ML reference model published via CI (ROC-AUC 0.9957) and a
  tested trainer pipeline contract; end-to-end trainer→classifier integration.
- Live abuse.ch MalwareBazaar/URLhaus IOC ingestion into the signed feed
  (rolling 90-day store; fixed key-vs-header auth bug against live APIs).
- PyPI distribution: `pip install defentra`, clean-venv install verified.

### Fixed
- Fanotify blocking enforcement root-caused and repaired on kernel 6.17:
  wrong group class bit (`FAN_CLASS_PRE_CONTENT` instead of `CONTENT`),
  self-scan deadlock eliminated by scanning the kernel-provided descriptor,
  own-PID permission events auto-allowed, canonical `FAN_ALLOW/DENY` values
  restored (verified against runner uapi headers). Enforcement is now proven
  green in standard CI on every push.

## [0.7.0] — 2026-08-23

### Added
- Archive inspection: bounded zip/tar/gz with nested recursive scanning and
  bomb guards; Office VBA macro analysis via optional `oletools` extra.
- Generic YARA starter ruleset (LOLBin cradles, cred-dump tooling, webshells,
  ransomware markers, droppers), positive+negative validated.

### Fixed
- Per-file YARA namespaces so feed-delivered duplicates of builtin rules
  coexist instead of silently disabling YARA.

## [0.6.0] — 2026-08-23

### Added
- Signed YARA-rule channel inside signature feeds: atomic, compile-validated
  installs; running monitors hot-reload new rules automatically.
- Terminal dashboard (`defentra ui`).

## [0.5.0] — 2026-08-23

### Added
- DAS Management Plane: fleet console + managed agent with token-gated
  pairing, Ed25519-signed commands, scoped security-ops command set, and
  dual hash-chained audit logs.
- Shield self-defense layer: audited shutdown, heartbeat watchdog,
  trust-anchor sealing (`protect seal/check`).
- EICAR conformance suite; hardened distribution pipeline with root-Linux
  integration tests in CI.

## [0.4.0] — 2026-08-22

### Added
- Signed signature-feed update service: Ed25519 verify, expiry + replay
  protection, `keys` CLI, daily systemd timer, automated CI feed build from
  curated sources.

## [0.3.0] — 2026-08-21

### Added
- Initial engine: hash signatures + YARA + static-feature ML (PE/ELF),
- encrypted quarantine vault, realtime monitor skeleton, EMBER training
  pipeline and model hub.
