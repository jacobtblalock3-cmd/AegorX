# Contributing to AegorX

Thanks for helping build an open antivirus. This document covers the
development setup, the gates every change must pass, and repo conventions.

## Development setup

```bash
git clone https://github.com/jacobtblalock3-cmd/AegorX.git
cd aegorx
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest yara-python bandit[toml]
```

Optional extras:

```bash
pip install 'aegorx[office]'     # VBA macro analysis (oletools)
pip install lightgbm numpy         # ML detector
cargo --version                    # optional Rust acceleration layer (rust-core/)
```

## Running the tests

```bash
pytest tests/ -q                   # unit suite (fast, any OS, no root)
```

Linux-only integration tests (fanotify blocking, inotify, fleet end-to-end)
run automatically in CI as root; locally they skip cleanly when unsupported.

The fanotify kernel test requires root and a real Linux host — it is exercised
on every push by the `integration-linux` CI job on GitHub Actions runners.

## Gates (all enforced by CI on every push)

| Gate | Command | Expectation |
|---|---|---|
| Tests (3.9–3.13) | `pytest tests/ -q` | all green |
| Root integration | CI only (`integration-linux` job) | all green |
| SAST | `bandit -r aegorx scripts --severity-level medium --skip B101,B404,B603` | zero findings |
| Dependencies | `pip-audit --strict .` | no known vulns |
| Secrets | pattern scan in CI | none |
| CodeQL | GitHub default setup | no new alerts |

Run bandit + pytest locally before pushing; CI failures block merge.

## Conventions

- **Stdlib-first**: core features must not add runtime dependencies beyond
  `cryptography`; heavy detectors are optional extras with graceful fallback.
- **Fail clean, never crash**: hostile input must yield error verdicts, not
  exceptions that escape the scanner (a scanner crash is a DoS vector).
  Fuzz-style tests live in `tests/test_fuzz.py`.
- **Signed everything**: feeds, models, commands, update manifests are
  Ed25519-signed against keys pinned in `aegorx/signing/trusted_keys/`.
  New distribution channels must follow this trust model — see
  `aegorx/update.py` for the current reference implementation.
- **Size caps + timeouts** on every download and parse path.
- **Audit trail**: security-relevant actions write to the hash-chained audit
  logs, never just stdout.
- Commit messages: imperative mood, conventional prefixes
  (`feat:`/`fix:`/`ci:`/`docs:`/`test:`). Commits are GPG/SSH-signed.
- Docs live beside code: user-facing behavior changes should update README,
  `docs/OPERATIONS.md`, or `CHANGELOG.md` in the same PR.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md) — please do not open public issues for
security problems.

## Releasing

Maintainers: see [RELEASE.md](RELEASE.md) for the tag-driven release process
(artifacts, PyPI publishing, signed self-update manifest).
