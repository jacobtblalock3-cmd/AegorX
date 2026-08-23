# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for security vulnerabilities.

Email the maintainers or use GitHub's private vulnerability reporting
(**Security -> Report a vulnerability** on this repository). Include a
description, reproduction steps, and affected versions. You will receive an
acknowledgment within 72 hours. We credit reporters in release notes unless
they prefer to remain anonymous.

## Threat model

Defentra is a local, single-host antivirus daemon plus CLI. There are no
network services, no user accounts, and no remote APIs exposed by the engine
itself; it *consumes* HTTPS resources (signed signature feeds, model
artifacts). The primary trust boundaries are:

| Boundary | Risk | Mitigation |
|---|---|---|
| Scanned file contents | Malformed PE/ELF crafted to crash/DoS the scanner | Bounded reads, strict struct guards, broad exception capture (fail-safe verdict, never fail-scan) |
| Scanned filenames | Terminal escape injection in console output | Control characters neutralized (`report.sanitize`) |
| Signature feeds | Forged/tampered/stale/replayed intel | Ed25519 signatures against pinned root keys, expiry + replay checks, size caps, HTTPS-only |
| ML models | Malicious model files substituted for real ones | SHA256 vs signed metadata sidecar verified before load; HTTPS-only fetch with size cap |
| Quarantine vault | Path traversal via forged index; key theft | Strict blob-name validation, `O_NOFOLLOW`, 0700 state dir, 0600 blobs, key stored outside blob dir |
| Audit log | Log tampering by compromised processes | SHA256 hash-chained JSONL records (`verify_audit_log`) |
| CI/pipeline | Supply-chain injection | Actions pinned by commit SHA, least-privilege workflow permissions, Dependabot, bandit + pip-audit + secrets scanning |

Known, accepted limitations:

* On-access fanotify mode is **fail-open** on internal scanner errors: a bug
  must not brick the host. Detections still quarantine post-hoc via inotify.
* Hash-then-open TOCTOU windows exist for on-demand scans of attacker-writable
  directories (inherent to userspace AV without kernel assist).
* The audit log chain detects tampering but does not prevent it; ship logs off-box for stronger guarantees.

## Supported versions

Only the latest `main` receives security fixes. Pin releases and update promptly.
