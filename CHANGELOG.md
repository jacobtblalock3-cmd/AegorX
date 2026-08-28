# Changelog

All notable changes to AegorX. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [1.1.0] — 2026-08-26

**Windows + macOS support.** Standalone builds ship with the release; both
platforms are CI-tested on every push and participate in managed fleets in
scan-only mode (kernel-enforced realtime remains Linux).

### Added
- Cross-platform CI gate: full test matrix on `windows-latest` and
  `macos-latest` runners, including EICAR detection smoke tests.
- Standalone executables built per release: `aegorx-<ver>-windows-amd64.exe`
  (plus an Inno Setup installer) and `aegorx-<ver>-macos-arm64`, each
  smoke-tested post-build (version banner, EICAR verdict, trust keys).
  Bundles pinned trust keys and YARA rules; ML stack excluded by design.
- `docs/PLATFORMS.md` — per-platform capability matrix and install guides.
- **Network protection** — DNS-based domain blocking, connection monitoring,
  and automatic threat intel feed updates:
  - `aegorx.network.dns_filter` — trie-based domain blocklist with
    O(domain-length) lookups, block/unblock/allow, JSON persistence.
  - `aegorx.network.conn_monitor` — cross-platform connection scanner
    with `/proc/net/tcp` (Linux), `netstat` fallback (macOS/Windows),
    high-risk port detection, C2 beacon detection.
  - `aegorx.network.threat_feeds` — fetcher for URLhaus, StevenBlack,
    Phishing Army, and MalwareDomainList feeds with HTTPS-only enforcement
    and graceful degradation.
  - `aegorx.network.protector` — unified `NetworkProtector` service
    coordinating DNS filtering, connection monitoring, and feed updates.
  - CLI commands: `aegorx network start|stop|status|update|block|unblock|
    check|domains|scan|connections`.
  - 76 tests covering DNS filter, connection monitor, threat feeds,
    protector integration, and CLI commands.
- **DNS enforcement** — actual traffic blocking via hosts file (cross-platform),
  iptables (Linux), and pf (macOS).  `aegorx.network.enforcement` translates
  the DNSFilter blocklist into real network blocking.
- **USB auto-scan** — `aegorx.usb_scanner` monitors for newly mounted
  removable media and triggers scans.  Cross-platform (Linux /proc/mounts,
  macOS /Volumes, Windows drive type detection).
- **Scheduled scans** — `aegorx.scheduler` with OS-native backends:
  systemd timer (Linux), launchd (macOS), Task Scheduler (Windows), and a
  Python-level fallback.  `aegorx schedule install|uninstall|status`.
- **Browser download protection** — `aegorx.browser_guard` monitors browser
  download directories for new executable files and scans them in real-time.
  `aegorx browser start|stop|status|dirs`.
- **Process memory scanning** — `aegorx.process_scanner` detects fileless
  malware by scanning process memory for RWX regions, shellcode patterns,
  and suspicious strings.  `aegorx process scan-pid|scan-all|scan-name|status`.
- **Ransomware canary detection** — `aegorx.ransomware` provides multi-layered
  ransomware protection:
  - Canary files: decoy files (financial docs, password files) placed in
    monitored directories; any modification triggers an instant alert.
  - Velocity detection: rapid file modifications (> N files in M seconds).
  - Entropy spike detection: files suddenly becoming high-entropy (encrypted).
  - Extension monitoring: mass renames to ransomware extensions (.locked, .crypto, etc.).
  - Ransom note detection: known ransom note file names (readme.txt, how_to_decrypt.html).
  - Background canary checking with configurable interval.
  - `aegorx ransomware deploy|check|remove|list|start|stop|status|events`.
- **Outbound firewall** — `aegorx.firewall` monitors and blocks suspicious
  outbound connections to prevent C2 callbacks and data exfiltration:
  - Suspicious port blocking (IRC 6667, Metasploit 4444, Back Orifice 31337, etc.)
  - IP-based outbound blocking with iptables (Linux), pf (macOS), netsh (Windows)
  - Software-level connection scanning with alert callbacks
  - `aegorx firewall start|stop|status|block-ip|unblock-ip|block-port|unblock-port|scan`.
- **Application control** — `aegorx.app_control` enforces executable policies:
  - Hash-based blocking (SHA-256 of executable)
  - Path pattern blocking (glob patterns like `/tmp/*.exe`)
  - Extension blocking (.scr, .pif, .com, etc.)
  - Allowlist overrides (block all .exe except specific paths)
  - Persistent policy store with atomic updates
  - `aegorx appcontrol check|block-hash|block-path|block-extension|allow-path|rules|delete-rule|status`.
- **Vulnerability scanner** — `aegorx.vuln_scanner` detects unpatched software:
  - Cross-platform inventory (dpkg, rpm, snap, brew, system_profiler, WMI, registry)
  - Built-in CVE database (browsers, Java, OpenSSL, Node.js, Python, sudo, etc.)
  - Version comparison with severity classification (critical/high/medium/low)
  - Ignore list for accepted risks
  - `aegorx vuln scan|status|ignore|unignore|ignored`.
- **Encrypted DNS** — `aegorx.network.encrypted_dns` protects DNS queries:
  - DNS over HTTPS (DoH) via Cloudflare, Google, Quad9
  - DNS over TLS (DoT) on port 853
  - Response caching with TTL respect
  - Fallback to system resolver on failure
  - `aegorx dns status|resolve|config|providers|clear-cache`.

### Fixed
- Windows: `os.geteuid` crash in backend selection; `O_NOFOLLOW` absence in
  quarantine vault; `os.kill(pid, 0)` self-termination in liveness probes
  (now OpenProcess-based); backslash path handling for trusted-key origin
  labeling; curses-free `aegorx ui` degradation.

## [1.0.0] — 2026-08-26

First stable release, validated for deployment and testing on real devices:
blocking on-access enforcement is CI-proven on current Linux kernels on every
push, all distribution channels (PyPI, deb, GitHub Releases) are live, and
clients keep themselves current through the signed self-update channel.

### Added
- `aegorx doctor` — read-only health/suitability report across privileges,
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
  `update-manifest.json`; `aegorx update check|apply` verifies provenance
  against pinned root keys, enforces signed sha256 + size on download, and
  refuses downgrades without `--force`.
- Fleet remote command `check-update` — consoles can ask any device for its
  current vs. available release through the verified command pipeline.
- `aegorx doctor` — read-only one-shot health report (privileges, fanotify,
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
- PyPI distribution: `pip install aegorx`, clean-venv install verified.

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
- Terminal dashboard (`aegorx ui`).

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
