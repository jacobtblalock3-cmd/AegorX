# Defentra CLI Reference

Generated from the argparse tree by `scripts/gen_cli_docs.py` —
do not edit by hand; regenerate instead.

Commands:

- [`admin`](#admin) — DAS administration console
- [`agent`](#agent) — managed client agent (connects to your DAS admin console)
- [`audit`](#audit) — audit log operations
- [`db`](#db) — signature database operations
- [`doctor`](#doctor) — one-shot health/suitability report (read-only)
- [`feed`](#feed) — signed signature-feed operations
- [`keys`](#keys) — signing key management
- [`model`](#model) — ML model information
- [`monitor`](#monitor) — real-time on-access protection (Linux)
- [`protect`](#protect) — trust-anchor integrity operations
- [`quarantine`](#quarantine) — quarantine vault operations
- [`scan`](#scan) — scan a file or directory
- [`ui`](#ui) — terminal dashboard (minimal, floating-button console)
- [`update`](#update) — self-update: check for and apply signed releases
- [`watchdog`](#watchdog) — verify realtime protection liveness; restart if stale

## Global options

- `--version` — show program's version number and exit

## `defentra admin`

_DAS administration console_

Subcommands: [`admin agents`](#admin-agents) — list managed devices and last-seen state, [`admin detections`](#admin-detections) — aggregated detections across the fleet, [`admin enroll-token`](#admin-enroll-token) — issue a one-time pairing token for a device, [`admin gen-certs`](#admin-gen-certs) — generate a self-signed TLS server certificate, [`admin policy`](#admin-policy) — queue an apply-policy command for a device, [`admin results`](#admin-results) — recent command results, [`admin revoke`](#admin-revoke) — revoke a device's credentials immediately, [`admin send`](#admin-send) — queue a command for a device, [`admin serve`](#admin-serve) — run the management server

## `defentra admin agents`

_list managed devices and last-seen state_

## `defentra admin detections`

_aggregated detections across the fleet_

- `--limit` `LIMIT` — max rows to show (default 50)

## `defentra admin enroll-token`

_issue a one-time pairing token for a device_

- `--name` `NAME` — unique device name
- `--ttl-hours` `TTL_HOURS` — token lifetime in hours (default 24)

## `defentra admin gen-certs`

_generate a self-signed TLS server certificate_

- `--out` `OUT` — output directory for server.crt/server.key
- `--hostname` `HOSTNAME` — DNS name clients will reach
- `--days` `DAYS` — certificate lifetime in days (default 825)

## `defentra admin policy`

_queue an apply-policy command for a device_

- `AGENT_NAME` — target device name
- `--file` `FILE` — policy JSON document

## `defentra admin results`

_recent command results_

- `--agent` `AGENT` — filter by device name

## `defentra admin revoke`

_revoke a device's credentials immediately_

- `AGENT_NAME` — device name as shown by 'admin agents'

## `defentra admin send`

_queue a command for a device_

- `AGENT_NAME` — target device name
- `COMMAND` — security-ops command to queue
- `--arg` `ARGS` — key=value argument (repeatable)

## `defentra admin serve`

_run the management server_

- `--host` `HOST` — bind address (use 0.0.0.0 for remote agents)
- `--port` `PORT` — TCP port (default 8477)
- `--db` `DB` — fleet database path (default: <state>/fleet.db)
- `--tls-cert` `TLS_CERT` — server certificate PEM (enables HTTPS)
- `--tls-key` `TLS_KEY` — server private key PEM

## `defentra agent`

_managed client agent (connects to your DAS admin console)_

Subcommands: [`agent pair`](#agent-pair) — pair this machine with a management server (one-time), [`agent run`](#agent-run) — start check-in loop (foreground; use systemd for production), [`agent status`](#agent-status) — show pairing/connection status

## `defentra agent pair`

_pair this machine with a management server (one-time)_

- `--server` `SERVER` — management server URL
- `--token` `TOKEN` — one-time pairing token from the console
- `--ca-cert` `CA_CERT` — server cert / CA chain to pin for HTTPS (required off-host)

## `defentra agent run`

_start check-in loop (foreground; use systemd for production)_

## `defentra agent status`

_show pairing/connection status_

## `defentra audit`

_audit log operations_

Subcommands: [`audit verify`](#audit-verify) — verify the hash chain of a realtime audit log

## `defentra audit verify`

_verify the hash chain of a realtime audit log_

- `LOG` — audit log path (default: <state>/realtime.log)

## `defentra db`

_signature database operations_

Subcommands: [`db add-hash`](#db-add-hash) — add one hash signature, [`db export`](#db-export) — export signatures to JSON file, [`db import`](#db-import) — import signatures from JSON file, [`db seed`](#db-seed) — load built-in signatures, [`db stats`](#db-stats) — show database statistics

- `--db` `DB` — path to signature database

## `defentra db add-hash`

_add one hash signature_

- `--sha256` `SHA256` — SHA-256 of the known-threat file
- `--name` `NAME` — detection name to report on hit
- `--md5` `MD5` — optional MD5 for legacy lookups
- `--sha1` `SHA1` — optional SHA-1 for legacy lookups
- `--family` `FAMILY` — malware family label
- `--severity` `SEVERITY` — severity 1-10 (default 8)

## `defentra db export`

_export signatures to JSON file_

- `FILE` — destination JSON path

## `defentra db import`

_import signatures from JSON file_

- `FILE` — JSON file with a list of signature objects

## `defentra db seed`

_load built-in signatures_

## `defentra db stats`

_show database statistics_

## `defentra doctor`

_one-shot health/suitability report (read-only)_

## `defentra feed`

_signed signature-feed operations_

Subcommands: [`feed sign`](#feed-sign) — sign a feed document (publishers), [`feed update`](#feed-update) — download, verify, and apply signature updates, [`feed verify`](#feed-verify) — verify a signed feed against trusted keys

## `defentra feed sign`

_sign a feed document (publishers)_

- `FILE` — unsigned feed JSON
- `--key` `KEY` — Ed25519 private key PEM
- `--out` `OUT` — write signed feed here (default: <file>.signed.json)

## `defentra feed update`

_download, verify, and apply signature updates_

- `--url` `URL` — feed URL (default: official release asset)
- `--file` `FEED_FILE` — apply from a local signed feed file
- `--db` `DB` — path to signature database
- `--force` `FORCE` — apply even if not newer than last update
- `--allow-expired` `ALLOW_EXPIRED` — accept feeds past their expiry

## `defentra feed verify`

_verify a signed feed against trusted keys_

- `FILE` — signed feed JSON

## `defentra keys`

_signing key management_

Subcommands: [`keys generate`](#keys-generate) — create an Ed25519 signing keypair (feed publishers), [`keys list`](#keys-list) — list trusted public keys, [`keys trust`](#keys-trust) — install a public key into your trust store

## `defentra keys generate`

_create an Ed25519 signing keypair (feed publishers)_

- `--out` `OUT` — output directory (default: <state>/signing)

## `defentra keys list`

_list trusted public keys_

## `defentra keys trust`

_install a public key into your trust store_

- `PUBKEY` — path to a PEM Ed25519 public key

## `defentra model`

_ML model information_

Subcommands: [`model fetch`](#model-fetch) — download the published reference model, [`model info`](#model-info) — show loaded model info

## `defentra model fetch`

_download the published reference model_

- `--url` `URL` — override model asset URL

## `defentra model info`

_show loaded model info_

## `defentra monitor`

_real-time on-access protection (Linux)_

- `PATHS` — directories/filesystem roots to watch
- `--backend` `auto|fanotify|inotify` — kernel backend (auto: fanotify as root, else inotify)
- `--workers` `WORKERS` — scan thread pool size (inotify mode)
- `--exclude` `EXCLUDE` — fnmatch pattern to skip (repeatable)
- `--no-quarantine` `NO_QUARANTINE` — detect but do not quarantine
- `--no-ml` `NO_ML` — disable the ML detector
- `--db` `DB` — path to signature database
- `--rules` `RULES` — YARA rules directory (repeatable)
- `--max-size-mb` `MAX_SIZE_MB` — skip files larger than this (MB)
- `--log` `LOG` — JSONL audit log path (default: <state>/realtime.log)

## `defentra protect`

_trust-anchor integrity operations_

Subcommands: [`protect check`](#protect-check) — verify trust anchors against the sealed manifest, [`protect seal`](#protect-seal) — pin current hashes of trusted keys and agent config

## `defentra protect check`

_verify trust anchors against the sealed manifest_

## `defentra protect seal`

_pin current hashes of trusted keys and agent config_

## `defentra quarantine`

_quarantine vault operations_

Subcommands: [`quarantine delete`](#quarantine-delete) — permanently delete an item by id, [`quarantine list`](#quarantine-list) — list quarantined items, [`quarantine restore`](#quarantine-restore) — restore an item by id

## `defentra quarantine delete`

_permanently delete an item by id_

- `ID` — quarantine item id (from 'quarantine list')

## `defentra quarantine list`

_list quarantined items_

## `defentra quarantine restore`

_restore an item by id_

- `ID` — quarantine item id (from 'quarantine list')

## `defentra scan`

_scan a file or directory_

- `PATHS` — files or directories to scan
- `--json` `JSON` — emit machine-readable JSON report
- `--no-color` `NO_COLOR` — disable colored output
- `--no-ml` `NO_ML` — disable the ML detector
- `--db` `DB` — path to signature database
- `--rules` `RULES` — YARA rules directory (repeatable)
- `--max-size-mb` `MAX_SIZE_MB` — skip files larger than this (MB)

## `defentra ui`

_terminal dashboard (minimal, floating-button console)_

## `defentra update`

_self-update: check for and apply signed releases_

Subcommands: [`update apply`](#update-apply) — verify + download + install the newest release artifact, [`update check`](#update-check) — fetch + verify the signed release manifest; report newer versions

## `defentra update apply`

_verify + download + install the newest release artifact_

- `--url` `URL` — manifest URL (default: official latest release)
- `--kind` `auto|deb|wheel` — artifact to install (auto: deb when root+apt-get, else wheel)
- `--force` `FORCE` — apply even when not newer than the running version
- `--allow-expired` `ALLOW_EXPIRED` — accept manifests past their expiry

## `defentra update check`

_fetch + verify the signed release manifest; report newer versions_

- `--url` `URL` — manifest URL (default: official latest release)

## `defentra watchdog`

_verify realtime protection liveness; restart if stale_

- `--max-age` `MAX_AGE` — heartbeat staleness threshold (seconds)
- `--service` `SERVICE` — systemd unit to restart
- `--no-restart` `NO_RESTART` — report only
