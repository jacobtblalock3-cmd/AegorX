# Defentra CLI Reference

Generated from the argparse tree by `scripts/gen_cli_docs.py` —
do not edit by hand; regenerate instead.

Commands:

- [`admin`](#admin) — DAS administration console
- [`agent`](#agent) — managed client agent (connects to your DAS admin console)
- [`appcontrol`](#appcontrol) — application control (allowlist/blocklist executables)
- [`audit`](#audit) — audit log operations
- [`browser`](#browser) — browser download protection
- [`db`](#db) — signature database operations
- [`dns`](#dns) — encrypted DNS (DoH/DoT)
- [`doctor`](#doctor) — one-shot health/suitability report (read-only)
- [`feed`](#feed) — signed signature-feed operations
- [`firewall`](#firewall) — outbound firewall (block C2 connections)
- [`keys`](#keys) — signing key management
- [`model`](#model) — ML model information
- [`monitor`](#monitor) — real-time on-access protection (Linux)
- [`network`](#network) — network protection: DNS filtering, connection monitoring, threat intel
- [`process`](#process) — process memory scanning (fileless malware detection)
- [`protect`](#protect) — trust-anchor integrity operations
- [`quarantine`](#quarantine) — quarantine vault operations
- [`ransomware`](#ransomware) — ransomware canary detection and protection
- [`scan`](#scan) — scan a file or directory
- [`schedule`](#schedule) — scheduled scan management
- [`ui`](#ui) — terminal dashboard (minimal, floating-button console)
- [`update`](#update) — self-update: check for and apply signed releases
- [`usb`](#usb) — USB/removable media auto-scan
- [`vuln`](#vuln) — vulnerability scanner (detect unpatched software)
- [`watchdog`](#watchdog) — verify realtime protection liveness; restart if stale

## Global options

- `--version` — show program's version number and exit

## `aegorx admin`

_DAS administration console_

Subcommands: [`admin agents`](#admin-agents) — list managed devices and last-seen state, [`admin detections`](#admin-detections) — aggregated detections across the fleet, [`admin enroll-token`](#admin-enroll-token) — issue a one-time pairing token for a device, [`admin gen-certs`](#admin-gen-certs) — generate a self-signed TLS server certificate, [`admin policy`](#admin-policy) — queue an apply-policy command for a device, [`admin results`](#admin-results) — recent command results, [`admin revoke`](#admin-revoke) — revoke a device's credentials immediately, [`admin send`](#admin-send) — queue a command for a device, [`admin serve`](#admin-serve) — run the management server

## `aegorx admin agents`

_list managed devices and last-seen state_

- `--stale-hours` `N` — only show devices not seen for more than N hours

## `aegorx admin detections`

_aggregated detections across the fleet_

- `--limit` `LIMIT` — max rows to show (default 50)

## `aegorx admin enroll-token`

_issue a one-time pairing token for a device_

- `--name` `NAME` — unique device name
- `--ttl-hours` `TTL_HOURS` — token lifetime in hours (default 24)

## `aegorx admin gen-certs`

_generate a self-signed TLS server certificate_

- `--out` `OUT` — output directory for server.crt/server.key
- `--hostname` `HOSTNAME` — DNS name clients will reach
- `--days` `DAYS` — certificate lifetime in days (default 825)

## `aegorx admin policy`

_queue an apply-policy command for a device_

- `AGENT_NAME` — target device name
- `--file` `FILE` — policy JSON document

## `aegorx admin results`

_recent command results_

- `--agent` `AGENT` — filter by device name

## `aegorx admin revoke`

_revoke a device's credentials immediately_

- `AGENT_NAME` — device name as shown by 'admin agents'

## `aegorx admin send`

_queue a command for a device_

- `AGENT_NAME` — target device name
- `COMMAND` — security-ops command to queue
- `--arg` `ARGS` — key=value argument (repeatable)

## `aegorx admin serve`

_run the management server_

- `--host` `HOST` — bind address (use 0.0.0.0 for remote agents)
- `--port` `PORT` — TCP port (default 8477)
- `--db` `DB` — fleet database path (default: <state>/fleet.db)
- `--tls-cert` `TLS_CERT` — server certificate PEM (enables HTTPS)
- `--tls-key` `TLS_KEY` — server private key PEM

## `aegorx agent`

_managed client agent (connects to your DAS admin console)_

Subcommands: [`agent pair`](#agent-pair) — pair this machine with a management server (one-time), [`agent run`](#agent-run) — start check-in loop (foreground; use systemd for production), [`agent status`](#agent-status) — show pairing/connection status

## `aegorx agent pair`

_pair this machine with a management server (one-time)_

- `--server` `SERVER` — management server URL
- `--token` `TOKEN` — one-time pairing token from the console
- `--ca-cert` `CA_CERT` — server cert / CA chain to pin for HTTPS (required off-host)

## `aegorx agent run`

_start check-in loop (foreground; use systemd for production)_

## `aegorx agent status`

_show pairing/connection status_

## `aegorx appcontrol`

_application control (allowlist/blocklist executables)_

Subcommands: [`appcontrol allow-path`](#appcontrol-allow-path) — allow executables matching a path pattern, [`appcontrol block-extension`](#appcontrol-block-extension) — block executables with a specific extension, [`appcontrol block-hash`](#appcontrol-block-hash) — block an executable by SHA-256 hash, [`appcontrol block-path`](#appcontrol-block-path) — block executables matching a path pattern, [`appcontrol check`](#appcontrol-check) — check if an executable is allowed, [`appcontrol delete-rule`](#appcontrol-delete-rule) — delete a rule by index, [`appcontrol rules`](#appcontrol-rules) — list all application control rules, [`appcontrol status`](#appcontrol-status) — show application control status

## `aegorx appcontrol allow-path`

_allow executables matching a path pattern_

- `PATTERN` — glob pattern

## `aegorx appcontrol block-extension`

_block executables with a specific extension_

- `EXTENSION` — file extension (e.g. .scr)

## `aegorx appcontrol block-hash`

_block an executable by SHA-256 hash_

- `PATH` — path to executable to hash and block

## `aegorx appcontrol block-path`

_block executables matching a path pattern_

- `PATTERN` — glob pattern (e.g. /tmp/*.exe)

## `aegorx appcontrol check`

_check if an executable is allowed_

- `PATH` — path to executable

## `aegorx appcontrol delete-rule`

_delete a rule by index_

- `INDEX` — rule index (from 'rules' command)

## `aegorx appcontrol rules`

_list all application control rules_

## `aegorx appcontrol status`

_show application control status_

## `aegorx audit`

_audit log operations_

Subcommands: [`audit verify`](#audit-verify) — verify the hash chain of a realtime audit log

## `aegorx audit verify`

_verify the hash chain of a realtime audit log_

- `LOG` — audit log path (default: <state>/realtime.log)

## `aegorx browser`

_browser download protection_

Subcommands: [`browser add`](#browser-add) — add a download directory to monitor, [`browser dirs`](#browser-dirs) — list monitored download directories, [`browser start`](#browser-start) — start browser download monitoring, [`browser status`](#browser-status) — show browser guard status, [`browser stop`](#browser-stop) — stop browser download monitoring

## `aegorx browser add`

_add a download directory to monitor_

- `PATH` — directory path to monitor

## `aegorx browser dirs`

_list monitored download directories_

## `aegorx browser start`

_start browser download monitoring_

## `aegorx browser status`

_show browser guard status_

## `aegorx browser stop`

_stop browser download monitoring_

## `aegorx db`

_signature database operations_

Subcommands: [`db add-hash`](#db-add-hash) — add one hash signature, [`db export`](#db-export) — export signatures to JSON file, [`db import`](#db-import) — import signatures from JSON file, [`db seed`](#db-seed) — load built-in signatures, [`db stats`](#db-stats) — show database statistics

- `--db` `DB` — path to signature database

## `aegorx db add-hash`

_add one hash signature_

- `--sha256` `SHA256` — SHA-256 of the known-threat file
- `--name` `NAME` — detection name to report on hit
- `--md5` `MD5` — optional MD5 for legacy lookups
- `--sha1` `SHA1` — optional SHA-1 for legacy lookups
- `--family` `FAMILY` — malware family label
- `--severity` `SEVERITY` — severity 1-10 (default 8)

## `aegorx db export`

_export signatures to JSON file_

- `FILE` — destination JSON path

## `aegorx db import`

_import signatures from JSON file_

- `FILE` — JSON file with a list of signature objects

## `aegorx db seed`

_load built-in signatures_

## `aegorx db stats`

_show database statistics_

## `aegorx dns`

_encrypted DNS (DoH/DoT)_

Subcommands: [`dns clear-cache`](#dns-clear-cache) — clear DNS cache, [`dns config`](#dns-config) — configure encrypted DNS, [`dns providers`](#dns-providers) — list available DNS providers, [`dns resolve`](#dns-resolve) — resolve a domain via encrypted DNS, [`dns status`](#dns-status) — show encrypted DNS status

## `aegorx dns clear-cache`

_clear DNS cache_

## `aegorx dns config`

_configure encrypted DNS_

- `--provider` `cloudflare|google|quad9` — DNS provider
- `--mode` `doh|dot` — encryption mode
- `--timeout` `TIMEOUT` — query timeout in seconds

## `aegorx dns providers`

_list available DNS providers_

## `aegorx dns resolve`

_resolve a domain via encrypted DNS_

- `DOMAIN` — domain name to resolve
- `--type` `A|AAAA` — record type

## `aegorx dns status`

_show encrypted DNS status_

## `aegorx doctor`

_one-shot health/suitability report (read-only)_

## `aegorx feed`

_signed signature-feed operations_

Subcommands: [`feed sign`](#feed-sign) — sign a feed document (publishers), [`feed update`](#feed-update) — download, verify, and apply signature updates, [`feed verify`](#feed-verify) — verify a signed feed against trusted keys

## `aegorx feed sign`

_sign a feed document (publishers)_

- `FILE` — unsigned feed JSON
- `--key` `KEY` — Ed25519 private key PEM
- `--out` `OUT` — write signed feed here (default: <file>.signed.json)

## `aegorx feed update`

_download, verify, and apply signature updates_

- `--url` `URL` — feed URL (default: official release asset)
- `--file` `FEED_FILE` — apply from a local signed feed file
- `--db` `DB` — path to signature database
- `--force` `FORCE` — apply even if not newer than last update
- `--allow-expired` `ALLOW_EXPIRED` — accept feeds past their expiry

## `aegorx feed verify`

_verify a signed feed against trusted keys_

- `FILE` — signed feed JSON

## `aegorx firewall`

_outbound firewall (block C2 connections)_

Subcommands: [`firewall block-ip`](#firewall-block-ip) — add IP to outbound block list, [`firewall block-port`](#firewall-block-port) — add port to outbound block list, [`firewall scan`](#firewall-scan) — one-shot scan of outbound connections, [`firewall start`](#firewall-start) — start outbound connection monitoring, [`firewall status`](#firewall-status) — show firewall status, [`firewall stop`](#firewall-stop) — stop outbound monitoring, [`firewall unblock-ip`](#firewall-unblock-ip) — remove IP from outbound block list, [`firewall unblock-port`](#firewall-unblock-port) — remove port from outbound block list

## `aegorx firewall block-ip`

_add IP to outbound block list_

- `IP` — IP address to block

## `aegorx firewall block-port`

_add port to outbound block list_

- `PORT` — port number to block

## `aegorx firewall scan`

_one-shot scan of outbound connections_

## `aegorx firewall start`

_start outbound connection monitoring_

## `aegorx firewall status`

_show firewall status_

## `aegorx firewall stop`

_stop outbound monitoring_

## `aegorx firewall unblock-ip`

_remove IP from outbound block list_

- `IP` — IP address to unblock

## `aegorx firewall unblock-port`

_remove port from outbound block list_

- `PORT` — port number to unblock

## `aegorx keys`

_signing key management_

Subcommands: [`keys generate`](#keys-generate) — create an Ed25519 signing keypair (feed publishers), [`keys list`](#keys-list) — list trusted public keys, [`keys trust`](#keys-trust) — install a public key into your trust store

## `aegorx keys generate`

_create an Ed25519 signing keypair (feed publishers)_

- `--out` `OUT` — output directory (default: <state>/signing)

## `aegorx keys list`

_list trusted public keys_

## `aegorx keys trust`

_install a public key into your trust store_

- `PUBKEY` — path to a PEM Ed25519 public key

## `aegorx model`

_ML model information_

Subcommands: [`model fetch`](#model-fetch) — download the published reference model, [`model info`](#model-info) — show loaded model info

## `aegorx model fetch`

_download the published reference model_

- `--url` `URL` — override model asset URL

## `aegorx model info`

_show loaded model info_

## `aegorx monitor`

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

## `aegorx network`

_network protection: DNS filtering, connection monitoring, threat intel_

Subcommands: [`network block`](#network-block) — block a domain, [`network check`](#network-check) — check if a domain is blocked, [`network connections`](#network-connections) — show current active connections, [`network domains`](#network-domains) — list all blocked domains, [`network scan`](#network-scan) — one-shot scan of active network connections, [`network start`](#network-start) — start network protection daemon (DNS filter + connection monitor), [`network status`](#network-status) — show network protection status, [`network stop`](#network-stop) — stop network protection daemon, [`network unblock`](#network-unblock) — unblock a domain, [`network update`](#network-update) — manually refresh threat intel feeds

## `aegorx network block`

_block a domain_

- `DOMAIN` — domain to block

## `aegorx network check`

_check if a domain is blocked_

- `DOMAIN` — domain to check

## `aegorx network connections`

_show current active connections_

## `aegorx network domains`

_list all blocked domains_

## `aegorx network scan`

_one-shot scan of active network connections_

## `aegorx network start`

_start network protection daemon (DNS filter + connection monitor)_

## `aegorx network status`

_show network protection status_

## `aegorx network stop`

_stop network protection daemon_

## `aegorx network unblock`

_unblock a domain_

- `DOMAIN` — domain to unblock

## `aegorx network update`

_manually refresh threat intel feeds_

- `--sources` `SOURCES` — comma-separated sources: urlhaus,stevenblack,phishingarmy

## `aegorx process`

_process memory scanning (fileless malware detection)_

Subcommands: [`process scan-all`](#process-scan-all) — scan all user processes, [`process scan-name`](#process-scan-name) — scan processes matching a name, [`process scan-pid`](#process-scan-pid) — scan a specific process by PID, [`process status`](#process-status) — show process scanner status

## `aegorx process scan-all`

_scan all user processes_

- `--skip-self` `SKIP_SELF` — skip aegorx's own processes

## `aegorx process scan-name`

_scan processes matching a name_

- `NAME` — process name substring to match

## `aegorx process scan-pid`

_scan a specific process by PID_

- `PID` — process ID to scan

## `aegorx process status`

_show process scanner status_

## `aegorx protect`

_trust-anchor integrity operations_

Subcommands: [`protect check`](#protect-check) — verify trust anchors against the sealed manifest, [`protect seal`](#protect-seal) — pin current hashes of trusted keys and agent config

## `aegorx protect check`

_verify trust anchors against the sealed manifest_

## `aegorx protect seal`

_pin current hashes of trusted keys and agent config_

## `aegorx quarantine`

_quarantine vault operations_

Subcommands: [`quarantine delete`](#quarantine-delete) — permanently delete an item by id, [`quarantine list`](#quarantine-list) — list quarantined items, [`quarantine restore`](#quarantine-restore) — restore an item by id

## `aegorx quarantine delete`

_permanently delete an item by id_

- `ID` — quarantine item id (from 'quarantine list')

## `aegorx quarantine list`

_list quarantined items_

## `aegorx quarantine restore`

_restore an item by id_

- `ID` — quarantine item id (from 'quarantine list')

## `aegorx ransomware`

_ransomware canary detection and protection_

Subcommands: [`ransomware check`](#ransomware-check) — check canary files for modifications, [`ransomware deploy`](#ransomware-deploy) — deploy canary files to directories, [`ransomware events`](#ransomware-events) — show recent detection events, [`ransomware list`](#ransomware-list) — list deployed canary files, [`ransomware remove`](#ransomware-remove) — remove all canary files, [`ransomware start`](#ransomware-start) — start background ransomware protection, [`ransomware status`](#ransomware-status) — show ransomware protection status, [`ransomware stop`](#ransomware-stop) — stop background protection

## `aegorx ransomware check`

_check canary files for modifications_

## `aegorx ransomware deploy`

_deploy canary files to directories_

- `PATHS` — directories to deploy canaries in

## `aegorx ransomware events`

_show recent detection events_

## `aegorx ransomware list`

_list deployed canary files_

## `aegorx ransomware remove`

_remove all canary files_

## `aegorx ransomware start`

_start background ransomware protection_

- `PATHS` — directories to protect

## `aegorx ransomware status`

_show ransomware protection status_

## `aegorx ransomware stop`

_stop background protection_

## `aegorx scan`

_scan a file or directory_

- `PATHS` — files or directories to scan
- `--json` `JSON` — emit machine-readable JSON report
- `--no-color` `NO_COLOR` — disable colored output
- `--no-ml` `NO_ML` — disable the ML detector
- `--db` `DB` — path to signature database
- `--rules` `RULES` — YARA rules directory (repeatable)
- `--max-size-mb` `MAX_SIZE_MB` — skip files larger than this (MB, minimum 1)

## `aegorx schedule`

_scheduled scan management_

Subcommands: [`schedule install`](#schedule-install) — install scheduled scan (systemd/launchd/schtasks), [`schedule status`](#schedule-status) — show scheduled scan status, [`schedule uninstall`](#schedule-uninstall) — remove scheduled scan

## `aegorx schedule install`

_install scheduled scan (systemd/launchd/schtasks)_

- `--paths` `PATHS` — directories to scan
- `--interval-hours` `INTERVAL_HOURS` — scan interval in hours

## `aegorx schedule status`

_show scheduled scan status_

## `aegorx schedule uninstall`

_remove scheduled scan_

## `aegorx ui`

_terminal dashboard (minimal, floating-button console)_

## `aegorx update`

_self-update: check for and apply signed releases_

Subcommands: [`update apply`](#update-apply) — verify + download + install the newest release artifact, [`update check`](#update-check) — fetch + verify the signed release manifest; report newer versions

## `aegorx update apply`

_verify + download + install the newest release artifact_

- `--url` `URL` — manifest URL (default: official latest release)
- `--kind` `auto|deb|wheel` — artifact to install (auto: deb when root+apt-get, else wheel)
- `--force` `FORCE` — apply even when not newer than the running version
- `--allow-expired` `ALLOW_EXPIRED` — accept manifests past their expiry

## `aegorx update check`

_fetch + verify the signed release manifest; report newer versions_

- `--url` `URL` — manifest URL (default: official latest release)

## `aegorx usb`

_USB/removable media auto-scan_

Subcommands: [`usb scan`](#usb-scan) — manually scan a mount point, [`usb start`](#usb-start) — start USB monitoring daemon, [`usb status`](#usb-status) — show USB scanner status, [`usb stop`](#usb-stop) — stop USB monitoring daemon

## `aegorx usb scan`

_manually scan a mount point_

- `PATH` — mount point or directory to scan

## `aegorx usb start`

_start USB monitoring daemon_

## `aegorx usb status`

_show USB scanner status_

## `aegorx usb stop`

_stop USB monitoring daemon_

## `aegorx vuln`

_vulnerability scanner (detect unpatched software)_

Subcommands: [`vuln ignore`](#vuln-ignore) — add software to ignore list, [`vuln ignored`](#vuln-ignored) — list ignored software, [`vuln scan`](#vuln-scan) — scan for vulnerable software, [`vuln status`](#vuln-status) — show last scan results, [`vuln unignore`](#vuln-unignore) — remove software from ignore list

## `aegorx vuln ignore`

_add software to ignore list_

- `SOFTWARE` — software name to ignore

## `aegorx vuln ignored`

_list ignored software_

## `aegorx vuln scan`

_scan for vulnerable software_

## `aegorx vuln status`

_show last scan results_

## `aegorx vuln unignore`

_remove software from ignore list_

- `SOFTWARE` — software name to unignore

## `aegorx watchdog`

_verify realtime protection liveness; restart if stale_

- `--max-age` `MAX_AGE` — heartbeat staleness threshold (seconds)
- `--service` `SERVICE` — systemd unit to restart
- `--no-restart` `NO_RESTART` — report only
