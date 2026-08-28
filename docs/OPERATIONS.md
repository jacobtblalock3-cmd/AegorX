# AegorX Operations Runbook

Deployment guide and operational procedures for running AegorX as a managed
fleet: one **management console** (DAS), many **protected endpoints**, and the
detection-content pipeline that keeps both current.

Everything here uses only commands and units shipped in the package. For
release mechanics (tagging, artifacts) see [RELEASE.md](../RELEASE.md); for the
trust model see [SECURITY.md](../SECURITY.md).

---

## 1. Architecture at a glance

```
                ┌────────────────────────────┐
                │  management console (DAS)   │
                │  aegorx admin serve :8477 │
                │  fleet.db · admin key · TLS │
                └──────────┬─────────────────┘
        Ed25519-signed     │  HTTPS, per-device
        command queue      │  bearer tokens,
        + policy push      │  pinned server cert
                ┌──────────┴─────────────────┐
                │      managed endpoints      │
                │  aegorx agent run         │  ← check-in loop
                │  aegorx-monitor.service   │  ← fanotify blocking
                │  aegorx-feed-update.timer │  ← daily signed intel
                │  aegorx-watchdog.timer    │  ← liveness restarts
                └─────────────────────────────┘
```

* Agents authenticate with per-device tokens issued at one-time pairing;
  admins can revoke instantly.
* Every queued command carries an Ed25519 signature from the console's admin
  key; agents verify provenance and expiry before executing.
* Detection content (signature feeds, ML models) is distributed through a
  separate Ed25519-verified channel that works with or without a console.

---

## 2. Requirements

| Component | Needs |
|---|---|
| Console host | Python 3.9+, any Linux; port 8477 reachable from agent networks |
| Endpoints | Linux with `fanotify` (kernel 2.6.37+; blocking permission events used in production are CI-proven on modern kernels) |
| Windows / macOS endpoints | Standalone builds from GitHub Releases — **scan-only fleet mode**: on-demand + scheduled scans, telemetry, self-updates; no kernel-enforced realtime yet ([details](PLATFORMS.md)) |
| Realtime monitor | root / `CAP_SYS_ADMIN` — permission events require it |
| Optional ML detection | x86_64/aarch64 Linux; model fetched via `aegorx model fetch` |

Install on every machine (console and endpoints alike) from the channels in
[RELEASE.md](../RELEASE.md): `apt install ./aegorx_<version>_all.deb`,
`pip install aegorx`, or from source.

---

## 3. Deploying the management console

### 3.1 Pick a console home

All console state lives in one directory — the fleet database, the admin
signing key, and pairing records. Decide it once and export
`AEGORX_HOME` for **every** console-side command so the CLI and the service
agree:

```bash
sudo install -d -m 700 -o aegorx-admin -g aegorx-admin /var/lib/aegorx-console
echo 'export AEGORX_HOME=/var/lib/aegorx-console' | sudo tee /etc/profile.d/aegorx-console.sh
```

(If you skip this, everything defaults to `~/.aegorx` of whatever user you
run as — fine for evaluation, ambiguous for production.)

### 3.2 Bootstrap TLS

```bash
sudo -u aegorx-admin aegorx admin gen-certs \
    --out /etc/aegorx/tls --hostname console.corp.example --days 825
```

This writes `server.crt` / `server.key` (mode 0600). The certificate doubles
as the client trust anchor — endpoints pin it at pairing time, which is why a
public CA is not required.

### 3.3 Run the console as a service

```bash
sudo cp packaging/systemd/aegorx-admin.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aegorx-admin
```

The unit runs `aegorx admin serve --host 0.0.0.0 --port 8477` with TLS via
the certs above. Firewall accordingly — expose 8477/tcp only to networks where
agents live; nothing else needs to reach the console.

> The console binds plain HTTP if started without `--tls-cert/--tls-key`.
> Acceptable only for loopback testing; always run TLS beyond localhost.

### 3.4 Back up before going live

Stop the service and copy `/var/lib/aegorx-console/fleet.db` plus
`management_admin.key` to cold storage (see §10). Losing the admin key means
every endpoint must re-pair under a new key.

---

## 4. Enrolling client machines

On the console, mint a one-time pairing token bound to the device name
(default TTL 24h; use short TTLs for batch enrollments):

```bash
aegorx admin enroll-token --name workstation-01 --ttl-hours 8
# -> one-time token (shown once)
```

On the endpoint, pair with the console cert you generated in §3.2 — pinning is
mandatory for any non-loopback server, and pairing refuses otherwise:

```bash
sudo scp console.corp:/etc/aegorx/tls/server.crt /usr/local/share/aegorx-console.crt
sudo aegorx agent pair \
    --server https://console.corp.example:8477 \
    --ca-cert /usr/local/share/aegorx-console.crt \
    --token <ONE-TIME-TOKEN>
sudo systemctl enable --now aegorx-agent
```

Verify both ends:

```bash
aegorx agent status          # endpoint: paired, last check-in
aegorx admin agents          # console: fleet list with last-seen/platform/version
```

Tokens are single-use, persisted server-side (they survive console restarts),
and expire. A failed pairing (wrong/expired/replayed token) returns 403 and is
audit-logged.

---

## 5. Fleet administration

### 5.1 Device lifecycle

| Action | Command |
|---|---|
| List devices / last-seen | `aegorx admin agents` |
| Cut a device off immediately | `aegorx admin revoke workstation-01` |
| Re-enroll after revoke | issue a fresh token; device pairs again under a new identity |

Revocation takes effect on the next check-in attempt (403, audit-logged).

### 5.2 Central policy

Policy documents ride the signed-command channel. Create `policy.json`:

```json
{
  "exclusions": ["/var/lib/docker/**", "/proc/**"],
  "backend": "fanotify",
  "malicious_probability": 0.9,
  "scan_interval_seconds": 604800,
  "scheduled_paths": ["/home", "/srv"]
}
```

Push it:

```bash
aegorx admin policy workstation-01 --file policy.json
aegorx admin results --agent workstation-01   # confirm "status": "done"
```

Schema (validated strictly client-side — unknown fields rejected even though
the envelope is signed):

| Field | Meaning | Constraints |
|---|---|---|
| `exclusions` | realtime monitor fnmatch patterns | ≤ 200 strings, no `..` |
| `backend` | preferred kernel backend | `auto` \| `fanotify` \| `inotify` |
| `malicious_probability` / `suspicious_probability` | ML verdict thresholds | float in [0, 1] |
| `scan_interval_seconds` | scheduled deep-scan cadence | int ≥ 0 (0 = off) |
| `scheduled_paths` | deep-scan targets | list of paths |

Absence of policy = stock behavior; every field is optional.

### 5.3 Remote commands

```bash
aegorx admin send workstation-01 ping
aegorx admin send workstation-01 status
aegorx admin send workstation-01 diag
aegorx admin send workstation-01 scan-path --arg path=/home/alice
aegorx admin send workstation-01 feed-update
aegorx admin send workstation-01 quarantine-list
aegorx admin send workstation-01 quarantine-delete --arg id=<item>
```

Commands queue server-side and execute when the device checks in (default
agent interval: 60 s). Results appear in `admin results`; anything a scan finds
flows back into `admin detections`.

### 5.4 Watching the fleet

```bash
aegorx admin detections --limit 100   # fleet-wide detections feed
aegorx admin results                  # command outcomes
```

Operational rhythm: check `agents` daily for stale last-seen (a device quiet
for many hours may be offline or tampered), triage new detections weekly, and
review the console audit log (`fleet.db` table `audit`) after any access change.

---

## 6. Detection content operations

### 6.1 Signature feeds

Endpoints pull the official Ed25519-signed feed daily via
`aegorx-feed-update.timer` (ships with the package):

```bash
sudo systemctl enable --now aegorx-feed-update.timer
```

Manual update / verification at any time:

```bash
sudo aegorx feed update     # download → verify signature → apply atomically
aegorx db stats             # current signature count
```

Default feed: the rolling `signature-feed` GitHub Release rebuilt and re-signed
daily by CI. Custom/air-gapped feeds: publish your own document and point
`feed update --url <URL>` at it after installing your public key with
`aegorx keys trust`.

### 6.2 ML model

```bash
sudo aegorx model fetch     # SHA256+signature-verified reference model
aegorx model info           # confirm load
```

Override locations with `AEGORX_MODEL` (file) or `AEGORX_MODEL_DIR`
(directory) if you distribute models internally.

---

## 7. Realtime protection on endpoints

Enable blocking on-access protection:

```bash
sudo systemctl enable --now aegorx-monitor
```

The unit runs `aegorx monitor --backend fanotify /` as root (permission
events require it). Behavior: opens of marked files block until the engine
decides; malicious verdicts deny the open outright; scanner self-activity is
exempt via its own PID guard and fd-based scanning, so scanning never loops.

Notes:

* `backend: auto` falls back to non-blocking `inotify` watching when fanotify
  is unavailable (e.g. missing privileges); prefer explicit `fanotify` in
  policy for enforcement-critical hosts.
* Set `AEGORX_FANOTIFY_DEBUG=1` on the unit for per-event debug lines when
  diagnosing.
* Liveness is watchdogged — install the timer so stale monitors restart:

```bash
sudo cp packaging/systemd/aegorx-watchdog.{service,timer} /etc/systemd/system/
sudo systemctl enable --now aegorx-watchdog.timer
```

The watchdog restarts `aegorx-monitor` when its heartbeat exceeds the
staleness threshold (default 90 s; tune with `--max-age`).

---

## 8. State directory reference

Everything mutable lives under `AEGORX_HOME` (default `~/.aegorx`):

| Path | Side | Contents |
|---|---|---|
| `fleet.db` | console | fleet registry, hashed pending pairing tokens, command queue/results, detections, audit |
| `management_admin.key` | console | Ed25519 admin signing key (**critical**) |
| `agent.json` | endpoint | server URL, agent id, API token, pinned admin key (0600) |
| `policy.json` | endpoint | last applied central policy |
| `signatures.db` | endpoint | applied signature database |
| `model/` | endpoint | fetched ML model |
| `vault/` + `vault.key` | endpoint | encrypted quarantine vault |
| `realtime.log` | endpoint | hash-chained realtime audit log |
| `agent-audit.log` | endpoint | hash-chained management-command audit log |
| `protection-manifest.json` | endpoint | sealed trust-anchor hashes |

Integrity checks:

```bash
aegorx audit verify                    # chain of realtime.log
aegorx audit verify ~/.aegorx/agent-audit.log
sudo aegorx protect seal               # pin trust-anchor hashes
sudo aegorx protect check              # detect tampering later
```

Run `protect seal` once right after enrollment; schedule or spot-run `check`
periodically and after any suspected compromise.

---

## 9. Upgrades

### 9.1 Self-update channel (preferred)

Every release publishes an Ed25519-signed `update-manifest.json` alongside the
artifacts. Endpoints verify the manifest against the pinned root keys, enforce
the signed sha256 + size on download, and refuse downgrades/rollbacks:

```bash
sudo aegorx update check               # report newer signed release
sudo aegorx update apply               # verify → download → apt-get/pip install
sudo aegorx update apply --kind wheel  # force a channel (deb|wheel)
```

Notes:

* `.deb` artifacts auto-install only when running as root with apt-get
  present; otherwise install the downloaded wheel via pip.
* Manifests expire (14-day TTL). A host offline past expiry needs
  `--allow-expired` to apply, which is safe: signature and checksums still
  gate everything.
* Fleet visibility: `aegorx admin send DEVICE check-update` returns the
  device's current vs. available version through the normal result pipeline.

### 9.2 Manual upgrades

1. Verify the release: check `SHA256SUMS` against downloaded artifacts.
2. Upgrade the package (deb: `apt install ./aegorx_<new>_all.deb`, pip:
   `pip install -U aegorx`).
3. Restart services: `systemctl restart aegorx-admin aegorx-agent
   aegorx-monitor` as applicable.
4. Smoke-test: `aegorx db stats`, `aegorx model info`, then one
   `admin send <device> ping` end-to-end.

Fleet-wide: push `feed-update` via the console after upgrading endpoints so
content and code move together. There are no schema migrations today — the
fleet DB upgrades itself in place on first start.

---

## 10. Backup and restore

**Console (the important side):**

```bash
sudo systemctl stop aegorx-admin
sudo tar czf /secure/aegorx-console-backup.tgz \
    -C /var/lib/aegorx-console fleet.db management_admin.key \
    -C /etc/aegorx tls
sudo systemctl start aegorx-admin
```

Restore = stop service, untar into the same paths, start. Test restores
quarterly; an untested backup is a rumor.

**Endpoint:** state is reconstructable — re-pairing re-issues credentials, and
feeds/models re-download. If you want bit-exact continuity, archive `agent.json`,
`policy.json`, and `protection-manifest.json` (all mode-0600 secrets).

---

## 11. Incident response

**Compromised or stolen endpoint**

1. `aegorx admin revoke <device>` — immediate credential cutoff.
2. Pull history: `aegorx admin results --agent <device>` and
   `aegorx admin detections` for what it saw/reported.
3. Rebuild the host; re-enroll fresh with a new name only if trusted again.

**Suspicious detection triage**

```bash
aegorx admin detections                       # what/where/which detector
aegorx admin send <device> scan-path --arg path=<dir>   # sweep neighbors
aegorx admin send <device> quarantine-list
aegorx admin send <device> quarantine-delete --arg id=<id>   # dispose
```

Quarantined items are Fernet-encrypted at rest; deletion is permanent.

**Suspected tampering with protection itself**

```bash
sudo aegorx protect check     # trust anchors vs sealed manifest
aegorx audit verify            # audit chain integrity
```

Any mismatch: treat the host as compromised, escalate to revocation above.

---

## 12. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Pairing returns 403 | Token expired, already used, or revoked — mint a new one (`admin enroll-token`). Check clock skew. |
| Pairing rejects URL | Off-host HTTP(S) without `--ca-cert`. Pin the cert first (§4). |
| TLS error on pair/click-in | Server cert regenerated but clients pin the old one — redistribute `server.crt`, or restore the original cert/key. |
| Agent never appears in `admin agents` | Network/firewall to :8477; console actually running with TLS; `journalctl -u aegorx-agent` for check-in errors. |
| Device stopped checking in | It was revoked, or token rotated — `admin agents` shows last-seen; re-enroll if needed. |
| Command stuck "pending" | Endpoint offline until next check-in (60 s default). Long queues drain ≤20 per check-in. |
| Command result "rejected" | Signature invalid or expired envelope — verify console clock; never hand-forge envelopes. |
| Monitor not blocking | Not root / no CAP_SYS_ADMIN; backend fell back to inotify. Run unit as root, set `backend: fanotify` in policy. |
| Opens blocked forever on a file | Scanner decision path wedged — check `journalctl -u aegorx-monitor`; `AEGORX_FANOTIFY_DEBUG=1` for event traces; watchdog should restart it. |
| `feed update` exits nonzero repeatedly | Feed signature failed against trusted keys — do not force; inspect `aegorx keys list` and the feed source. |

Environment variables that matter: `AEGORX_HOME` (state dir override),
`AEGORX_MODEL` / `AEGORX_MODEL_DIR` (model placement),
`AEGORX_FANOTIFY_DEBUG` (event tracing).
