"""Defentra command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from typing import List, Optional

from aegorx import __version__
from aegorx.engine import ScanEngine
from aegorx.quarantine.vault import QuarantineVault
from aegorx.report import render_json, render_text
from aegorx.utils import state_dir

EXIT_CLEAN = 0
EXIT_SUSPICIOUS = 1
EXIT_MALICIOUS = 2
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegorx",
        description="Defentra - open-source AI-assisted antivirus engine",
    )
    parser.add_argument("--version", action="version", version=f"aegorx {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a file or directory")
    p_scan.add_argument("paths", nargs="+", help="files or directories to scan")
    p_scan.add_argument("--json", action="store_true", help="emit machine-readable JSON report")
    p_scan.add_argument("--no-color", action="store_true", help="disable colored output")
    p_scan.add_argument("--no-ml", action="store_true", help="disable the ML detector")
    p_scan.add_argument("--db", default=None, help="path to signature database")
    p_scan.add_argument("--rules", action="append", default=None, dest="rules", help="YARA rules directory (repeatable)")
    p_scan.add_argument("--max-size-mb", type=int, default=512, help="skip files larger than this (MB, minimum 1)")

    p_db = sub.add_parser("db", help="signature database operations")
    p_db.add_argument("--db", default=None, help="path to signature database")
    db_sub = p_db.add_subparsers(dest="db_command")
    db_stats = db_sub.add_parser("stats", help="show database statistics")
    db_seed = db_sub.add_parser("seed", help="load built-in signatures")
    db_add = db_sub.add_parser("add-hash", help="add one hash signature")
    db_add.add_argument("--sha256", required=True, help="SHA-256 of the known-threat file")
    db_add.add_argument("--name", required=True, help="detection name to report on hit")
    db_add.add_argument("--md5", default="", help="optional MD5 for legacy lookups")
    db_add.add_argument("--sha1", default="", help="optional SHA-1 for legacy lookups")
    db_add.add_argument("--family", default="", help="malware family label")
    db_add.add_argument("--severity", type=int, default=8, help="severity 1-10 (default 8)")
    db_import = db_sub.add_parser("import", help="import signatures from JSON file")
    db_import.add_argument("file", help="JSON file with a list of signature objects")
    db_export = db_sub.add_parser("export", help="export signatures to JSON file")
    db_export.add_argument("file", help="destination JSON path")

    p_q = sub.add_parser("quarantine", help="quarantine vault operations")
    q_sub = p_q.add_subparsers(dest="q_command")
    q_sub.add_parser("list", help="list quarantined items")
    q_restore = q_sub.add_parser("restore", help="restore an item by id")
    q_restore.add_argument("id", help="quarantine item id (from 'quarantine list')")
    q_delete = q_sub.add_parser("delete", help="permanently delete an item by id")
    q_delete.add_argument("id", help="quarantine item id (from 'quarantine list')")

    p_model = sub.add_parser("model", help="ML model information")
    model_sub = p_model.add_subparsers(dest="model_command")
    model_sub.add_parser("info", help="show loaded model info")
    p_fetch = model_sub.add_parser("fetch", help="download the published reference model")
    p_fetch.add_argument("--url", default=None, help="override model asset URL")

    p_mon = sub.add_parser("monitor", help="real-time on-access protection (Linux)")
    p_mon.add_argument("paths", nargs="+", help="directories/filesystem roots to watch")
    p_mon.add_argument("--backend", choices=("auto", "fanotify", "inotify"), default="auto", help="kernel backend (auto: fanotify as root, else inotify)")
    p_mon.add_argument("--workers", type=int, default=4, help="scan thread pool size (inotify mode)")
    p_mon.add_argument("--exclude", action="append", default=None, dest="exclude", help="fnmatch pattern to skip (repeatable)")
    p_mon.add_argument("--no-quarantine", action="store_true", help="detect but do not quarantine")
    p_mon.add_argument("--no-ml", action="store_true", help="disable the ML detector")
    p_mon.add_argument("--db", default=None, help="path to signature database")
    p_mon.add_argument("--rules", action="append", default=None, dest="rules", help="YARA rules directory (repeatable)")
    p_mon.add_argument("--max-size-mb", type=int, default=512, help="skip files larger than this (MB)")
    p_mon.add_argument("--log", default=None, help="JSONL audit log path (default: <state>/realtime.log)")

    p_keys = sub.add_parser("keys", help="signing key management")
    keys_sub = p_keys.add_subparsers(dest="keys_command")
    k_gen = keys_sub.add_parser("generate", help="create an Ed25519 signing keypair (feed publishers)")
    k_gen.add_argument("--out", default=None, help="output directory (default: <state>/signing)")
    k_trust = keys_sub.add_parser("trust", help="install a public key into your trust store")
    k_trust.add_argument("pubkey", help="path to a PEM Ed25519 public key")
    keys_sub.add_parser("list", help="list trusted public keys")

    p_feed = sub.add_parser("feed", help="signed signature-feed operations")
    feed_sub = p_feed.add_subparsers(dest="feed_command")
    f_sign = feed_sub.add_parser("sign", help="sign a feed document (publishers)")
    f_sign.add_argument("file", help="unsigned feed JSON")
    f_sign.add_argument("--key", required=True, help="Ed25519 private key PEM")
    f_sign.add_argument("--out", default=None, help="write signed feed here (default: <file>.signed.json)")
    f_verify = feed_sub.add_parser("verify", help="verify a signed feed against trusted keys")
    f_verify.add_argument("file", help="signed feed JSON")
    f_update = feed_sub.add_parser("update", help="download, verify, and apply signature updates")
    src = f_update.add_mutually_exclusive_group()
    src.add_argument("--url", default=None, help="feed URL (default: official release asset)")
    src.add_argument("--file", dest="feed_file", default=None, help="apply from a local signed feed file")
    f_update.add_argument("--db", default=None, help="path to signature database")
    f_update.add_argument("--force", action="store_true", help="apply even if not newer than last update")
    f_update.add_argument("--allow-expired", action="store_true", help="accept feeds past their expiry")

    p_audit = sub.add_parser("audit", help="audit log operations")
    audit_sub = p_audit.add_subparsers(dest="audit_command")
    a_verify = audit_sub.add_parser("verify", help="verify the hash chain of a realtime audit log")
    a_verify.add_argument("log", nargs="?", default=None, help="audit log path (default: <state>/realtime.log)")

    p_agent = sub.add_parser("agent", help="managed client agent (connects to your DAS admin console)")
    agent_sub = p_agent.add_subparsers(dest="agent_command")
    ag_pair = agent_sub.add_parser("pair", help="pair this machine with a management server (one-time)")
    ag_pair.add_argument("--server", required=True, help="management server URL")
    ag_pair.add_argument("--token", required=True, help="one-time pairing token from the console")
    ag_pair.add_argument("--ca-cert", default=None, help="server cert / CA chain to pin for HTTPS (required off-host)")
    agent_sub.add_parser("run", help="start check-in loop (foreground; use systemd for production)")
    agent_sub.add_parser("status", help="show pairing/connection status")

    p_admin = sub.add_parser("admin", help="DAS administration console")
    admin_sub = p_admin.add_subparsers(dest="admin_command")
    ad_serve = admin_sub.add_parser("serve", help="run the management server")
    ad_serve.add_argument("--host", default="127.0.0.1", help="bind address (use 0.0.0.0 for remote agents)")
    ad_serve.add_argument("--port", type=int, default=8477, help="TCP port (default 8477)")
    ad_serve.add_argument("--db", default=None, help="fleet database path (default: <state>/fleet.db)")
    ad_serve.add_argument("--tls-cert", default=None, help="server certificate PEM (enables HTTPS)")
    ad_serve.add_argument("--tls-key", default=None, help="server private key PEM")
    ad_certs = admin_sub.add_parser("gen-certs", help="generate a self-signed TLS server certificate")
    ad_certs.add_argument("--out", required=True, help="output directory for server.crt/server.key")
    ad_certs.add_argument("--hostname", default=socket.gethostname(), help="DNS name clients will reach")
    ad_certs.add_argument("--days", type=int, default=825, help="certificate lifetime in days (default 825)")
    ad_enroll = admin_sub.add_parser("enroll-token", help="issue a one-time pairing token for a device")
    ad_enroll.add_argument("--name", required=True, help="unique device name")
    ad_enroll.add_argument("--ttl-hours", type=float, default=24.0, help="token lifetime in hours (default 24)")
    ad_revoke = admin_sub.add_parser("revoke", help="revoke a device's credentials immediately")
    ad_revoke.add_argument("agent_name", help="device name as shown by 'admin agents'")
    ad_policy = admin_sub.add_parser("policy", help="queue an apply-policy command for a device")
    ad_policy.add_argument("agent_name", help="target device name")
    ad_policy.add_argument("--file", required=True, help="policy JSON document")
    ad_agents = admin_sub.add_parser("agents", help="list managed devices and last-seen state")
    ad_agents.add_argument(
        "--stale-hours",
        type=float,
        default=None,
        metavar="N",
        help="only show devices not seen for more than N hours",
    )
    ad_send = admin_sub.add_parser("send", help="queue a command for a device")
    ad_send.add_argument("agent_name", help="target device name")
    ad_send.add_argument("command", choices=("ping", "status", "diag", "scan-path", "feed-update", "check-update", "quarantine-list", "quarantine-delete"), help="security-ops command to queue")
    ad_send.add_argument("--arg", action="append", default=None, dest="args", help="key=value argument (repeatable)")
    ad_results = admin_sub.add_parser("results", help="recent command results")
    ad_results.add_argument("--agent", default=None, help="filter by device name")
    ad_dets = admin_sub.add_parser("detections", help="aggregated detections across the fleet")
    ad_dets.add_argument("--limit", type=int, default=50, help="max rows to show (default 50)")

    p_watch = sub.add_parser("watchdog", help="verify realtime protection liveness; restart if stale")
    p_watch.add_argument("--max-age", type=int, default=90, help="heartbeat staleness threshold (seconds)")
    p_watch.add_argument("--service", default="aegorx-monitor", help="systemd unit to restart")
    p_watch.add_argument("--no-restart", action="store_true", help="report only")

    p_protect = sub.add_parser("protect", help="trust-anchor integrity operations")
    protect_sub = p_protect.add_subparsers(dest="protect_command")
    protect_sub.add_parser("seal", help="pin current hashes of trusted keys and agent config")
    protect_sub.add_parser("check", help="verify trust anchors against the sealed manifest")

    p_network = sub.add_parser("network", help="network protection: DNS filtering, connection monitoring, threat intel")
    net_sub = p_network.add_subparsers(dest="network_command")
    net_sub.add_parser("start", help="start network protection daemon (DNS filter + connection monitor)")
    net_sub.add_parser("stop", help="stop network protection daemon")
    net_sub.add_parser("status", help="show network protection status")
    net_update = net_sub.add_parser("update", help="manually refresh threat intel feeds")
    net_update.add_argument("--sources", default=None, help="comma-separated sources: urlhaus,stevenblack,phishingarmy")
    net_block = net_sub.add_parser("block", help="block a domain")
    net_block.add_argument("domain", help="domain to block")
    net_unblock = net_sub.add_parser("unblock", help="unblock a domain")
    net_unblock.add_argument("domain", help="domain to unblock")
    net_sub.add_parser("domains", help="list all blocked domains")
    net_check = net_sub.add_parser("check", help="check if a domain is blocked")
    net_check.add_argument("domain", help="domain to check")
    net_scan = net_sub.add_parser("scan", help="one-shot scan of active network connections")
    net_sub.add_parser("connections", help="show current active connections")

    p_usb = sub.add_parser("usb", help="USB/removable media auto-scan")
    usb_sub = p_usb.add_subparsers(dest="usb_command")
    usb_sub.add_parser("start", help="start USB monitoring daemon")
    usb_sub.add_parser("stop", help="stop USB monitoring daemon")
    usb_sub.add_parser("status", help="show USB scanner status")
    usb_scan = usb_sub.add_parser("scan", help="manually scan a mount point")
    usb_scan.add_argument("path", help="mount point or directory to scan")

    p_sched = sub.add_parser("schedule", help="scheduled scan management")
    sched_sub = p_sched.add_subparsers(dest="schedule_command")
    sched_install = sched_sub.add_parser("install", help="install scheduled scan (systemd/launchd/schtasks)")
    sched_install.add_argument("--paths", nargs="+", default=["/"], help="directories to scan")
    sched_install.add_argument("--interval-hours", type=int, default=24, help="scan interval in hours")
    sched_sub.add_parser("uninstall", help="remove scheduled scan")
    sched_sub.add_parser("status", help="show scheduled scan status")

    p_browser = sub.add_parser("browser", help="browser download protection")
    browser_sub = p_browser.add_subparsers(dest="browser_command")
    browser_sub.add_parser("start", help="start browser download monitoring")
    browser_sub.add_parser("stop", help="stop browser download monitoring")
    browser_sub.add_parser("status", help="show browser guard status")
    browser_dirs = browser_sub.add_parser("dirs", help="list monitored download directories")
    browser_add = browser_sub.add_parser("add", help="add a download directory to monitor")
    browser_add.add_argument("path", help="directory path to monitor")

    p_proc = sub.add_parser("process", help="process memory scanning (fileless malware detection)")
    proc_sub = p_proc.add_subparsers(dest="process_command")
    proc_pid = proc_sub.add_parser("scan-pid", help="scan a specific process by PID")
    proc_pid.add_argument("pid", type=int, help="process ID to scan")
    proc_all = proc_sub.add_parser("scan-all", help="scan all user processes")
    proc_all.add_argument("--skip-self", action="store_true", help="skip aegorx's own processes")
    proc_name = proc_sub.add_parser("scan-name", help="scan processes matching a name")
    proc_name.add_argument("name", help="process name substring to match")
    proc_sub.add_parser("status", help="show process scanner status")

    p_ransom = sub.add_parser("ransomware", help="ransomware canary detection and protection")
    ransom_sub = p_ransom.add_subparsers(dest="ransomware_command")
    ransom_deploy = ransom_sub.add_parser("deploy", help="deploy canary files to directories")
    ransom_deploy.add_argument("paths", nargs="+", help="directories to deploy canaries in")
    ransom_sub.add_parser("check", help="check canary files for modifications")
    ransom_sub.add_parser("remove", help="remove all canary files")
    ransom_sub.add_parser("list", help="list deployed canary files")
    ransom_start = ransom_sub.add_parser("start", help="start background ransomware protection")
    ransom_start.add_argument("paths", nargs="+", help="directories to protect")
    ransom_sub.add_parser("stop", help="stop background protection")
    ransom_sub.add_parser("status", help="show ransomware protection status")
    ransom_sub.add_parser("events", help="show recent detection events")

    p_firewall = sub.add_parser("firewall", help="outbound firewall (block C2 connections)")
    fw_sub = p_firewall.add_subparsers(dest="firewall_command")
    fw_sub.add_parser("start", help="start outbound connection monitoring")
    fw_sub.add_parser("stop", help="stop outbound monitoring")
    fw_sub.add_parser("status", help="show firewall status")
    fw_block_ip = fw_sub.add_parser("block-ip", help="add IP to outbound block list")
    fw_block_ip.add_argument("ip", help="IP address to block")
    fw_unblock_ip = fw_sub.add_parser("unblock-ip", help="remove IP from outbound block list")
    fw_unblock_ip.add_argument("ip", help="IP address to unblock")
    fw_block_port = fw_sub.add_parser("block-port", help="add port to outbound block list")
    fw_block_port.add_argument("port", type=int, help="port number to block")
    fw_unblock_port = fw_sub.add_parser("unblock-port", help="remove port from outbound block list")
    fw_unblock_port.add_argument("port", type=int, help="port number to unblock")
    fw_sub.add_parser("scan", help="one-shot scan of outbound connections")

    p_appctrl = sub.add_parser("appcontrol", help="application control (allowlist/blocklist executables)")
    ac_sub = p_appctrl.add_subparsers(dest="appcontrol_command")
    ac_check = ac_sub.add_parser("check", help="check if an executable is allowed")
    ac_check.add_argument("path", help="path to executable")
    ac_block_hash = ac_sub.add_parser("block-hash", help="block an executable by SHA-256 hash")
    ac_block_hash.add_argument("path", help="path to executable to hash and block")
    ac_block_path = ac_sub.add_parser("block-path", help="block executables matching a path pattern")
    ac_block_path.add_argument("pattern", help="glob pattern (e.g. /tmp/*.exe)")
    ac_block_ext = ac_sub.add_parser("block-extension", help="block executables with a specific extension")
    ac_block_ext.add_argument("extension", help="file extension (e.g. .scr)")
    ac_allow_path = ac_sub.add_parser("allow-path", help="allow executables matching a path pattern")
    ac_allow_path.add_argument("pattern", help="glob pattern")
    ac_sub.add_parser("rules", help="list all application control rules")
    ac_del_rule = ac_sub.add_parser("delete-rule", help="delete a rule by index")
    ac_del_rule.add_argument("index", type=int, help="rule index (from 'rules' command)")
    ac_sub.add_parser("status", help="show application control status")

    p_dns = sub.add_parser("dns", help="encrypted DNS (DoH/DoT)")
    dns_sub = p_dns.add_subparsers(dest="dns_command")
    dns_sub.add_parser("status", help="show encrypted DNS status")
    dns_resolve = dns_sub.add_parser("resolve", help="resolve a domain via encrypted DNS")
    dns_resolve.add_argument("domain", help="domain name to resolve")
    dns_resolve.add_argument("--type", choices=["A", "AAAA"], default="A", help="record type")
    dns_config = dns_sub.add_parser("config", help="configure encrypted DNS")
    dns_config.add_argument("--provider", choices=["cloudflare", "google", "quad9"], help="DNS provider")
    dns_config.add_argument("--mode", choices=["doh", "dot"], help="encryption mode")
    dns_config.add_argument("--timeout", type=int, help="query timeout in seconds")
    dns_sub.add_parser("providers", help="list available DNS providers")
    dns_sub.add_parser("clear-cache", help="clear DNS cache")

    p_vuln = sub.add_parser("vuln", help="vulnerability scanner (detect unpatched software)")
    vuln_sub = p_vuln.add_subparsers(dest="vuln_command")
    vuln_sub.add_parser("scan", help="scan for vulnerable software")
    vuln_sub.add_parser("status", help="show last scan results")
    vuln_ignore_add = vuln_sub.add_parser("ignore", help="add software to ignore list")
    vuln_ignore_add.add_argument("software", help="software name to ignore")
    vuln_ignore_rm = vuln_sub.add_parser("unignore", help="remove software from ignore list")
    vuln_ignore_rm.add_argument("software", help="software name to unignore")
    vuln_sub.add_parser("ignored", help="list ignored software")

    sub.add_parser("doctor", help="one-shot health/suitability report (read-only)")

    p_update = sub.add_parser("update", help="self-update: check for and apply signed releases")
    update_sub = p_update.add_subparsers(dest="update_command")
    u_check = update_sub.add_parser("check", help="fetch + verify the signed release manifest; report newer versions")
    u_check.add_argument("--url", default=None, help="manifest URL (default: official latest release)")
    u_apply = update_sub.add_parser("apply", help="verify + download + install the newest release artifact")
    u_apply.add_argument("--url", default=None, help="manifest URL (default: official latest release)")
    u_apply.add_argument(
        "--kind",
        choices=("auto", "deb", "wheel"),
        default="auto",
        help="artifact to install (auto: deb when root+apt-get, else wheel)",
    )
    u_apply.add_argument("--force", action="store_true", help="apply even when not newer than the running version")
    u_apply.add_argument("--allow-expired", action="store_true", help="accept manifests past their expiry")

    sub.add_parser("ui", help="terminal dashboard (minimal, floating-button console)")

    return parser


def _color_ok() -> bool:
    """ANSI colors: fine on POSIX terminals and Windows Terminal; off for legacy consoles."""
    if os.name == "nt":
        return bool(os.environ.get("WT_SESSION") or os.environ.get("TERM"))
    return sys.stdout.isatty()


def cmd_scan(args) -> int:
    max_size = max(1, args.max_size_mb) * 1024 * 1024
    engine = ScanEngine(
        db_path=args.db,
        rules_dirs=args.rules,
        enable_ml=not args.no_ml,
        max_file_size=max_size,
    )
    caps = engine.capabilities
    all_results = []
    started = time.time()
    for target in args.paths:
        all_results.extend(engine.scan_target(target))
    elapsed = time.time() - started
    if args.json:
        print(render_json(all_results, " ".join(args.paths), elapsed))
    else:
        color = not args.no_color and _color_ok()
        print(render_text(all_results, " ".join(args.paths), elapsed, color=color))
        ml_state = "loaded" if caps["ml_model"] else "not found (train with scripts/train_model.py)"
        yara_state = f"{caps['yara_rules']} rule file(s)" if caps["yara_available"] else "unavailable (pip install yara-python)"
        vba_state = "on" if caps["office_macros"] else "off (pip install 'aegorx[office]')"
        print(
            f"engines: signatures={caps['signature_db']} | yara={yara_state} | ml={ml_state} "
            f"| hash={caps['hash_backend']} | archives=zip,tar,gz | office-vba={vba_state}"
        )

    if any(r.verdict == "malicious" for r in all_results):
        return EXIT_MALICIOUS
    if any(r.verdict == "suspicious" for r in all_results):
        return EXIT_SUSPICIOUS
    if any(r.verdict == "error" for r in all_results):
        return EXIT_ERROR
    return EXIT_CLEAN


def _resolve_db(args) -> Optional[str]:
    return getattr(args, "db", None)


def cmd_db(args) -> int:
    from aegorx.signatures.db import SignatureDB

    db = SignatureDB(getattr(args, "db", None))
    if args.db_command == "stats":
        stats = db.stats()
        print(json.dumps(stats, indent=2))
        return 0
    if args.db_command == "seed":
        n = db.seed()
        print(f"seeded {n} new signature(s); total={db.count()}")
        return 0
    if args.db_command == "add-hash":
        n = db.add(
            sha256=args.sha256,
            name=args.name,
            md5=args.md5,
            sha1=args.sha1,
            family=args.family,
            severity=args.severity,
        )
        print(f"added={n} total={db.count()}")
        return 0
    if args.db_command == "import":
        n = db.import_json(args.file)
        print(f"imported {n} signature(s); total={db.count()}")
        return 0
    if args.db_command == "export":
        n = db.export_json(args.file)
        print(f"exported {n} signature(s) to {args.file}")
        return 0
    print("no db subcommand given; use: stats | seed | add-hash | import | export", file=sys.stderr)
    return EXIT_ERROR


def cmd_quarantine(args) -> int:
    vault = QuarantineVault()
    if args.q_command == "list":
        items = vault.list_items()
        if not items:
            print("quarantine is empty")
            return 0
        for item in items:
            enc = "encrypted" if item.get("encrypted") else "plain"
            print(f"{item['id']}  {enc:<9} {item['original_path']}  ({item.get('reason', '')})")
        return 0
    if args.q_command == "restore":
        try:
            dest = vault.restore(args.id)
        except KeyError:
            print(f"error: unknown id {args.id}", file=sys.stderr)
            return EXIT_ERROR
        print(f"restored to {dest}")
        return 0
    if args.q_command == "delete":
        if vault.delete(args.id):
            print("deleted permanently")
            return 0
        print(f"error: unknown id {args.id}", file=sys.stderr)
        return EXIT_ERROR
    print("no quarantine subcommand given; use: list | restore | delete", file=sys.stderr)
    return EXIT_ERROR


def cmd_model(args) -> int:
    from aegorx.ml.classifier import MalwareClassifier

    clf = MalwareClassifier()
    info = clf.info()
    print(json.dumps(info, indent=2))
    if not info["available"]:
        print(
            "\nNo trained model found. Get the published reference model:\n"
            "  aegorx model fetch\n"
            "or train your own from EMBER 2018:\n"
            "  python scripts/train_ember.py --train train.jsonl --test test.jsonl",
            file=sys.stderr,
        )
    return 0


def cmd_model_fetch(args) -> int:
    from aegorx.ml import modelhub

    try:
        path = modelhub.fetch(url=args.url)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"model installed at {path}; it will be used automatically by scan and monitor")
    return 0


def cmd_monitor(args) -> int:
    from aegorx.realtime.monitor import RealTimeMonitor
    from aegorx.realtime.events import RealtimeUnavailableError

    engine = ScanEngine(
        db_path=args.db,
        rules_dirs=args.rules,
        enable_ml=not args.no_ml,
        max_file_size=max(1, args.max_size_mb) * 1024 * 1024,
    )
    log_path = args.log or os.path.join(state_dir(), "realtime.log")
    try:
        monitor = RealTimeMonitor(
            engine=engine,
            paths=args.paths,
            backend=args.backend,
            workers=args.workers,
            excludes=args.exclude,
            quarantine=not args.no_quarantine,
            log_path=log_path,
        )
    except RealtimeUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    exit_code = EXIT_CLEAN
    try:
        monitor.run()
    except RealtimeUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        summary = monitor.summary()
        print(
            "session: received={received} scanned={scanned} malicious={malicious} "
            "suspicious={suspicious} quarantined={quarantined} errors={errors}".format(**summary)
        )
        if summary["malicious"] > 0:
            exit_code = EXIT_MALICIOUS
    return exit_code


def cmd_keys(args) -> int:
    from aegorx.signing.keys import (
        default_signing_dir,
        generate_keypair,
        load_public_key,
        public_key_fingerprint,
        trust_public_key,
        trusted_key_paths,
    )

    if args.keys_command == "generate":
        private_path, public_path = generate_keypair(args.out or default_signing_dir())
        print(f"private key: {private_path} (keep secret, mode 0600)")
        print(f"public key:  {public_path}")
        print("distribute the public key; users install it with 'aegorx keys trust'")
        return 0
    if args.keys_command == "trust":
        try:
            installed = trust_public_key(args.pubkey)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"trusted key installed at {installed}")
        return 0
    if args.keys_command == "list":
        paths = trusted_key_paths()
        if not paths:
            print("no trusted keys installed")
            return 0
        for path in paths:
            origin = "package" if "/trusted_keys/" in path else "user"
            try:
                fp = public_key_fingerprint(load_public_key(path))
            except Exception:
                fp = "unreadable"
            print(f"{fp}  [{origin}]  {path}")
        return 0
    print("no keys subcommand given; use: generate | trust | list", file=sys.stderr)
    return EXIT_ERROR


def cmd_feed(args) -> int:
    from aegorx.signatures.db import SignatureDB
    from aegorx.signing.feed import (
        DEFAULT_FEED_URL,
        FeedError,
        apply_feed,
        check_expiry,
        check_replay,
        fetch_feed,
        load_feed,
        record_applied,
        sign_document,
        save_feed,
        verify_document,
    )

    if args.feed_command == "sign":
        try:
            doc = load_feed(args.file)
            signed = sign_document(doc, args.key)
            out = save_feed(signed, args.out or (args.file + ".signed.json"))
        except (FeedError, OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"signed feed written to {out} ({len(signed.get('signatures', []))} signature(s))")
        return 0

    if args.feed_command == "verify":
        try:
            doc = load_feed(args.file)
            fingerprint = verify_document(doc)
            check_expiry(doc)
        except FeedError as exc:
            print(f"INVALID: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(
            f"valid (key {fingerprint}, generated {doc.get('generated_utc')}, "
            f"{len(doc.get('signatures', []))} signature(s), expires {doc.get('expires_utc')})"
        )
        return 0

    if args.feed_command == "update":
        try:
            if args.feed_file:
                doc = load_feed(args.feed_file)
                source_desc = args.feed_file
            else:
                doc = fetch_feed(args.url or DEFAULT_FEED_URL)
                source_desc = args.url or DEFAULT_FEED_URL
            fingerprint = verify_document(doc)
            check_expiry(doc, allow_expired=args.allow_expired)
            if not check_replay(doc, force=args.force):
                print(f"feed is not newer than the last applied update; use --force to override")
                return EXIT_CLEAN
            db = SignatureDB(getattr(args, "db", None))
            added = apply_feed(db, doc)
            rules_summary = ""
            try:
                from aegorx.rules_store import install_rules

                installed = install_rules(doc.get("rules"))
                rules_summary = f"; rules installed={installed['installed']} removed={installed['removed']}"
            except Exception as exc:
                rules_summary = f"; rules NOT updated ({exc})"
                print(f"warning: rules installation failed: {exc}", file=sys.stderr)
            else:
                record_applied(doc)
        except FeedError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(
            f"feed verified (key {fingerprint}); applied {added} new signature(s) "
            f"from {source_desc}; total={db.count()}{rules_summary}"
        )
        return EXIT_CLEAN
    print("no feed subcommand given; use: sign | verify | update", file=sys.stderr)
    return EXIT_ERROR


def cmd_audit(args) -> int:
    from aegorx.realtime.monitor import verify_audit_log

    if not getattr(args, "audit_command", None):
        print("no audit subcommand given; use: verify", file=sys.stderr)
        return EXIT_ERROR
    log_path = getattr(args, "log", None) or os.path.join(state_dir(), "realtime.log")
    if not os.path.exists(log_path):
        print(f"error: no audit log at {log_path}", file=sys.stderr)
        return EXIT_ERROR
    ok, seq = verify_audit_log(log_path)
    if ok:
        print(f"audit chain intact through record {seq}: {log_path}")
        return EXIT_CLEAN
    print(f"TAMPERED: audit chain broken at or after record {seq + 1} in {log_path}", file=sys.stderr)
    return EXIT_MALICIOUS


def cmd_agent(args) -> int:
    from aegorx.management import agent as agent_mod

    command = getattr(args, "agent_command", None)
    if not command:
        print("no agent subcommand given; use: pair | run | status", file=sys.stderr)
        return EXIT_ERROR
    try:
        if command == "pair":
            cfg = agent_mod.pair(args.server, args.token, ca_cert=getattr(args, "ca_cert", None))
            print(f"paired as {cfg['agent_id']}; admin key pinned")
            print("start the agent with: aegorx agent run")
            return EXIT_CLEAN
        if command == "status":
            cfg = agent_mod.load_config()
            print(json.dumps({
                "paired": True,
                "agent_id": cfg["agent_id"],
                "server": cfg["server_url"],
                "paired_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(cfg["paired_utc"])),
                "admin_key_pinned": bool(cfg.get("admin_public_key")),
            }, indent=2))
            return EXIT_CLEAN
        if command == "run":
            cfg = agent_mod.load_config()
            print(
                f"[agent] {cfg['agent_id']} checking in to {cfg['server_url']} every 60s"
                " (Ctrl+C to stop)",
                flush=True,
            )
            agent = agent_mod.DASAgent(cfg)
            try:
                agent.run_forever(interval_seconds=60.0)
            except KeyboardInterrupt:
                agent.stop()
                print("\n[agent] stopped", file=sys.stderr)
            return EXIT_CLEAN
    except agent_mod.AgentConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


def cmd_admin(args) -> int:
    from aegorx.management.server import ManagementServer

    command = getattr(args, "admin_command", None)
    if not command:
        print(
            "no admin subcommand given; use: serve | gen-certs | enroll-token | agents"
            " | revoke | policy | send | results | detections",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if command == "gen-certs":
        from aegorx.management.certs import generate_server_cert

        cert_path, key_path = generate_server_cert(
            args.out, hostname=args.hostname, days=args.days
        )
        print(f"server certificate: {cert_path}")
        print(f"server private key: {key_path}  (keep secret; chmod 600)")
        print("serve TLS with:")
        print(f"  aegorx admin serve --host 0.0.0.0 --tls-cert {cert_path} --tls-key {key_path}")
        print(f"clients pair with:  aegorx agent pair --ca-cert {cert_path} ...")
        return EXIT_CLEAN

    server = ManagementServer(
        db_path=getattr(args, "db", None),
        tls_cert=getattr(args, "tls_cert", None),
        tls_key=getattr(args, "tls_key", None),
    )

    if command == "serve":
        scheme = "https" if (args.tls_cert and args.tls_key) else "http"
        scope = "" if args.host == "127.0.0.1" else " — off-host clients must use TLS"
        print(f"[admin] management server on {scheme}://{args.host}:{args.port}{scope}")
        print("[admin] issue pairing tokens with: aegorx admin enroll-token --name DEVICE")
        if scheme == "http" and args.host != "127.0.0.1":
            print("::warning:: serving plain HTTP on a non-loopback interface", file=sys.stderr)
        server.start_background()
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            server.shutdown()
        return EXIT_CLEAN
    if command == "enroll-token":
        token = server.issue_pairing_token(args.name, ttl_hours=args.ttl_hours)
        print(f"pairing token for '{args.name}' (single use, expires in {args.ttl_hours:g}h):\n{token}")
        print("on the device run:")
        print(f"  aegorx agent pair --server https://YOUR-CONSOLE:8477 --ca-cert server.crt --token {token}")
        return EXIT_CLEAN
    if command == "revoke":
        ok = server.store.revoke(args.agent_name)
        if ok:
            print(f"revoked '{args.agent_name}': check-ins will be rejected immediately")
            return EXIT_CLEAN
        print(f"error: no active device named '{args.agent_name}'", file=sys.stderr)
        return EXIT_ERROR
    if command == "policy":
        rows = [a for a in server.store.list_agents() if a["name"] == args.agent_name]
        if not rows:
            print(f"error: unknown device '{args.agent_name}'", file=sys.stderr)
            return EXIT_ERROR
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read policy file: {exc}", file=sys.stderr)
            return EXIT_ERROR
        from aegorx.policy import validate_policy

        try:
            validate_policy(doc)
        except Exception as exc:
            print(f"error: invalid policy document: {exc}", file=sys.stderr)
            return EXIT_ERROR
        command_id = server.store.queue_command(
            rows[0]["agent_id"], "apply-policy", doc, server.admin_private_key
        )
        print(f"queued policy push {command_id}; applies on the device's next check-in")
        return EXIT_CLEAN
    if command == "agents":
        agents = server.store.list_agents()
        stale_hours = getattr(args, "stale_hours", None)
        now = time.time()
        if stale_hours is not None:
            agents = [
                a
                for a in agents
                if not a.get("last_seen_utc")
                or (now - a["last_seen_utc"]) > stale_hours * 3600
            ]
        print(json.dumps(agents, indent=2))
        if stale_hours is not None and not agents:
            print(f"no devices quiet for more than {stale_hours:g}h — fleet looks healthy")
        return EXIT_CLEAN
    if command == "send":
        rows = [a for a in server.store.list_agents() if a["name"] == args.agent_name]
        if not rows:
            print(f"error: unknown device '{args.agent_name}'", file=sys.stderr)
            return EXIT_ERROR
        cmd_args = {}
        for kv in args.args or []:
            key, _, value = kv.partition("=")
            cmd_args[key] = value
        command_id = server.store.queue_command(rows[0]["agent_id"], args.command, cmd_args, server.admin_private_key)
        print(f"queued {command_id}; result arrives on the device's next check-in")
        return EXIT_CLEAN
    if command == "results":
        print(json.dumps(server.store.results(agent_id=None, limit=50), indent=2))
        return EXIT_CLEAN
    if command == "detections":
        print(json.dumps(server.store.detections(limit=args.limit), indent=2))
        return EXIT_CLEAN
    return EXIT_ERROR


def cmd_doctor(args) -> int:
    from aegorx.doctor import STATUS_FAIL, render_text, run_doctor

    reports = run_doctor()
    print(render_text(reports))
    return EXIT_ERROR if any(r["status"] == STATUS_FAIL for r in reports) else EXIT_CLEAN


def cmd_update(args) -> int:
    from aegorx.update import UpdateError, auto_apply, check

    if not getattr(args, "update_command", None):
        print("specify a subcommand: aegorx update check|apply", file=sys.stderr)
        return EXIT_ERROR
    try:
        if args.update_command == "check":
            result = check(url=args.url)
            doc = {k: result[k] for k in ("current", "available", "update_available")}
            print(json.dumps(doc, indent=2))
            return EXIT_CLEAN
        outcome = auto_apply(
            kind=args.kind,
            url=args.url,
            force=args.force,
            allow_expired=getattr(args, "allow_expired", False),
        )
    except UpdateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps({k: v for k, v in outcome.items() if k != "_doc"}, indent=2))
    if not outcome.get("updated", True):
        return EXIT_CLEAN
    return EXIT_CLEAN if outcome.get("returncode", 0) == 0 else EXIT_ERROR


def cmd_watchdog(args) -> int:
    from aegorx.shield import liveness, restart_service

    status = liveness(max_age_seconds=args.max_age)
    print(json.dumps(status, indent=2))
    if status["healthy"]:
        return EXIT_CLEAN
    if args.no_restart:
        print("protection is NOT healthy; restart suppressed (--no-restart)", file=sys.stderr)
        return EXIT_MALICIOUS
    restarted = restart_service(args.service)
    if restarted:
        print(f"stale protection detected; restarted {args.service}")
        return EXIT_CLEAN
    print(
        "protection is NOT healthy and automatic restart failed;"
        " start it manually: sudo systemctl restart " + args.service,
        file=sys.stderr,
    )
    return EXIT_MALICIOUS


def cmd_protect(args) -> int:
    from aegorx import shield

    command = getattr(args, "protect_command", None)
    if not command:
        print("no protect subcommand given; use: seal | check", file=sys.stderr)
        return EXIT_ERROR
    if command == "seal":
        manifest = shield.seal()
        print(f"sealed {len(manifest['entries'])} trust-anchor file(s)")
        for path in manifest["entries"]:
            print(f"  {path}")
        return EXIT_CLEAN
    if command == "check":
        report = shield.verify()
        if not report["sealed"]:
            print("no protection manifest found; run 'aegorx protect seal' first", file=sys.stderr)
            return EXIT_ERROR
        if report["ok"]:
            print("trust anchors intact")
            return EXIT_CLEAN
        for path in report["changed"]:
            print(f"TAMPERED: {path}", file=sys.stderr)
        for path in report["missing"]:
            print(f"MISSING:  {path}", file=sys.stderr)
        return EXIT_MALICIOUS
    return EXIT_ERROR


def cmd_network(args) -> int:
    from aegorx.network.dns_filter import DNSFilter
    from aegorx.network.conn_monitor import ConnectionMonitor

    command = getattr(args, "network_command", None)
    if not command:
        print("no network subcommand given; use: start | stop | status | update | block | unblock | check | scan | connections | domains", file=sys.stderr)
        return EXIT_ERROR

    dns = DNSFilter()
    monitor = ConnectionMonitor()

    if command == "start":
        from aegorx.network.protector import NetworkProtector
        protector = NetworkProtector(dns_filter=dns, conn_monitor=monitor)
        protector.start()
        print("[network] network protection started", flush=True)
        print(protector.summary_text(), flush=True)
        try:
            while True:
                time.sleep(60)
                print(protector.summary_text(), flush=True)
        except KeyboardInterrupt:
            protector.stop()
            print("\n[network] stopped", flush=True)
        return EXIT_CLEAN

    if command == "stop":
        print("[network] stop requested (daemon must be stopped from its process)")
        return EXIT_CLEAN

    if command == "status":
        from aegorx.network.protector import NetworkProtector
        protector = NetworkProtector(dns_filter=dns, conn_monitor=monitor)
        print(protector.summary_text())
        return EXIT_CLEAN

    if command == "update":
        from aegorx.network.threat_feeds import update_threat_intel
        sources = None
        if args.sources:
            sources = [s.strip() for s in args.sources.split(",") if s.strip()]
        print("[network] updating threat intel feeds...", flush=True)
        results = update_threat_intel(dns, monitor, sources=sources)
        for source, info in results.items():
            if source.startswith("_"):
                continue
            status = info.get("status", "unknown")
            detail = ""
            if status == "ok":
                detail = f"domains={info.get('domains', 0)}"
            elif status == "error":
                detail = f"error={info.get('error', '?')}"
            print(f"  {source}: {status} {detail}")
        total = results.get("_total", {})
        print(f"[network] total: fetched={total.get('domains_fetched', 0)} added={total.get('domains_added', 0)}")
        print(f"[network] blocklist: {dns.count()} domains")
        return EXIT_CLEAN

    if command == "block":
        added = dns.block(args.domain)
        if added:
            print(f"[network] blocked {args.domain}")
        else:
            print(f"[network] {args.domain} is already blocked")
        return EXIT_CLEAN

    if command == "unblock":
        removed = dns.unblock(args.domain)
        if removed:
            print(f"[network] unblocked {args.domain}")
        else:
            print(f"[network] {args.domain} is not in the blocklist")
        return EXIT_CLEAN

    if command == "check":
        blocked = dns.lookup(args.domain)
        if blocked:
            print(f"[network] BLOCKED: {args.domain}")
            return EXIT_MALICIOUS
        print(f"[network] allowed: {args.domain}")
        return EXIT_CLEAN

    if command == "domains":
        domains = dns.domains()
        if not domains:
            print("[network] no blocked domains (run 'aegorx network update' to fetch threat intel)")
            return EXIT_CLEAN
        for d in domains:
            print(d)
        print(f"\n[network] {len(domains)} blocked domain(s)")
        return EXIT_CLEAN

    if command == "scan":
        from aegorx.network.conn_monitor import ConnectionMonitor
        mon = ConnectionMonitor()
        print("[network] scanning active connections...", flush=True)
        suspicious = mon.scan_once()
        if not suspicious:
            print("[network] no suspicious connections found")
        else:
            print(f"[network] {len(suspicious)} suspicious connection(s):")
            for conn in suspicious:
                print(f"  {conn.remote_addr}:{conn.remote_port} (proto={conn.proto} pid={conn.pid})")
        stats = mon.stats()
        print(f"[network] scanned={stats['connections_scanned']} suspicious={stats['suspicious_detected']}")
        return EXIT_CLEAN if not suspicious else EXIT_SUSPICIOUS

    if command == "connections":
        from aegorx.network.conn_monitor import _get_connections_platform
        conns = _get_connections_platform()
        if not conns:
            print("[network] no active connections found")
            return EXIT_CLEAN
        print(f"{'Local':<25} {'Remote':<25} {'Proto':<6} {'PID':<8} {'State'}")
        print("-" * 80)
        for c in conns:
            local = f"{c.local_addr}:{c.local_port}"
            remote = f"{c.remote_addr}:{c.remote_port}"
            print(f"{local:<25} {remote:<25} {c.proto:<6} {c.pid:<8} {c.state}")
        print(f"\n[network] {len(conns)} active connection(s)")
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_usb(args) -> int:
    from aegorx.usb_scanner import USBScanner

    command = getattr(args, "usb_command", None)
    if not command:
        print("no usb subcommand given; use: start | stop | status | scan", file=sys.stderr)
        return EXIT_ERROR

    scanner = USBScanner()

    if command == "start":
        engine = ScanEngine()
        def on_mount(path, reason):
            print(f"[usb] scanning {path}...", flush=True)
            result = engine.scan_path(path)
            if result.verdict == "malicious":
                print(f"[usb] THREAT: {path} — {len(result.detections)} detection(s)")
                for d in result.detections:
                    print(f"  {d.detector}: {d.rule_name} (severity {d.severity})")
            elif result.verdict == "suspicious":
                print(f"[usb] suspicious: {path}")
            else:
                print(f"[usb] clean: {path}")

        scanner.scan_callback = on_mount
        scanner.start()
        print("[usb] USB monitoring started", flush=True)
        try:
            while True:
                time.sleep(30)
                stats = scanner.stats()
                print(f"[usb] mounts={stats['mounts_detected']} scans={stats['scans_triggered']}", flush=True)
        except KeyboardInterrupt:
            scanner.stop()
            print("\n[usb] stopped", flush=True)
        return EXIT_CLEAN

    if command == "stop":
        print("[usb] stop requested (daemon must be stopped from its process)")
        return EXIT_CLEAN

    if command == "status":
        stats = scanner.stats()
        running = scanner.is_running()
        print(f"[usb] running={running}")
        print(f"[usb] mounts_detected={stats['mounts_detected']} scans_triggered={stats['scans_triggered']}")
        return EXIT_CLEAN

    if command == "scan":
        engine = ScanEngine()
        path = args.path
        if not os.path.isdir(path):
            print(f"[usb] {path} is not a directory", file=sys.stderr)
            return EXIT_ERROR
        print(f"[usb] scanning {path}...", flush=True)
        result = engine.scan_path(path)
        if result.verdict == "malicious":
            print(f"[usb] THREAT: {path} — {len(result.detections)} detection(s)")
            for d in result.detections:
                print(f"  {d.detector}: {d.rule_name} (severity {d.severity})")
            return EXIT_MALICIOUS
        print(f"[usb] clean: {path}")
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_schedule(args) -> int:
    from aegorx.scheduler import get_scheduler

    command = getattr(args, "schedule_command", None)
    if not command:
        print("no schedule subcommand given; use: install | uninstall | status", file=sys.stderr)
        return EXIT_ERROR

    scheduler = get_scheduler()

    if command == "install":
        paths = args.paths
        interval = args.interval_hours
        print(f"[schedule] installing scheduled scan (interval={interval}h, paths={paths})...")
        success = scheduler.install(scan_paths=paths, interval_hours=interval)
        if success:
            print("[schedule] installed successfully")
        else:
            print("[schedule] installation failed", file=sys.stderr)
            return EXIT_ERROR
        return EXIT_CLEAN

    if command == "uninstall":
        print("[schedule] removing scheduled scan...")
        success = scheduler.uninstall()
        if success:
            print("[schedule] removed successfully")
        else:
            print("[schedule] removal failed", file=sys.stderr)
            return EXIT_ERROR
        return EXIT_CLEAN

    if command == "status":
        status = scheduler.status()
        installed = status.get("installed", False)
        print(f"[schedule] installed={installed}")
        if status.get("output"):
            print(status["output"])
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_browser(args) -> int:
    from aegorx.browser_guard import BrowserDownloadMonitor

    command = getattr(args, "browser_command", None)
    if not command:
        print("no browser subcommand given; use: start | stop | status | dirs | add", file=sys.stderr)
        return EXIT_ERROR

    if command == "start":
        engine = ScanEngine()
        def on_download(path, reason):
            print(f"[browser] scanning {path}...", flush=True)
            result = engine.scan_file(path)
            if result.verdict == "malicious":
                print(f"[browser] THREAT: {path} — {len(result.detections)} detection(s)")
                for d in result.detections:
                    print(f"  {d.detector}: {d.rule_name} (severity {d.severity})")
            elif result.verdict == "suspicious":
                print(f"[browser] suspicious: {path}")

        monitor = BrowserDownloadMonitor(scan_callback=on_download)
        monitor.start()
        print("[browser] download protection started", flush=True)
        print(f"[browser] monitoring: {', '.join(monitor.download_dirs)}", flush=True)
        try:
            while True:
                time.sleep(30)
                stats = monitor.stats()
                print(f"[browser] files={stats['files_detected']} scans={stats['scans_triggered']}", flush=True)
        except KeyboardInterrupt:
            monitor.stop()
            print("\n[browser] stopped", flush=True)
        return EXIT_CLEAN

    if command == "stop":
        print("[browser] stop requested (daemon must be stopped from its process)")
        return EXIT_CLEAN

    if command == "status":
        monitor = BrowserDownloadMonitor()
        stats = monitor.stats()
        print(f"[browser] monitoring dirs: {', '.join(monitor.download_dirs)}")
        print(f"[browser] files_detected={stats['files_detected']} scans_triggered={stats['scans_triggered']}")
        return EXIT_CLEAN

    if command == "dirs":
        monitor = BrowserDownloadMonitor()
        if not monitor.download_dirs:
            print("[browser] no download directories found")
        for d in monitor.download_dirs:
            print(f"  {d}")
        return EXIT_CLEAN

    if command == "add":
        path = args.path
        if not os.path.isdir(path):
            print(f"[browser] {path} is not a directory", file=sys.stderr)
            return EXIT_ERROR
        print(f"[browser] added {path} to monitored directories")
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_process(args) -> int:
    from aegorx.process_scanner import ProcessMemoryScanner

    command = getattr(args, "process_command", None)
    if not command:
        print("no process subcommand given; use: scan-pid | scan-all | scan-name | status", file=sys.stderr)
        return EXIT_ERROR

    scanner = ProcessMemoryScanner()

    if command == "scan-pid":
        pid = args.pid
        print(f"[process] scanning PID {pid}...", flush=True)
        findings = scanner.scan_pid(pid)
        if not findings:
            print(f"[process] PID {pid}: clean")
            return EXIT_CLEAN
        print(f"[process] PID {pid}: {len(findings)} finding(s):")
        for f in findings:
            print(f"  [{f.finding_type}] {f.details}")
        return EXIT_SUSPICIOUS

    if command == "scan-all":
        skip_pids = set()
        if args.skip_self:
            skip_pids = {os.getpid()}
        print("[process] scanning all processes...", flush=True)
        findings = scanner.scan_all(skip_pids=skip_pids)
        if not findings:
            print("[process] all processes: clean")
            return EXIT_CLEAN
        print(f"[process] {len(findings)} finding(s):")
        for f in findings:
            print(f"  [PID {f.pid}] {f.process_name}: {f.details}")
        return EXIT_SUSPICIOUS

    if command == "scan-name":
        name = args.name
        print(f"[process] scanning processes matching '{name}'...", flush=True)
        findings = scanner.scan_name(name)
        if not findings:
            print(f"[process] no findings for '{name}'")
            return EXIT_CLEAN
        print(f"[process] {len(findings)} finding(s):")
        for f in findings:
            print(f"  [PID {f.pid}] {f.process_name}: {f.details}")
        return EXIT_SUSPICIOUS

    if command == "status":
        stats = scanner.stats()
        print(f"[process] processes_scanned={stats['processes_scanned']} findings={stats['findings']}")
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_ransomware(args) -> int:
    from aegorx.ransomware import RansomwareDetector, CanaryManager

    command = getattr(args, "ransomware_command", None)
    if not command:
        print("no ransomware subcommand given; use: deploy | check | remove | list | start | stop | status | events", file=sys.stderr)
        return EXIT_ERROR

    detector = RansomwareDetector()

    if command == "deploy":
        paths = args.paths
        count = detector.deploy_canaries(paths)
        print(f"[ransomware] deployed {count} canary file(s) to {len(paths)} director(ies)")
        return EXIT_CLEAN

    if command == "check":
        events = detector.check_canaries()
        if not events:
            print("[ransomware] all canaries intact")
            return EXIT_CLEAN
        print(f"[ransomware] {len(events)} event(s):")
        for e in events:
            print(f"  [{e.detection_type}] severity={e.severity} {e.details}")
        return EXIT_MALICIOUS

    if command == "remove":
        count = detector.canaries.remove_all()
        print(f"[ransomware] removed {count} canary file(s)")
        return EXIT_CLEAN

    if command == "list":
        canaries = detector.canaries.list_canaries()
        if not canaries:
            print("[ransomware] no canaries deployed")
            return EXIT_CLEAN
        print(f"{'Path':<60} {'Directory':<30} {'Created'}")
        print("-" * 110)
        for c in canaries:
            created = time.strftime("%Y-%m-%d %H:%M", time.localtime(c.created_at)) if c.created_at else "unknown"
            print(f"{c.path:<60} {c.directory:<30} {created}")
        print(f"\n[ransomware] {len(canaries)} canary file(s)")
        return EXIT_CLEAN

    if command == "start":
        paths = args.paths
        detector = RansomwareDetector()

        def on_event(event):
            print(f"[ransomware] ALERT: {event.detection_type} — {event.details}", flush=True)

        detector.response_callback = on_event
        count = detector.deploy_canaries(paths)
        detector.start_background_check()
        print(f"[ransomware] protection started ({count} canaries deployed)", flush=True)
        try:
            while True:
                time.sleep(30)
                stats = detector.stats()
                print(f"[ransomware] checks={stats['checks_performed']} events={stats['events_detected']}", flush=True)
        except KeyboardInterrupt:
            detector.stop_background_check()
            print("\n[ransomware] stopped", flush=True)
        return EXIT_CLEAN

    if command == "stop":
        print("[ransomware] stop requested (daemon must be stopped from its process)")
        return EXIT_CLEAN

    if command == "status":
        detector = RansomwareDetector()
        stats = detector.stats()
        canaries = detector.canaries.list_canaries()
        print(f"[ransomware] canaries={len(canaries)} checks={stats['checks_performed']} events={stats['events_detected']}")
        return EXIT_CLEAN

    if command == "events":
        detector = RansomwareDetector()
        events = detector.events()
        if not events:
            print("[ransomware] no events recorded")
            return EXIT_CLEAN
        print(f"{'Time':<20} {'Type':<15} {'Severity':<10} {'Details'}")
        print("-" * 80)
        for e in events:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.timestamp))
            print(f"{ts:<20} {e.detection_type:<15} {e.severity:<10} {e.details[:50]}")
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_firewall(args) -> int:
    from aegorx.firewall import OutboundFirewall

    command = getattr(args, "firewall_command", None)
    if not command:
        print("no firewall subcommand given; use: start | stop | status | block-ip | unblock-ip | block-port | unblock-port | scan", file=sys.stderr)
        return EXIT_ERROR

    fw = OutboundFirewall()

    if command == "start":
        def on_alert(conn, reason):
            print(f"[firewall] BLOCKED: {conn.remote_addr}:{conn.remote_port} — {reason}", flush=True)

        fw.alert_callback = on_alert
        fw.start()
        print("[firewall] outbound monitoring started", flush=True)
        try:
            while True:
                time.sleep(30)
                stats = fw.stats()
                print(f"[firewall] checked={stats['connections_checked']} blocked={stats['connections_blocked']}", flush=True)
        except KeyboardInterrupt:
            fw.stop()
            print("\n[firewall] stopped", flush=True)
        return EXIT_CLEAN

    if command == "stop":
        print("[firewall] stop requested (daemon must be stopped from its process)")
        return EXIT_CLEAN

    if command == "status":
        stats = fw.stats()
        print(f"[firewall] running={fw.is_running()}")
        print(f"[firewall] blocked_ips={len(fw.blocked_ips)} blocked_ports={len(fw.blocked_ports)}")
        print(f"[firewall] checked={stats['connections_checked']} blocked={stats['connections_blocked']}")
        return EXIT_CLEAN

    if command == "block-ip":
        fw.add_blocked_ip(args.ip)
        print(f"[firewall] blocked outbound to {args.ip}")
        return EXIT_CLEAN

    if command == "unblock-ip":
        fw.remove_blocked_ip(args.ip)
        print(f"[firewall] unblocked outbound to {args.ip}")
        return EXIT_CLEAN

    if command == "block-port":
        fw.add_blocked_port(args.port)
        print(f"[firewall] blocked outbound port {args.port}")
        return EXIT_CLEAN

    if command == "unblock-port":
        fw.remove_blocked_port(args.port)
        print(f"[firewall] unblocked outbound port {args.port}")
        return EXIT_CLEAN

    if command == "scan":
        print("[firewall] scanning outbound connections...", flush=True)
        blocked = fw.scan()
        if not blocked:
            print("[firewall] no suspicious outbound connections")
        else:
            print(f"[firewall] {len(blocked)} suspicious connection(s):")
            for conn in blocked:
                print(f"  {conn.remote_addr}:{conn.remote_port} (proto={conn.proto} pid={conn.pid})")
        return EXIT_CLEAN if not blocked else EXIT_SUSPICIOUS

    return EXIT_ERROR


def cmd_appcontrol(args) -> int:
    from aegorx.app_control import ApplicationController, PolicyStore

    command = getattr(args, "appcontrol_command", None)
    if not command:
        print("no appcontrol subcommand given; use: check | block-hash | block-path | block-extension | allow-path | rules | delete-rule | status", file=sys.stderr)
        return EXIT_ERROR

    ac = ApplicationController()

    if command == "check":
        verdict = ac.check(args.path)
        if verdict == "allow":
            print(f"[appcontrol] ALLOWED: {args.path}")
            return EXIT_CLEAN
        print(f"[appcontrol] BLOCKED: {args.path}")
        return EXIT_MALICIOUS

    if command == "block-hash":
        try:
            rule = ac.block_hash(args.path)
            print(f"[appcontrol] blocked by hash: {rule.value[:16]}... ({rule.name})")
        except ValueError as e:
            print(f"[appcontrol] error: {e}", file=sys.stderr)
            return EXIT_ERROR
        return EXIT_CLEAN

    if command == "block-path":
        rule = ac.block_path(args.pattern)
        print(f"[appcontrol] blocked path pattern: {args.pattern}")
        return EXIT_CLEAN

    if command == "block-extension":
        rule = ac.block_extension(args.extension)
        print(f"[appcontrol] blocked extension: {args.extension}")
        return EXIT_CLEAN

    if command == "allow-path":
        rule = ac.allow_path(args.pattern)
        print(f"[appcontrol] allowed path pattern: {args.pattern}")
        return EXIT_CLEAN

    if command == "rules":
        rules = ac.list_rules()
        if not rules:
            print("[appcontrol] no rules defined")
            return EXIT_CLEAN
        print(f"{'#':<5} {'Type':<12} {'Action':<8} {'Value':<40} {'Name'}")
        print("-" * 80)
        for i, r in enumerate(rules):
            val = r.value[:38] + ".." if len(r.value) > 40 else r.value
            print(f"{i:<5} {r.rule_type:<12} {r.action:<8} {val:<40} {r.name}")
        print(f"\n[appcontrol] {len(rules)} rule(s)")
        return EXIT_CLEAN

    if command == "delete-rule":
        if ac.remove_rule(args.index):
            print(f"[appcontrol] deleted rule #{args.index}")
        else:
            print(f"[appcontrol] rule #{args.index} not found", file=sys.stderr)
            return EXIT_ERROR
        return EXIT_CLEAN

    if command == "status":
        stats = ac.stats()
        rules = ac.list_rules()
        print(f"[appcontrol] rules={len(rules)} checked={stats['executables_checked']} "
              f"allowed={stats['allowed']} blocked={stats['blocked']}")
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_dns(args) -> int:
    from aegorx.network.encrypted_dns import EncryptedDNS

    command = getattr(args, "dns_command", None)
    if not command:
        print("no dns subcommand given; use: status | resolve | config | providers | clear-cache", file=sys.stderr)
        return EXIT_ERROR

    resolver = EncryptedDNS()

    if command == "status":
        stats = resolver.stats()
        cache = resolver.cache_stats()
        print(f"[dns] provider={resolver._provider.name} mode={resolver._mode} "
              f"queries={stats['queries']} cache_hits={stats['cache_hits']} "
              f"failures={stats['failures']} fallbacks={stats['fallbacks']}")
        print(f"[dns] cache: entries={cache['entries']} max={cache['max_size']}")
        return EXIT_CLEAN

    if command == "resolve":
        import socket
        qtype = 28 if args.type == "AAAA" else 1
        try:
            result = resolver.resolve(args.domain, qtype)
            if result["addresses"]:
                print(f"[dns] {args.domain} -> {', '.join(result['addresses'])}")
                print(f"[dns] source={result['source']} ttl={result['ttl']}")
                return EXIT_CLEAN
            else:
                print(f"[dns] {args.domain} -> no records found")
                return EXIT_MALICIOUS
        except Exception as exc:
            print(f"[dns] resolution failed: {exc}", file=sys.stderr)
            return EXIT_ERROR

    if command == "config":
        changed = False
        if args.provider:
            resolver.set_provider(args.provider)
            changed = True
        if args.mode:
            resolver.set_mode(args.mode)
            changed = True
        if args.timeout:
            resolver._timeout = args.timeout
            resolver._save_config()
            changed = True
        if changed:
            print(f"[dns] configured: provider={resolver._provider.name} mode={resolver._mode}")
        else:
            print(f"[dns] provider={resolver._provider.name} mode={resolver._mode} timeout={resolver._timeout}")
        return EXIT_CLEAN

    if command == "providers":
        for key, name in resolver.providers().items():
            marker = " *" if key == resolver._provider.name else ""
            print(f"  {key:<12} {name}{marker}")
        print("\n[dns] * = active provider")
        return EXIT_CLEAN

    if command == "clear-cache":
        resolver.clear_cache()
        print("[dns] cache cleared")
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_vuln(args) -> int:
    from aegorx.vuln_scanner import VulnScanner

    command = getattr(args, "vuln_command", None)
    if not command:
        print("no vuln subcommand given; use: scan | status | ignore | unignore | ignored", file=sys.stderr)
        return EXIT_ERROR

    scanner = VulnScanner()

    if command == "scan":
        print("[vuln] scanning installed software...", flush=True)
        findings = scanner.scan()
        if not findings:
            print("[vuln] no vulnerabilities found")
            return EXIT_CLEAN
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: severity_order.get(f.severity, 4))
        print(f"\n[vuln] {len(findings)} vulnerability(ies) found:\n")
        print(f"{'Software':<25} {'Installed':<15} {'Fixed':<15} {'Severity':<10} {'CVE'}")
        print("-" * 90)
        for f in findings:
            print(f"{f.software:<25} {f.installed_version:<15} {f.fixed_version:<15} {f.severity:<10} {f.cve}")
        stats = scanner.stats()
        print(f"\n[vuln] scanned={stats['software_scanned']} critical={stats['critical']} "
              f"high={stats['high']} medium={stats['medium']} low={stats['low']}")
        return EXIT_MALICIOUS if stats.get("critical", 0) or stats.get("high", 0) else EXIT_CLEAN

    if command == "status":
        last = scanner.last_scan()
        stats = scanner.stats()
        if last:
            age = int(time.time() - last)
            if age < 3600:
                age_str = f"{age // 60}m ago"
            elif age < 86400:
                age_str = f"{age // 3600}h ago"
            else:
                age_str = f"{age // 86400}d ago"
        else:
            age_str = "never"
        print(f"[vuln] last_scan={age_str} software={stats['software_scanned']} "
              f"vulns={stats['vulnerabilities_found']}")
        return EXIT_CLEAN

    if command == "ignore":
        scanner.add_ignore(args.software)
        print(f"[vuln] ignoring {args.software}")
        return EXIT_CLEAN

    if command == "unignore":
        scanner.remove_ignore(args.software)
        print(f"[vuln] no longer ignoring {args.software}")
        return EXIT_CLEAN

    if command == "ignored":
        ignored = scanner.list_ignored()
        if not ignored:
            print("[vuln] no software in ignore list")
            return EXIT_CLEAN
        for name in ignored:
            print(f"  {name}")
        print(f"\n[vuln] {len(ignored)} ignored")
        return EXIT_CLEAN

    return EXIT_ERROR


def cmd_ui(args) -> int:
    from aegorx import tui

    if not getattr(tui, "CURSES_AVAILABLE", True):
        print(
            "error: the terminal dashboard requires curses (unavailable on Windows;"
            " install windows-curses or use 'aegorx scan'/'aegorx doctor')",
            file=sys.stderr,
        )
        return EXIT_ERROR
    return tui.main()


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_ERROR
    handlers = {
        "scan": cmd_scan,
        "db": cmd_db,
        "quarantine": cmd_quarantine,
        "model": cmd_model,
        "monitor": cmd_monitor,
        "keys": cmd_keys,
        "feed": cmd_feed,
        "audit": cmd_audit,
        "agent": cmd_agent,
        "admin": cmd_admin,
        "watchdog": cmd_watchdog,
        "protect": cmd_protect,
        "doctor": cmd_doctor,
        "network": cmd_network,
        "usb": cmd_usb,
        "schedule": cmd_schedule,
        "browser": cmd_browser,
        "process": cmd_process,
        "ransomware": cmd_ransomware,
        "firewall": cmd_firewall,
        "appcontrol": cmd_appcontrol,
        "dns": cmd_dns,
        "vuln": cmd_vuln,
        "update": cmd_update,
        "ui": cmd_ui,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return EXIT_ERROR
    if args.command == "model" and getattr(args, "model_command", None) == "fetch":
        return cmd_model_fetch(args)
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
