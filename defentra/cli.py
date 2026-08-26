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

from defentra import __version__
from defentra.engine import ScanEngine
from defentra.quarantine.vault import QuarantineVault
from defentra.report import render_json, render_text
from defentra.utils import state_dir

EXIT_CLEAN = 0
EXIT_SUSPICIOUS = 1
EXIT_MALICIOUS = 2
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defentra",
        description="Defentra - open-source AI-assisted antivirus engine",
    )
    parser.add_argument("--version", action="version", version=f"defentra {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a file or directory")
    p_scan.add_argument("paths", nargs="+", help="files or directories to scan")
    p_scan.add_argument("--json", action="store_true", help="emit machine-readable JSON report")
    p_scan.add_argument("--no-color", action="store_true", help="disable colored output")
    p_scan.add_argument("--no-ml", action="store_true", help="disable the ML detector")
    p_scan.add_argument("--db", default=None, help="path to signature database")
    p_scan.add_argument("--rules", action="append", default=None, dest="rules", help="YARA rules directory (repeatable)")
    p_scan.add_argument("--max-size-mb", type=int, default=512, help="skip files larger than this (MB)")

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
    p_watch.add_argument("--service", default="defentra-monitor", help="systemd unit to restart")
    p_watch.add_argument("--no-restart", action="store_true", help="report only")

    p_protect = sub.add_parser("protect", help="trust-anchor integrity operations")
    protect_sub = p_protect.add_subparsers(dest="protect_command")
    protect_sub.add_parser("seal", help="pin current hashes of trusted keys and agent config")
    protect_sub.add_parser("check", help="verify trust anchors against the sealed manifest")

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


def cmd_scan(args) -> int:
    engine = ScanEngine(
        db_path=args.db,
        rules_dirs=args.rules,
        enable_ml=not args.no_ml,
        max_file_size=args.max_size_mb * 1024 * 1024,
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
        print(render_text(all_results, " ".join(args.paths), elapsed, color=not args.no_color))
        ml_state = "loaded" if caps["ml_model"] else "not found (train with scripts/train_model.py)"
        yara_state = f"{caps['yara_rules']} rule file(s)" if caps["yara_available"] else "unavailable (pip install yara-python)"
        vba_state = "on" if caps["office_macros"] else "off (pip install 'defentra[office]')"
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
    from defentra.signatures.db import SignatureDB

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
    from defentra.ml.classifier import MalwareClassifier

    clf = MalwareClassifier()
    info = clf.info()
    print(json.dumps(info, indent=2))
    if not info["available"]:
        print(
            "\nNo trained model found. Get the published reference model:\n"
            "  defentra model fetch\n"
            "or train your own from EMBER 2018:\n"
            "  python scripts/train_ember.py --train train.jsonl --test test.jsonl",
            file=sys.stderr,
        )
    return 0


def cmd_model_fetch(args) -> int:
    from defentra.ml import modelhub

    try:
        path = modelhub.fetch(url=args.url)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"model installed at {path}; it will be used automatically by scan and monitor")
    return 0


def cmd_monitor(args) -> int:
    from defentra.realtime.monitor import RealTimeMonitor
    from defentra.realtime.events import RealtimeUnavailableError

    engine = ScanEngine(
        db_path=args.db,
        rules_dirs=args.rules,
        enable_ml=not args.no_ml,
        max_file_size=args.max_size_mb * 1024 * 1024,
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
    from defentra.signing.keys import (
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
        print("distribute the public key; users install it with 'defentra keys trust'")
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
    from defentra.signatures.db import SignatureDB
    from defentra.signing.feed import (
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
                from defentra.rules_store import install_rules

                installed = install_rules(doc.get("rules"))
                rules_summary = f"; rules installed={installed['installed']} removed={installed['removed']}"
            except Exception as exc:
                rules_summary = f"; rules NOT updated ({exc})"
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
    from defentra.realtime.monitor import verify_audit_log

    if not getattr(args, "audit_command", None):
        print("no audit subcommand given; use: verify", file=sys.stderr)
        return EXIT_ERROR
    log_path = getattr(args, "log", None) or os.path.join(state_dir(), "realtime.log")
    ok, seq = verify_audit_log(log_path)
    if not os.path.exists(log_path):
        print(f"error: no audit log at {log_path}", file=sys.stderr)
        return EXIT_ERROR
    if ok:
        print(f"audit chain intact through record {seq}: {log_path}")
        return EXIT_CLEAN
    print(f"TAMPERED: audit chain broken at or after record {seq + 1} in {log_path}", file=sys.stderr)
    return EXIT_MALICIOUS


def cmd_agent(args) -> int:
    from defentra.management import agent as agent_mod

    command = getattr(args, "agent_command", None)
    if not command:
        print("no agent subcommand given; use: pair | run | status", file=sys.stderr)
        return EXIT_ERROR
    try:
        if command == "pair":
            cfg = agent_mod.pair(args.server, args.token, ca_cert=getattr(args, "ca_cert", None))
            print(f"paired as {cfg['agent_id']}; admin key pinned")
            print("start the agent with: defentra agent run")
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
    from defentra.management.server import ManagementServer

    command = getattr(args, "admin_command", None)
    if not command:
        print(
            "no admin subcommand given; use: serve | gen-certs | enroll-token | agents"
            " | revoke | policy | send | results | detections",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if command == "gen-certs":
        from defentra.management.certs import generate_server_cert

        cert_path, key_path = generate_server_cert(
            args.out, hostname=args.hostname, days=args.days
        )
        print(f"server certificate: {cert_path}")
        print(f"server private key: {key_path}  (keep secret; chmod 600)")
        print("serve TLS with:")
        print(f"  defentra admin serve --host 0.0.0.0 --tls-cert {cert_path} --tls-key {key_path}")
        print(f"clients pair with:  defentra agent pair --ca-cert {cert_path} ...")
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
        print("[admin] issue pairing tokens with: defentra admin enroll-token --name DEVICE")
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
        print(f"  defentra agent pair --server https://YOUR-CONSOLE:8477 --ca-cert server.crt --token {token}")
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
        from defentra.policy import validate_policy

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
        print(json.dumps(server.store.list_agents(), indent=2))
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
    from defentra.doctor import STATUS_FAIL, render_text, run_doctor

    reports = run_doctor()
    print(render_text(reports))
    return EXIT_ERROR if any(r["status"] == STATUS_FAIL for r in reports) else EXIT_CLEAN


def cmd_update(args) -> int:
    from defentra.update import UpdateError, auto_apply, check

    if not getattr(args, "update_command", None):
        print("specify a subcommand: defentra update check|apply", file=sys.stderr)
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
    from defentra.shield import liveness, restart_service

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
    from defentra import shield

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
            print("no protection manifest found; run 'defentra protect seal' first", file=sys.stderr)
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


def cmd_ui(args) -> int:
    from defentra import tui

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
