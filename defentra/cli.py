"""Defentra command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
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
    db_add.add_argument("--sha256", required=True)
    db_add.add_argument("--name", required=True)
    db_add.add_argument("--md5", default="")
    db_add.add_argument("--sha1", default="")
    db_add.add_argument("--family", default="")
    db_add.add_argument("--severity", type=int, default=8)
    db_import = db_sub.add_parser("import", help="import signatures from JSON file")
    db_import.add_argument("file")
    db_export = db_sub.add_parser("export", help="export signatures to JSON file")
    db_export.add_argument("file")

    p_q = sub.add_parser("quarantine", help="quarantine vault operations")
    q_sub = p_q.add_subparsers(dest="q_command")
    q_sub.add_parser("list", help="list quarantined items")
    q_restore = q_sub.add_parser("restore", help="restore an item by id")
    q_restore.add_argument("id")
    q_delete = q_sub.add_parser("delete", help="permanently delete an item by id")
    q_delete.add_argument("id")

    p_model = sub.add_parser("model", help="ML model information")
    model_sub = p_model.add_subparsers(dest="model_command")
    model_sub.add_parser("info", help="show loaded model info")
    p_fetch = model_sub.add_parser("fetch", help="download the published reference model")
    p_fetch.add_argument("--url", default=None, help="override model asset URL")

    p_mon = sub.add_parser("monitor", help="real-time on-access protection (Linux)")
    p_mon.add_argument("paths", nargs="+", help="directories/filesystem roots to watch")
    p_mon.add_argument("--backend", choices=("auto", "fanotify", "inotify"), default="auto")
    p_mon.add_argument("--workers", type=int, default=4, help="scan thread pool size (inotify mode)")
    p_mon.add_argument("--exclude", action="append", default=None, dest="exclude", help="fnmatch pattern to skip (repeatable)")
    p_mon.add_argument("--no-quarantine", action="store_true", help="detect but do not quarantine")
    p_mon.add_argument("--no-ml", action="store_true", help="disable the ML detector")
    p_mon.add_argument("--db", default=None, help="path to signature database")
    p_mon.add_argument("--rules", action="append", default=None, dest="rules", help="YARA rules directory (repeatable)")
    p_mon.add_argument("--max-size-mb", type=int, default=512, help="skip files larger than this (MB)")
    p_mon.add_argument("--log", default=None, help="JSONL audit log path (default: <state>/realtime.log)")

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
        if not args.json:
            ml_state = "loaded" if caps["ml_model"] else "not found (train with scripts/train_model.py)"
            yara_state = f"{caps['yara_rules']} rule file(s)" if caps["yara_available"] else "unavailable (pip install yara-python)"
            print(f"engines: signatures={caps['signature_db']} | yara={yara_state} | ml={ml_state} | hash={caps['hash_backend']}")

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
