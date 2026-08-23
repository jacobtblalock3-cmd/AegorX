import json
import subprocess
import sys
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli(args):
    env = dict(os.environ)
    proc = subprocess.run(
        [sys.executable, "-m", "defentra.cli"] + args,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    return proc


def test_version_flag():
    proc = run_cli(["--version"])
    assert proc.returncode == 0
    assert proc.stdout.startswith("defentra ")


def test_scan_json_exit_codes(tmp_home, rules_dir, eicar_file, benign_file):
    proc = run_cli(
        ["scan", "--json", "--no-ml", "--db", str(tmp_home + "/sig.db"), "--rules", rules_dir, eicar_file]
    )
    assert proc.returncode == 2
    report = json.loads(proc.stdout)
    assert report["files"][0]["verdict"] == "malicious"

    proc_clean = run_cli(
        ["scan", "--json", "--no-ml", "--db", str(tmp_home + "/sig.db"), "--rules", rules_dir, benign_file]
    )
    assert proc_clean.returncode == 0
    clean_report = json.loads(proc_clean.stdout)
    assert clean_report["files"][0]["verdict"] == "clean"


def test_db_stats_and_add_hash(tmp_home):
    db_path = os.path.join(tmp_home, "sigs.db")
    proc = run_cli(["db", "--db", db_path, "stats"])
    assert proc.returncode == 0
    stats = json.loads(proc.stdout)
    assert stats["total"] >= 1

    proc_add = run_cli(
        [
            "db",
            "--db",
            db_path,
            "add-hash",
            "--sha256",
            "f" * 64,
            "--name",
            "CLI.Added.Threat",
        ]
    )
    assert proc_add.returncode == 0
    assert "total=" in proc_add.stdout


def test_model_info_without_training(tmp_home):
    proc = run_cli(["model", "info"])
    assert proc.returncode == 0
    info = json.loads(proc.stdout)
    assert info["available"] in (True, False)
