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


def test_cli_reference_docs_in_sync(tmp_path):
    """docs/CLI.md must match the live argparse tree (run scripts/gen_cli_docs.py)."""
    import subprocess
    import sys

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    doc = os.path.join(repo, "docs", "CLI.md")
    assert os.path.exists(doc), "docs/CLI.md missing - run scripts/gen_cli_docs.py"
    out = os.path.join(str(tmp_path), "CLI.md")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    subprocess.run(
        [sys.executable, os.path.join(repo, "scripts", "gen_cli_docs.py"), "--out", out],
        check=True,
        cwd=repo,
        env=env,
        capture_output=True,
    )
    committed = open(doc, encoding="utf-8").read()
    generated = open(out, encoding="utf-8").read()
    assert generated.strip(), "generated doc is empty"
    assert committed == generated, (
        "docs/CLI.md drifted from the CLI parser - run: python scripts/gen_cli_docs.py"
    )
