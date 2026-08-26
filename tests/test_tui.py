from __future__ import annotations

import json
import os
import time

import pytest

from defentra import tui

pytestmark = pytest.mark.skipif(
    not getattr(tui, "CURSES_AVAILABLE", True),
    reason="curses unavailable on this platform (Windows stdlib)",
)


def test_truncate_and_sanitize():
    assert tui.truncate("short", 10) == "short"
    assert tui.truncate("x" * 50, 5).endswith("…")
    assert tui.truncate("abc", 0) == ""
    cleaned = tui.sanitize("\x1b]0;pwn\x07evil.exe")
    assert "\x1b" not in cleaned and "\x07" not in cleaned


def test_button_definitions_have_unique_keys():
    keys = [k for _kind, k, _label in tui.BUTTON_DEFS]
    assert len(keys) == len(set(keys))
    assert "q" in keys
    for kind, key, label in tui.BUTTON_DEFS:
        assert kind == "key" and key and label


def test_button_layout_centers_within_width():
    spans = tui.button_layout(100, 30)
    assert all(y == spans[0][0] for y, _x, _w in spans)
    assert spans[0][1] >= 1
    last_end = spans[-1][1] + spans[-1][2]
    assert last_end <= 100 - 1


def test_parse_audit_tail_reads_threats_and_events(tmp_home):
    home = os.environ["DEFENTRA_HOME"]
    os.makedirs(home, exist_ok=True)
    log = os.path.join(home, "realtime.log")
    records = [
        {"ts": 1, "path": "/x/evil.exe", "verdict": "malicious", "detections": [{"detector": "signature"}]},
        {"ts": 2, "event": "rules-reloaded"},
        "not-json",
        {"ts": 3, "path": "/y/ok.txt", "verdict": "clean", "detections": []},
    ]
    with open(log, "w") as fh:
        for rec in records:
            fh.write(rec if isinstance(rec, str) else json.dumps(rec))
            fh.write("\n")

    rows = tui.parse_audit_tail(log, limit=10)
    kinds = [r["kind"] for r in rows]
    assert "threat" in kinds and "event" in kinds
    threat = [r for r in rows if r["kind"] == "threat"][0]
    assert threat["path"] == "evil.exe"

    missing = tui.parse_audit_tail(os.path.join(tmp_home, "nope.log"))
    assert missing == []


def test_status_snapshot_reports_engines(tmp_home):
    from defentra.signatures.db import SignatureDB

    SignatureDB(None)  # ensure db exists with builtin seed

    snap = tui.status_snapshot(state_dir_path=os.environ["DEFENTRA_HOME"])
    assert snap["signatures"] >= 1
    assert snap["version"]
    assert snap["protection_alive"] is False  # no monitor running in tests
    assert snap["anchors_ok"] is None  # unsealed by default


def test_dashboard_hit_test_without_curses():
    """hit_test math replicated without a terminal via button_layout."""
    width, height = 100, 30
    spans = tui.button_layout(width, height)
    y, x, w = spans[0]
    inside_key = None
    for (sy, sx, sw), (_kind, key, _label) in zip(spans, tui.BUTTON_DEFS):
        if sy <= y + 1 <= sy + 2 and sx <= x + 2 <= sx + sw:
            inside_key = key
            break
    assert inside_key == "s"
