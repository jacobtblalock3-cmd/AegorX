"""Defentra terminal UI: a minimal Linux-console dashboard.

Pure stdlib (curses). Visual language: near-black canvas, thin rounded
panels, and a row of shadowed action buttons drawn last so they appear to
float above the content. Keyboard-first; buttons also respond to mouse
clicks where the terminal supports it.

Launch with:  aegorx ui
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

try:
    import curses
except ImportError:  # Windows: curses is not in the stdlib
    curses = None

from aegorx import __version__

CURSES_AVAILABLE = curses is not None

ACCENT_CYAN = 1
ACCENT_GREEN = 2
ACCENT_MAGENTA = 3
ACCENT_YELLOW = 4
DIM_SHADOW = 5
FG_DEFAULT = 6

BUTTON_DEFS = [
    ("key", "s", "Scan"),
    ("key", "f", "Feed update"),
    ("key", "r", "Rules"),
    ("key", "p", "Protect"),
    ("key", "w", "Watchdog"),
    ("key", "q", "Quit"),
]


def truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


def sanitize(text: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in str(text))


def parse_audit_tail(path: str, limit: int = 12) -> List[Dict]:
    """Last `limit` structured records from a realtime/audit JSONL file."""
    rows: List[Dict] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            # Read only the last portion of the file for efficiency
            fh.seek(0, 2)
            file_size = fh.tell()
            # Read last 64KB or whole file, whichever is smaller
            read_size = min(file_size, 65536)
            fh.seek(max(0, file_size - read_size))
            lines = fh.readlines()[-limit:]
    except OSError:
        return rows
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(rec.get("detections"), list) and rec.get("path"):
            rows.append(
                {
                    "kind": "threat" if rec.get("verdict") != "clean" else "info",
                    "verdict": str(rec.get("verdict", "")),
                    "path": os.path.basename(str(rec["path"])),
                    "ts": rec.get("ts", 0),
                }
            )
        elif rec.get("event"):
            rows.append({"kind": "event", "verdict": str(rec["event"]), "path": "", "ts": rec.get("ts", 0)})
    return rows[-limit:]


def status_snapshot(state_dir_path: Optional[str] = None) -> Dict:
    """Gather dashboard data without touching curses."""
    from aegorx.utils import state_dir
    from aegorx.shield import liveness

    base = state_dir_path or state_dir()

    signatures = 0
    try:
        from aegorx.signatures.db import SignatureDB

        signatures = SignatureDB(os.path.join(base, "signatures.db")).count()
    except Exception:
        pass

    feed_rules = 0
    try:
        from aegorx.rules_store import current_rules

        feed_rules = len(current_rules())
    except Exception:
        pass

    ml_available = False
    ml_meta = {}
    try:
        from aegorx.ml.classifier import MalwareClassifier

        clf = MalwareClassifier()
        ml_available = clf.available
        ml_meta = clf.metadata or {}
    except Exception:
        pass

    paired = False
    agent_id = ""
    try:
        cfg_path = os.path.join(base, "agent.json")
        with open(cfg_path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        paired = bool(cfg.get("agent_id"))
        agent_id = str(cfg.get("agent_id", ""))
    except (OSError, json.JSONDecodeError):
        pass

    quarantine_count = 0
    try:
        index_path = os.path.join(base, "quarantine", "index.json")
        with open(index_path, "r", encoding="utf-8") as fh:
            items = json.load(fh)
        if isinstance(items, list):
            quarantine_count = len(items)
    except (OSError, json.JSONDecodeError):
        pass

    anchors_ok = None
    try:
        from aegorx import shield

        manifest_file = os.path.join(base, shield.MANIFEST_NAME)
        if os.path.exists(manifest_file):
            import hashlib

            with open(manifest_file, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
            changed = missing = 0
            for target, expected in (manifest.get("entries") or {}).items():
                if not os.path.isfile(target):
                    missing += 1
                    continue
                h = hashlib.sha256()
                with open(target, "rb") as fh2:
                    for chunk in iter(lambda: fh2.read(65536), b""):
                        h.update(chunk)
                if h.hexdigest() != expected:
                    changed += 1
            anchors_ok = changed == 0 and missing == 0
    except Exception:
        anchors_ok = None

    live = liveness(max_age_seconds=600)

    return {
        "version": __version__,
        "signatures": signatures,
        "feed_rules": feed_rules,
        "ml_available": ml_available,
        "ml_source": str(ml_meta.get("source", "")) if ml_meta else "",
        "paired": paired,
        "agent_id": agent_id,
        "quarantine_count": quarantine_count,
        "anchors_ok": anchors_ok,
        "protection_alive": bool(live.get("healthy")),
        "audit_log": os.path.join(base, "realtime.log"),
        "state_dir": base,
    }


def button_layout(width: int, height: int) -> List[Tuple[int, int, int]]:
    """Compute (y, x, total_width) for the floating button row."""
    labels = [f" {label} [{key.upper()}] " for _kind, key, label in BUTTON_DEFS]
    total = sum(len(label) + 2 for label in labels)
    x = max(1, (width - total) // 2)
    y = max(0, height - 4)
    spans = []
    cursor = x
    for label in labels:
        w = len(label) + 2
        spans.append((y, cursor, w))
        cursor += w
    return spans


class Dashboard:
    """Curses application. All drawing is exception-guarded for small terms."""

    MIN_COLS = 72
    MIN_LINES = 22

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.snapshot: Dict = {}
        self.rows: List[Dict] = []
        self.message = ""
        self.busy: Optional[str] = None
        self._refresh_data()

    # -- data ------------------------------------------------------------
    def _refresh_data(self):
        self.snapshot = status_snapshot()
        self.rows = parse_audit_tail(self.snapshot.get("audit_log", ""))

    def set_message(self, text: str):
        self.message = text

    def run_action_async(self, label: str, fn: Callable[[], str]):
        if self.busy is not None:
            self.set_message("another action is running…")
            return

        def worker():
            try:
                result = fn()
            except Exception as exc:
                result = f"error: {exc}"
            self.busy = None
            self.set_message(result)
            self._refresh_data()

        self.busy = label
        self.set_message(f"{label} running…")
        threading.Thread(target=worker, daemon=True).start()

    # -- drawing ---------------------------------------------------------
    def _panel(self, y, x, w, h, title="", accent=ACCENT_CYAN):
        scr = self.stdscr
        try:
            scr.attron(curses_color(accent))
            scr.addstr(y, x, "╭" + "─" * (w - 2) + "╮")
            scr.addstr(y + h - 1, x, "╰" + "─" * (w - 2) + "╯")
            scr.attroff(curses_color(accent))
            for row in range(y + 1, y + h - 1):
                scr.addstr(row, x, "│")
                scr.addstr(row, x + w - 1, "│")
            if title:
                scr.addstr(y, x + 2, f" {title} ")
        except curses_error():
            pass

    def _put(self, y, x, text, accent=None, bold=False):
        try:
            if accent is not None:
                self.stdscr.attron(curses_color(accent))
            if bold:
                self.stdscr.attron(curses.A_BOLD)
            self.stdscr.addstr(y, x, truncate(text, max(0, self.stdscr.getmaxyx()[1] - x - 1)))
            if bold:
                self.stdscr.attroff(curses.A_BOLD)
            if accent is not None:
                self.stdscr.attroff(curses_color(accent))
        except curses_error():
            pass

    def _button(self, y, x, w, key, label, hovered=False):
        scr = self.stdscr
        text = f" {label} [{key.upper()}] "
        color = ACCENT_GREEN if hovered else ACCENT_CYAN
        try:
            scr.attron(curses_color(color))
            scr.addstr(y, x, "╭" + "─" * (w - 2) + "╮")
            scr.addstr(y + 2, x, "╰" + "─" * (w - 2) + "╯")
            scr.addstr(y + 1, x, "│")
            scr.addstr(y + 1, x + w - 1, "│")
            scr.attroff(curses_color(color))
            scr.attron(curses_color(DIM_SHADOW))
            scr.addstr(y + 1, x + w, "░")
            scr.addstr(y + 2, x + 1, "░" * (w - 1))
            scr.attroff(curses_color(DIM_SHADOW))
            scr.addstr(y + 1, x + 1, text)
        except curses_error():
            pass

    def draw(self):
        scr = self.stdscr
        height, width = scr.getmaxyx()
        scr.erase()
        if height < self.MIN_LINES or width < self.MIN_COLS:
            self._put(0, 1, f"terminal too small ({width}x{height}); need {self.MIN_COLS}x{self.MIN_LINES}", ACCENT_YELLOW)
            scr.refresh()
            return

        snap = self.snapshot
        self._put(1, 3, "◈ DEFENTRA", ACCENT_MAGENTA, bold=True)
        self._put(1, 15, f"DAS v{snap['version']}", DIM_SHADOW)
        prot = "● LIVE" if snap["protection_alive"] else "○ DOWN"
        self._put(1, width // 2, f"protection {prot}", ACCENT_GREEN if snap["protection_alive"] else ACCENT_YELLOW)

        left_w = max(34, width // 2 - 2)
        right_x = left_w + 2
        right_w = width - right_x - 2
        body_h = height - 9

        self._panel(3, 2, left_w, body_h, "activity", ACCENT_CYAN)
        row_y = 5
        for row in self.rows[: body_h - 4]:
            marker = "▲" if row["kind"] == "threat" else "·"
            color = ACCENT_YELLOW if row["kind"] == "event" else ACCENT_GREEN
            line = f"{marker} {row['verdict']} {truncate(sanitize(row['path']), left_w - 16)}"
            self._put(row_y, 4, line, color)
            row_y += 1
        if not self.rows:
            self._put(row_y, 4, "no events yet — press s to run a scan", DIM_SHADOW)

        self._panel(3, right_x, right_w, body_h, "engines", ACCENT_CYAN)
        engines = [
            ("signatures", str(snap["signatures"]), ACCENT_GREEN),
            ("feed rules", str(snap["feed_rules"]), ACCENT_GREEN),
            (
                "ml model",
                f"{snap['ml_source'] or 'not installed'}",
                ACCENT_GREEN if snap["ml_available"] else ACCENT_YELLOW,
            ),
            (
                "fleet",
                snap["agent_id"] if snap["paired"] else "unpaired",
                ACCENT_GREEN if snap["paired"] else DIM_SHADOW,
            ),
            (
                "quarantine",
                f"{snap['quarantine_count']} item(s)",
                ACCENT_GREEN if snap["quarantine_count"] == 0 else ACCENT_YELLOW,
            ),
        ]
        ry = 5
        for name, value, color in engines:
            self._put(ry, right_x + 2, f"{name:<12}", DIM_SHADOW)
            self._put(ry, right_x + 15, truncate(value, right_w - 18), color)
            ry += 1
        if snap["anchors_ok"] is None:
            self._put(ry, right_x + 2, f"{'anchors':<12}", DIM_SHADOW)
            self._put(ry, right_x + 15, "unsealed", ACCENT_YELLOW)
        else:
            ok = snap["anchors_ok"]
            self._put(ry, right_x + 2, f"{'anchors':<12}", DIM_SHADOW)
            self._put(ry, right_x + 15, "intact" if ok else "TAMPERED", ACCENT_GREEN if ok else ACCENT_MAGENTA)

        msg_y = height - 6
        message = truncate(sanitize(self.message), width - 6)
        self._put(msg_y, 3, message, ACCENT_YELLOW)

        self._draw_buttons(width, height)
        scr.refresh()

    def _draw_buttons(self, width, height):
        spans = button_layout(width, height)
        for (y, x, w), (_kind, key, label) in zip(spans, BUTTON_DEFS):
            self._button(y, x, w, key, label)

    def hit_test(self, my, mx) -> Optional[str]:
        spans = button_layout(*self.stdscr.getmaxyx())
        for (y, x, w), (_kind, key, _label) in zip(spans, BUTTON_DEFS):
            if y <= my <= y + 2 and x <= mx <= x + w:
                return key
        return None


def curses_error():
    import curses

    return curses.error


def curses_color(index):
    import curses

    return curses.color_pair(index)


def init_colors():
    import curses

    curses.start_color()
    curses.use_default_colors()
    pairs = [
        (ACCENT_CYAN, curses.COLOR_CYAN),
        (ACCENT_GREEN, curses.COLOR_GREEN),
        (ACCENT_MAGENTA, curses.COLOR_MAGENTA),
        (ACCENT_YELLOW, curses.COLOR_YELLOW),
        (DIM_SHADOW, curses.COLOR_BLACK),
        (FG_DEFAULT, curses.COLOR_WHITE),
    ]
    for idx, fg in pairs:
        curses.init_pair(idx, fg, -1)


def action_scan(prompt_result: Dict) -> str:
    path = prompt_result.get("path") or os.path.expanduser("~/Downloads")
    from aegorx.engine import ScanEngine

    engine = ScanEngine(enable_ml=False)
    results = engine.scan_target(os.path.abspath(path))
    malicious = sum(1 for r in results if r.verdict == "malicious")
    suspicious = sum(1 for r in results if r.verdict == "suspicious")
    return f"scanned {len(results)} file(s): {malicious} malicious, {suspicious} suspicious"


def run(stdscr) -> None:
    import curses

    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)
    init_colors()
    try:
        curses.mousemask(curses.BUTTON1_CLICKED)
    except curses.error:
        pass

    dash = Dashboard(stdscr)
    last_refresh = time.time()

    while True:
        dash.draw()
        try:
            key = stdscr.getch()
        except curses_error():
            key = -1

        if key == ord("q"):
            return
        elif key == ord("s"):
            dash.run_action_async("scan", lambda: action_scan({}))
        elif key == ord("f"):
            from aegorx.cli import main as cli_main

            dash.run_action_async("feed update", lambda: f"feed update exit={cli_main(['feed', 'update'])}")
        elif key == ord("r"):
            dash.run_action_async("rules", lambda: f"active rule sets: {dash.snapshot.get('feed_rules', 0)}" )
        elif key == ord("p"):
            from aegorx import shield

            dash.run_action_async("protect check", lambda: "anchors intact" if shield.verify().get("ok") else "TAMPERED or unsealed")
        elif key == ord("w"):
            from aegorx.shield import liveness

            dash.run_action_async("watchdog", lambda: "healthy" if liveness().get("healthy") else "stale/down")

        if key == curses.KEY_MOUSE:
            try:
                _id, mx, my, _z, bstate = curses.getmouse()
                if bstate & curses.BUTTON1_CLICKED:
                    hit = dash.hit_test(my, mx)
                    if hit == "q":
                        return
            except curses.error:
                pass

        if time.time() - last_refresh > 10:
            dash._refresh_data()
            last_refresh = time.time()
        time.sleep(0.08)


def main() -> int:
    import curses

    rc = curses.wrapper(run)
    print("dashboard closed.")
    return 0 if rc is None else int(rc)


if __name__ == "__main__":
    raise SystemExit(main())
