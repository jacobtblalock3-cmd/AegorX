from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Dict, List, Optional

SEED_SIGNATURES = [
    {
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "md5": "44d88612fea8a8f36de82e1278abb02f",
        "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
        "name": "EICAR-Test-File",
        "family": "test",
        "severity": 8,
        "source": "builtin",
    }
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS hash_signatures (
    sha256 TEXT PRIMARY KEY,
    md5 TEXT,
    sha1 TEXT,
    name TEXT NOT NULL,
    family TEXT DEFAULT '',
    severity INTEGER NOT NULL DEFAULT 8,
    source TEXT DEFAULT 'user',
    added_at REAL
);
CREATE INDEX IF NOT EXISTS idx_sig_md5 ON hash_signatures(md5);
CREATE INDEX IF NOT EXISTS idx_sig_sha1 ON hash_signatures(sha1);
"""


class SignatureDB:
    def __init__(self, path: Optional[str] = None):
        if path is None:
            from defentra.utils import ensure_state_dir

            path = os.path.join(ensure_state_dir(), "signatures.db")
        fresh = not os.path.exists(path)
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        if fresh:
            self.seed()

    def seed(self) -> int:
        added = 0
        for sig in SEED_SIGNATURES:
            added += self.add(**sig)
        return added

    def add(
        self,
        sha256: str,
        name: str,
        md5: str = "",
        sha1: str = "",
        family: str = "",
        severity: int = 8,
        source: str = "user",
    ) -> int:
        with self._lock:
            cur = self.conn.execute(
                """
                INSERT OR IGNORE INTO hash_signatures
                (sha256, md5, sha1, name, family, severity, source, added_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sha256.lower().strip(),
                    md5.lower().strip(),
                    sha1.lower().strip(),
                    name.strip(),
                    family.strip(),
                    max(0, min(10, int(severity))),
                    source,
                    time.time(),
                ),
            )
            self.conn.commit()
            return cur.rowcount

    def lookup(self, sha256: str = "", md5: str = "", sha1: str = "") -> Optional[Dict]:
        with self._lock:
            row = None
            if sha256:
                row = self.conn.execute(
                    "SELECT * FROM hash_signatures WHERE sha256 = ?", (sha256,)
                ).fetchone()
            if row is None and md5:
                row = self.conn.execute(
                    "SELECT * FROM hash_signatures WHERE md5 = ?", (md5,)
                ).fetchone()
            if row is None and sha1:
                row = self.conn.execute(
                    "SELECT * FROM hash_signatures WHERE sha1 = ?", (sha1,)
                ).fetchone()
        return dict(row) if row else None

    def import_json(self, json_path: str, source: str = "import") -> int:
        with open(json_path, "r", encoding="utf-8") as fh:
            records = json.load(fh)
        if isinstance(records, dict):
            records = records.get("signatures", [])
        added = 0
        for rec in records:
            if not rec.get("sha256") or not rec.get("name"):
                continue
            added += self.add(
                sha256=rec["sha256"],
                name=rec["name"],
                md5=rec.get("md5", ""),
                sha1=rec.get("sha1", ""),
                family=rec.get("family", ""),
                severity=rec.get("severity", 8),
                source=source,
            )
        return added

    def export_json(self, json_path: str) -> int:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM hash_signatures").fetchall()
        payload = [dict(r) for r in rows]
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump({"signatures": payload}, fh, indent=2)
        return len(payload)

    def count(self) -> int:
        with self._lock:
            row = self.conn.execute("SELECT COUNT(*) AS n FROM hash_signatures").fetchone()
            return int(row["n"])

    def stats(self) -> Dict:
        with self._lock:
            rows = self.conn.execute(
                "SELECT source, COUNT(*) AS n FROM hash_signatures GROUP BY source"
            ).fetchall()
        return {"total": self.count(), "by_source": {r["source"]: r["n"] for r in rows}}

    def names(self) -> List[str]:
        with self._lock:
            rows = self.conn.execute("SELECT name FROM hash_signatures ORDER BY name").fetchall()
        return [r["name"] for r in rows]
