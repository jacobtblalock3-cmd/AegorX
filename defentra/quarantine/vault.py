from __future__ import annotations

import json
import os
import time
import uuid
from typing import Dict, List, Optional


class QuarantineVault:
    """Moves threats into a vault directory, optionally encrypted with Fernet."""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            from defentra.utils import state_dir

            base_dir = os.path.join(state_dir(), "quarantine")
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)
        self._cipher = self._load_cipher()
        self.index_path = os.path.join(self.base_dir, "index.json")

    @property
    def encryption(self) -> str:
        return "fernet" if self._cipher else "none"

    def _load_cipher(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            return None
        key_path = os.path.join(self.base_dir, "vault.key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as fh:
                key = fh.read().strip()
        else:
            key = Fernet.generate_key()
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key + b"\n")
        try:
            return Fernet(key)
        except Exception:
            return None

    def _read_index(self) -> List[Dict]:
        if not os.path.exists(self.index_path):
            return []
        with open(self.index_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write_index(self, items: List[Dict]) -> None:
        with open(self.index_path, "w", encoding="utf-8") as fh:
            json.dump(items, fh, indent=2)

    def quarantine(self, path: str, reason: str = "") -> Dict:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        item_id = uuid.uuid4().hex[:16]
        blob_name = f"{item_id}.quar"
        blob_path = os.path.join(self.base_dir, blob_name)
        with open(path, "rb") as fh:
            data = fh.read()
        if self._cipher is not None:
            data = self._cipher.encrypt(data)
        with open(blob_path, "wb") as fh:
            fh.write(data)
        os.chmod(blob_path, 0o600)
        entry = {
            "id": item_id,
            "original_path": path,
            "blob": blob_name,
            "reason": reason,
            "size": len(data),
            "encrypted": self._cipher is not None,
            "quarantined_at": time.time(),
        }
        items = self._read_index()
        items.append(entry)
        self._write_index(items)
        os.remove(path)
        return entry

    def list_items(self) -> List[Dict]:
        return self._read_index()

    def get(self, item_id: str) -> Optional[Dict]:
        for item in self._read_index():
            if item["id"] == item_id:
                return item
        return None

    def restore(self, item_id: str, destination: Optional[str] = None) -> str:
        item = self.get(item_id)
        if item is None:
            raise KeyError(f"unknown quarantine id: {item_id}")
        dest = destination or item["original_path"]
        dest = os.path.abspath(dest)
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        blob_path = os.path.join(self.base_dir, item["blob"])
        with open(blob_path, "rb") as fh:
            data = fh.read()
        if item.get("encrypted") and self._cipher is not None:
            data = self._cipher.decrypt(data)
        with open(dest, "wb") as fh:
            fh.write(data)
        self.delete(item_id)
        return dest

    def delete(self, item_id: str) -> bool:
        items = self._read_index()
        remaining = [i for i in items if i["id"] != item_id]
        if len(remaining) == len(items):
            return False
        removed = [i for i in items if i["id"] == item_id][0]
        blob_path = os.path.join(self.base_dir, removed["blob"])
        if os.path.exists(blob_path):
            os.remove(blob_path)
        self._write_index(remaining)
        return True

    def purge_missing_blobs(self) -> int:
        items = self._read_index()
        valid = [i for i in items if os.path.exists(os.path.join(self.base_dir, i["blob"]))]
        purged = len(items) - len(valid)
        if purged:
            self._write_index(valid)
        return purged


__all__ = ["QuarantineVault"]
