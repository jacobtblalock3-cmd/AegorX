from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from typing import Dict, List, Optional

# Windows lacks O_NOFOLLOW; symlink-following is a POSIX-only hazard here.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

CHUNK_SIZE = 1024 * 1024
BLOB_MAGIC = b"DFQ1"
BLOB_NAME_RE = re.compile(r"^[0-9a-f]{16}\.quar$")
LEGACY_MAX_PLAIN = 1024 * 1024 * 1024


class QuarantineVault:
    """Moves threats into a vault directory, encrypted at rest with Fernet.

    Security properties:
      * blobs are written 0600 into a 0700 state directory
      * the Fernet key lives OUTSIDE the blob directory (compromise of one
        must not imply the other)
      * index mutations are serialized and written atomically (tmp+rename)
      * blob names are strictly validated before any open/unlink so a forged
        or corrupted index cannot traverse paths (../, absolute, symlinks)
      * large files are encrypted in chunks to bound memory use
    """

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            from aegorx.utils import ensure_state_dir, state_dir

            base_dir = os.path.join(ensure_state_dir(), "quarantine")
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.base_dir, 0o700)
        except OSError:
            pass
        self._cipher = self._load_cipher()
        self.index_path = os.path.join(self.base_dir, "index.json")
        self._lock = threading.RLock()

    @property
    def encryption(self) -> str:
        return "fernet" if self._cipher else "none"

    def _key_path(self) -> str:
        from aegorx.utils import state_dir

        return os.path.join(state_dir(), "vault.key")

    def _load_cipher(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            return None
        key_path = self._key_path()
        legacy_path = os.path.join(self.base_dir, "vault.key")
        if not os.path.exists(key_path) and os.path.exists(legacy_path):
            try:
                os.replace(legacy_path, key_path)
                os.chmod(key_path, 0o600)
            except OSError:
                key_path = legacy_path
        if os.path.exists(key_path):
            try:
                with open(key_path, "rb") as fh:
                    key = fh.read().strip()
            except OSError:
                return None
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
        try:
            with open(self.index_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []
        return data if isinstance(data, list) else []

    def _write_index(self, items: List[Dict]) -> None:
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.index_path)

    def _blob_path_checked(self, item: Dict) -> str:
        name = str(item.get("blob", ""))
        if not BLOB_NAME_RE.match(name):
            raise ValueError(f"refusing unsafe quarantine blob name: {name!r}")
        path = os.path.join(self.base_dir, name)
        if os.path.dirname(path) != self.base_dir:
            raise ValueError("quarantine blob path escaped vault")
        return path

    def quarantine(self, path: str, reason: str = "") -> Dict:
        path = os.path.abspath(path)
        # Open by fd first to prevent TOCTOU race (lstat then open)
        try:
            src_fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
        except OSError:
            raise FileNotFoundError(path)
        try:
            import stat as _stat
            st = os.fstat(src_fd)
            if not _stat.S_ISREG(st.st_mode):
                raise FileNotFoundError(path)
            size_limit = LEGACY_MAX_PLAIN
            if st.st_size > size_limit:
                raise OSError(f"file too large to quarantine ({st.st_size} bytes)")
            with self._lock:
                item_id = uuid.uuid4().hex[:16]
                blob_name = f"{item_id}.quar"
                blob_path = os.path.join(self.base_dir, blob_name)
                chunked = False
                fd = os.open(blob_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as out:
                    with os.fdopen(src_fd, "rb") as src:
                        if self._cipher is not None:
                            out.write(BLOB_MAGIC)
                            chunked = True
                            while True:
                                chunk = src.read(CHUNK_SIZE)
                                if not chunk:
                                    break
                                token = self._cipher.encrypt(chunk)
                                out.write(len(token).to_bytes(4, "big"))
                                out.write(token)
                        else:
                            while True:
                                chunk = src.read(CHUNK_SIZE)
                                if not chunk:
                                    break
                                out.write(chunk)
                entry = {
                    "id": item_id,
                    "original_path": path,
                    "blob": blob_name,
                    "reason": reason,
                    "size": st.st_size,
                    "encrypted": self._cipher is not None,
                    "chunked": chunked,
                    "quarantined_at": time.time(),
                }
                items = self._read_index()
                items.append(entry)
                self._write_index(items)
                try:
                    os.remove(path)
                except OSError as exc:
                    # Log but don't fail - the file is safely quarantined
                    # but we should warn that the original wasn't removed
                    import logging
                    logging.warning("quarantine: failed to remove original %s: %s", path, exc)
                return entry
        except Exception:
            # Ensure src_fd is closed on any error
            try:
                os.close(src_fd)
            except OSError:
                pass
            raise

    def list_items(self) -> List[Dict]:
        with self._lock:
            return self._read_index()

    def get(self, item_id: str) -> Optional[Dict]:
        with self._lock:
            for item in self._read_index():
                if item.get("id") == item_id:
                    return item
        return None

    def restore(self, item_id: str, destination: Optional[str] = None) -> str:
        with self._lock:
            item = self.get(item_id)
            if item is None:
                raise KeyError(f"unknown quarantine id: {item_id}")
            dest = destination or item["original_path"]
            dest = os.path.abspath(dest)
            parent = os.path.dirname(dest)
            if parent:
                os.makedirs(parent, exist_ok=True)
            blob_path = self._blob_path_checked(item)
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out:
                with open(blob_path, "rb") as fh:
                    header = fh.read(4)
                    fh.seek(0)
                    if item.get("chunked"):
                        if header != BLOB_MAGIC:
                            raise ValueError("corrupt quarantine blob header")
                        fh.read(4)
                        while True:
                            len_bytes = fh.read(4)
                            if not len_bytes:
                                break
                            token_len = int.from_bytes(len_bytes, "big")
                            token = fh.read(token_len)
                            if len(token) != token_len:
                                raise ValueError("truncated quarantine blob")
                            data = self._decrypt_token(token) if item.get("encrypted") else token
                            out.write(data)
                    else:
                        data = fh.read()
                        if item.get("encrypted") and self._cipher is not None:
                            data = self._decrypt_token(data)
                        out.write(data)
            self.delete(item_id)
            return dest

    def _decrypt_token(self, token: bytes) -> bytes:
        if self._cipher is None:
            raise RuntimeError("blob is encrypted but no key is available")
        from cryptography.exceptions import InvalidTag
        from cryptography.fernet import InvalidToken

        try:
            return self._cipher.decrypt(token)
        except (InvalidToken, InvalidTag):
            raise ValueError("quarantine blob failed authentication (wrong key or corruption)")

    def delete(self, item_id: str) -> bool:
        with self._lock:
            items = self._read_index()
            remaining = [i for i in items if i.get("id") != item_id]
            if len(remaining) == len(items):
                return False
            removed = [i for i in items if i.get("id") == item_id][0]
            blob_path = self._blob_path_checked(removed)
            if os.path.exists(blob_path):
                try:
                    os.remove(blob_path)
                except OSError as exc:
                    import logging
                    logging.warning("vault: failed to remove blob %s: %s", blob_path, exc)
            self._write_index(remaining)
            return True

    def purge_missing_blobs(self) -> int:
        with self._lock:
            items = self._read_index()
            valid = []
            purged = 0
            for item in items:
                try:
                    path = self._blob_path_checked(item)
                    ok = os.path.exists(path)
                except ValueError:
                    ok = False
                if ok:
                    valid.append(item)
                else:
                    purged += 1
            if purged:
                self._write_index(valid)
            return purged


__all__ = ["QuarantineVault"]
