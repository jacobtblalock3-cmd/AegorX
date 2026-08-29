"""Malware-probability classifier wrapper around LightGBM."""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
from typing import Dict, Optional

from aegorx.ml.features import FEATURE_NAMES, FEATURE_VERSION

logger = logging.getLogger(__name__)

MODEL_FILENAME_GLOB = "*.lgbm"
META_SUFFIX = ".meta.json"


class MalwareClassifier:
    """Loads a trained LightGBM booster and maps feature vectors to a malware probability.

    Models are searched in $AEGORX_MODEL, then $AEGORX_MODEL_DIR,
    then ~/.aegorx/models/, then the bundled models dir. A sibling
    `<model>.meta.json` (provenance, checksum, metrics) is loaded when present.
    """

    def __init__(self, model_path: Optional[str] = None):
        self._booster = None
        self._model_path = None
        self.metadata: Dict = {}
        self._load(model_path)

    @property
    def available(self) -> bool:
        return self._booster is not None

    @property
    def model_path(self) -> Optional[str]:
        return self._model_path

    def _candidate_paths(self):
        env_path = os.environ.get("AEGORX_MODEL")
        if env_path:
            yield env_path
        from aegorx.utils import state_dir

        search_dirs = []
        env_dir = os.environ.get("AEGORX_MODEL_DIR")
        if env_dir:
            search_dirs.append(env_dir)
        search_dirs.extend(
            [
                os.path.join(state_dir(), "models"),
                os.path.join(os.path.expanduser("~"), ".aegorx", "models"),
                os.path.join(os.path.dirname(__file__), "models"),
            ]
        )
        for d in search_dirs:
            if not os.path.isdir(d):
                continue
            preferred = sorted(glob.glob(os.path.join(d, MODEL_FILENAME_GLOB)))
            for p in preferred:
                yield p

    def _load(self, model_path: Optional[str]) -> None:
        try:
            import lightgbm as lgb
        except ImportError:
            import logging
            logging.debug("lightgbm not installed; ML detection disabled")
            return
        candidates = [model_path] if model_path else self._candidate_paths()
        for path in candidates:
            if path and os.path.isfile(path):
                try:
                    self._verify_integrity(path)
                    self._booster = lgb.Booster(model_file=path)
                    n_feat = self._booster.num_feature()
                    if n_feat != len(FEATURE_NAMES):
                        self._booster = None
                        continue
                    self._model_path = path
                    self.metadata = {}
                    self._load_meta(path)
                    return
                except Exception:
                    self._booster = None
                    continue

    @staticmethod
    def _verify_integrity(path: str) -> None:
        """Refuse models whose sibling metadata records a different sha256."""
        meta_path = path + META_SUFFIX
        if not os.path.exists(meta_path):
            return
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        expected = meta.get("model_sha256") if isinstance(meta, dict) else None
        if not expected:
            return
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        if h.hexdigest() != expected:
            raise ValueError("model file does not match its published checksum")

    def _load_meta(self, model_path: str) -> None:
        meta_path = model_path + META_SUFFIX
        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
            if isinstance(meta, dict):
                self.metadata = meta
        except (OSError, json.JSONDecodeError):
            pass

    def predict_proba(self, vector) -> Optional[float]:
        if self._booster is None:
            return None
        try:
            score = self._booster.predict([list(vector)])[0]
            return max(0.0, min(1.0, float(score)))
        except Exception:
            return None

    def info(self) -> Dict:
        return {
            "available": self.available,
            "model_path": self._model_path,
            "feature_version": FEATURE_VERSION,
            "num_features": len(FEATURE_NAMES),
            "metadata": self.metadata,
        }
