"""ML-based static detection pipeline."""

from defentra.ml.classifier import MalwareClassifier
from defentra.ml.features import FEATURE_NAMES, FEATURE_VERSION, extract_features, vectorize

__all__ = ["FEATURE_NAMES", "FEATURE_VERSION", "MalwareClassifier", "extract_features", "vectorize"]
