"""Defentra - open-source AI-assisted antivirus engine."""

__version__ = "0.3.0"

from defentra.engine import Detection, FileScanResult, ScanEngine

__all__ = ["Detection", "FileScanResult", "ScanEngine", "__version__"]
