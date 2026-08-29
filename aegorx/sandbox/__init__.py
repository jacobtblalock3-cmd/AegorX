"""Sandboxing engine for zero-day detection.

Provides safe file analysis environments:
- Static analysis sandbox for parsing file formats without execution
- Behavioral sandbox for controlled execution monitoring
- Archive sandbox for safe extraction with bomb detection
"""

from .static_analyzer import StaticSandbox, AnalysisResult
from .behavioral_sandbox import BehavioralSandbox, SandboxConfig, SandboxResult
from .archive_sandbox import ArchiveSandbox, ExtractionResult

__all__ = [
    "StaticSandbox",
    "AnalysisResult",
    "BehavioralSandbox",
    "SandboxConfig",
    "SandboxResult",
    "ArchiveSandbox",
    "ExtractionResult",
]
