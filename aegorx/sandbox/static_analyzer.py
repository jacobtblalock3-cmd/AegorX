"""Static analysis sandbox — safely parses file formats without execution.

Extracts structural indicators, suspicious patterns, and metadata from
PE, ELF, Office, PDF, and script files in a memory-safe environment.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# File magic signatures
_MAGIC = {
    b"MZ": "pe",
    b"\x7fELF": "elf",
    b"%PDF": "pdf",
    b"PK": "zip",
    b"\xd0\xcf\x11\xe0": "ole2",  # MS Office OLE2
    b"Rar!": "rar",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\x1f\x8b": "gzip",
    b"BSHL": "bash",  # not real but detected by script heuristic
}

# Dangerous script patterns
_SCRIPT_PATTERNS = [
    (re.compile(r"eval\s*\(", re.I), "eval_call"),
    (re.compile(r"exec\s*\(", re.I), "exec_call"),
    (re.compile(r"__import__\s*\(", re.I), "dynamic_import"),
    (re.compile(r"subprocess\.(call|Popen|run)\s*\(", re.I), "subprocess_call"),
    (re.compile(r"os\.system\s*\(", re.I), "os_system"),
    (re.compile(r"base64\.(b64decode|decodebytes)\s*\(", re.I), "base64_decode"),
    (re.compile(r"compile\s*\(", re.I), "compile_call"),
    (re.compile(r"import\s+socket", re.I), "socket_import"),
    (re.compile(r"import\s+ctypes", re.I), "ctypes_import"),
    (re.compile(r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread", re.I), "winapi_inject"),
    (re.compile(r"SetWindowsHookEx|InjectA|InjectW", re.I), "hook_inject"),
]

# PDF dangerous actions
_PDF_ACTIONS = [
    re.compile(rb"/OpenAction", re.I),
    re.compile(rb"/AA\s", re.I),  # Additional Actions
    re.compile(rb"/JavaScript", re.I),
    re.compile(rb"/JS\s", re.I),
    re.compile(rb"/Launch", re.I),
    re.compile(rb"/SubmitForm", re.I),
    re.compile(rb"/ImportData", re.I),
]

# OLE2/VBA macro indicators
_VBA_INDICATORS = [
    b"VBA",
    b"ThisDocument",
    b"ThisWorkbook",
    b"AutoOpen",
    b"AutoExec",
    b"Document_Open",
    b"Workbook_Open",
    b"Macros",
    b"VBProject",
    b"Module1",
    b"Attribute VB_Name",
]


@dataclass
class AnalysisResult:
    file_type: str = "unknown"
    file_size: int = 0
    sha256: str = ""
    md5: str = ""
    entropy: float = 0.0

    # Structural info
    sections: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    suspicious_imports: List[Dict[str, str]] = field(default_factory=list)
    entry_point: Optional[int] = None
    is_packed: bool = False
    has_debug: bool = False
    has_signature: bool = False
    is_signed: bool = False

    # Indicators
    suspicious_patterns: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    yara_matches: List[str] = field(default_factory=list)

    # Metadata
    compiler_info: str = ""
    timestamps: Dict[str, float] = field(default_factory=dict)
    strings_of_interest: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_type": self.file_type,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "md5": self.md5,
            "entropy": self.entropy,
            "sections": self.sections,
            "imports": self.imports[:50],
            "suspicious_imports": self.suspicious_imports,
            "entry_point": self.entry_point,
            "is_packed": self.is_packed,
            "is_signed": self.is_signed,
            "suspicious_patterns": self.suspicious_patterns,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
        }


class StaticSandbox:
    """Safe static analysis of files without execution."""

    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
    MAX_STRING_SCAN = 10 * 1024 * 1024  # 10 MB for string scanning
    MAX_SECTIONS = 96
    MAX_IMPORTS = 2048

    def analyze(self, path: str) -> AnalysisResult:
        result = AnalysisResult()

        if not os.path.isfile(path):
            result.risk_factors.append("file_not_found")
            return result

        if os.path.isdir(path):
            result.risk_factors.append("path_is_directory")
            return result

        try:
            stat = os.stat(path)
            result.file_size = stat.st_size
            result.timestamps["modified"] = stat.st_mtime
            result.timestamps["created"] = stat.st_ctime
        except OSError as e:
            result.risk_factors.append(f"stat_failed: {e}")
            return result

        if result.file_size > self.MAX_FILE_SIZE:
            result.risk_factors.append("file_too_large")
            return result

        try:
            with open(path, "rb") as f:
                head = f.read(min(8192, result.file_size))
        except (OSError, PermissionError) as e:
            result.risk_factors.append(f"read_failed: {e}")
            return result

        # Compute hashes
        result.sha256 = hashlib.sha256(head).hexdigest()
        result.md5 = hashlib.md5(head).hexdigest()

        # Compute entropy
        result.entropy = self._entropy(head)

        # Detect file type
        result.file_type = self._detect_type(head)

        # Dispatch to format-specific analyzer
        if result.file_type == "pe":
            self._analyze_pe(path, head, result)
        elif result.file_type == "elf":
            self._analyze_elf(path, head, result)
        elif result.file_type == "pdf":
            self._analyze_pdf(path, head, result)
        elif result.file_type == "ole2":
            self._analyze_ole2(path, head, result)

        # Generic string scanning for scripts
        if result.file_type in ("unknown", "text"):
            self._analyze_scripts(path, head, result)

        # Compute risk score
        self._compute_risk(result)

        return result

    def _detect_type(self, head: bytes) -> str:
        for magic, ftype in _MAGIC.items():
            if head.startswith(magic):
                return ftype
        # Check for script shebangs
        if head.startswith(b"#!"):
            return "script"
        # Check if it's mostly printable text
        if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head[:256]):
            return "text"
        return "unknown"

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        ent = 0.0
        for count in freq:
            if count:
                p = count / length
                ent -= p * math.log2(p)
        return ent

    def _analyze_pe(self, path: str, head: bytes, result: AnalysisResult) -> None:
        try:
            # DOS header
            if len(head) < 64:
                result.risk_factors.append("pe_header_too_short")
                return

            pe_offset = struct.unpack_from("<I", head, 60)[0]
            if pe_offset + 4 >= len(head):
                result.risk_factors.append("pe_offset_invalid")
                return

            # PE signature
            if head[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                result.risk_factors.append("pe_signature_invalid")
                return

            # COFF header
            coff_offset = pe_offset + 4
            if coff_offset + 20 > len(head):
                return

            machine = struct.unpack_from("<H", head, coff_offset)[0]
            num_sections = struct.unpack_from("<H", head, coff_offset + 2)[0]
            timestamp = struct.unpack_from("<I", head, coff_offset + 4)[0]
            characteristics = struct.unpack_from("<H", head, coff_offset + 18)[0]

            result.timestamps["compile_time"] = float(timestamp)
            result.has_debug = bool(characteristics & 0x20)
            result.has_signature = bool(characteristics & 0x8)

            # Machine type
            machine_names = {
                0x14c: "i386", 0x8664: "AMD64", 0x1c0: "ARM",
                0xaa64: "ARM64", 0x1c4: "ARMNT",
            }
            machine_str = machine_names.get(machine, f"0x{machine:x}")

            # Optional header
            opt_offset = coff_offset + 20
            if opt_offset + 2 > len(head):
                return

            magic = struct.unpack_from("<H", head, opt_offset)[0]
            is_64 = magic == 0x20b

            if is_64 and opt_offset + 112 <= len(head):
                entry_rva = struct.unpack_from("<I", head, opt_offset + 16)[0]
                result.entry_point = entry_rva
            elif opt_offset + 96 <= len(head):
                entry_rva = struct.unpack_from("<I", head, opt_offset + 16)[0]
                result.entry_point = entry_rva

            # Section table
            section_offset = opt_offset + (240 if is_64 else 224)
            if section_offset + (40 * min(num_sections, self.MAX_SECTIONS)) <= len(head):
                for i in range(min(num_sections, self.MAX_SECTIONS)):
                    so = section_offset + i * 40
                    name = head[so:so + 8].rstrip(b"\x00").decode("ascii", errors="replace")
                    virtual_size = struct.unpack_from("<I", head, so + 8)[0]
                    raw_size = struct.unpack_from("<I", head, so + 16)[0]
                    chars = struct.unpack_from("<I", head, so + 36)[0]

                    section = {
                        "name": name,
                        "virtual_size": virtual_size,
                        "raw_size": raw_size,
                        "executable": bool(chars & 0x20000000),
                        "writable": bool(chars & 0x80000000),
                        "readable": bool(chars & 0x40000000),
                    }
                    result.sections.append(section)

                    # Detect packed sections (high entropy, executable, small raw size)
                    if (
                        section["executable"]
                        and raw_size > 0
                        and virtual_size > raw_size * 3
                    ):
                        result.is_packed = True

            # Suspicious characteristics
            if characteristics & 0x2:
                result.risk_factors.append("pei_executable")
            if not (characteristics & 0x20):
                result.risk_factors.append("no_relocs")

        except struct.error as e:
            result.risk_factors.append(f"pe_parse_error: {e}")

    def _analyze_elf(self, path: str, head: bytes, result: AnalysisResult) -> None:
        try:
            if len(head) < 16:
                return

            is_64 = head[4] == 2
            is_le = head[5] == 1

            fmt = "<" if is_le else ">"
            ei_class = head[4]
            ei_data = head[5]

            if ei_class == 1:  # 32-bit
                if len(head) < 52:
                    return
                e_type = struct.unpack_from(f"{fmt}H", head, 16)[0]
                e_machine = struct.unpack_from(f"{fmt}H", head, 18)[0]
                e_entry = struct.unpack_from(f"{fmt}I", head, 24)[0]
            elif ei_class == 2:  # 64-bit
                if len(head) < 64:
                    return
                e_type = struct.unpack_from(f"{fmt}H", head, 16)[0]
                e_machine = struct.unpack_from(f"{fmt}H", head, 18)[0]
                e_entry = struct.unpack_from(f"{fmt}Q", head, 24)[0]
            else:
                return

            result.entry_point = e_entry

            machine_names = {
                0x03: "i386", 0x3E: "x86-64", 0x28: "ARM",
                0xB7: "AArch64", 0x08: "MIPS",
            }
            machine_str = machine_names.get(e_machine, f"0x{e_machine:x}")

            # Type flags
            if e_type == 3:  # ET_DYN (shared object / PIE)
                result.risk_factors.append("pie_binary")
            if e_type == 2:  # ET_EXEC
                result.risk_factors.append("static_executable")

        except struct.error as e:
            result.risk_factors.append(f"elf_parse_error: {e}")

    def _analyze_pdf(self, path: str, head: bytes, result: AnalysisResult) -> None:
        try:
            with open(path, "rb") as f:
                content = f.read(self.MAX_STRING_SCAN)

            for action in _PDF_ACTIONS:
                matches = action.findall(content)
                if matches:
                    action_name = action.pattern.decode("ascii", errors="replace").lstrip("/").strip()
                    result.suspicious_patterns.append({
                        "type": "pdf_action",
                        "pattern": action_name,
                        "count": len(matches),
                    })

            # Check for encrypted PDFs
            if b"/Encrypt" in content:
                result.risk_factors.append("pdf_encrypted")
            if b"/URI" in content:
                result.risk_factors.append("pdf_has_uri")

        except (OSError, PermissionError):
            pass

    def _analyze_ole2(self, path: str, head: bytes, result: AnalysisResult) -> None:
        """Analyze OLE2 (MS Office) documents for macro indicators."""
        try:
            with open(path, "rb") as f:
                content = f.read(self.MAX_STRING_SCAN)

            for indicator in _VBA_INDICATORS:
                if indicator in content:
                    result.suspicious_patterns.append({
                        "type": "vba_indicator",
                        "pattern": indicator.decode("ascii", errors="replace"),
                    })

            # Check for auto-execution macros
            auto_exec = [
                b"AutoOpen", b"AutoExec", b"Document_Open",
                b"Workbook_Open", b"Auto_Close", b"AutoExit",
            ]
            for pattern in auto_exec:
                if pattern in content:
                    result.suspicious_patterns.append({
                        "type": "auto_exec_macro",
                        "pattern": pattern.decode("ascii", errors="replace"),
                    })
                    result.risk_factors.append("auto_exec_macro")

        except (OSError, PermissionError):
            pass

    def _analyze_scripts(self, path: str, head: bytes, result: AnalysisResult) -> None:
        """Analyze script files for suspicious patterns."""
        try:
            with open(path, "rb") as f:
                content = f.read(self.MAX_STRING_SCAN)

            text = content.decode("utf-8", errors="replace")

            for pattern, desc in _SCRIPT_PATTERNS:
                matches = pattern.findall(text)
                if matches:
                    result.suspicious_patterns.append({
                        "type": "script_pattern",
                        "pattern": desc,
                        "count": len(matches),
                    })

            # Check for obfuscation indicators
            if len(re.findall(r"\\x[0-9a-fA-F]{2}", text)) > 20:
                result.risk_factors.append("hex_obfuscation")
            if text.count("\\u00") > 20:
                result.risk_factors.append("unicode_obfuscation")

        except (OSError, PermissionError):
            pass

    def _compute_risk(self, result: AnalysisResult) -> None:
        score = 0.0
        factors = []

        # Entropy-based scoring (packed/encrypted)
        if result.entropy > 7.5:
            score += 0.2
            factors.append("high_entropy")
        elif result.entropy > 7.0:
            score += 0.1
            factors.append("moderate_entropy")

        # Packed binary
        if result.is_packed:
            score += 0.25
            factors.append("packed_binary")

        # Suspicious imports
        if len(result.suspicious_imports) > 5:
            score += 0.2
            factors.append(f"many_suspicious_imports({len(result.suspicious_imports)})")
        elif result.suspicious_imports:
            score += 0.1
            factors.append("some_suspicious_imports")

        # Suspicious patterns
        if len(result.suspicious_patterns) > 3:
            score += 0.25
            factors.append(f"many_suspicious_patterns({len(result.suspicious_patterns)})")
        elif result.suspicious_patterns:
            score += 0.1
            factors.append("some_suspicious_patterns")

        # Unsigned executable
        if result.file_type in ("pe", "elf") and not result.is_signed:
            score += 0.05
            factors.append("unsigned")

        # Risk factors from format analysis
        risk_factor_count = len(result.risk_factors)
        if risk_factor_count > 3:
            score += 0.15
        elif risk_factor_count > 0:
            score += 0.05

        result.risk_score = min(1.0, score)
        result.risk_factors.extend(factors)
