"""Unified static-feature schema shared by training and inference."""

from __future__ import annotations

import os
from typing import Dict, List

from defentra.ml.elf_features import NotElfError, parse_elf
from defentra.ml.pe_features import (
    NotPEError,
    parse_pe,
    section_entropies,
    suspicious_import_hits,
)
from defentra.utils import read_capped, shannon_entropy

MAX_ANALYZE_BYTES = 64 * 1024 * 1024

FEATURE_NAMES: List[str] = [
    "file_size",
    "entropy_mean",
    "entropy_max",
    "is_pe",
    "pe_machine",
    "pe_num_sections",
    "pe_timestamp",
    "pe_characteristics",
    "pe_subsystem",
    "pe_dll_characteristics",
    "pe_size_of_image",
    "pe_entry_rva",
    "pe_num_data_dirs",
    "pe_has_imports",
    "pe_has_resources",
    "pe_has_tls",
    "pe_has_debug",
    "pe_has_signature",
    "pe_has_dotnet",
    "pe_overlay_size",
    "pe_suspicious_import_hits",
    "pe_total_import_functions",
    "pe_num_import_dlls",
    "pe_writable_exec_sections",
    "pe_section_entropy_max",
    "pe_section_entropy_mean",
    "is_elf",
    "elf_class",
    "elf_type",
    "elf_machine",
    "elf_pie",
    "elf_nx_stack",
    "elf_num_sections",
    "elf_dynsym_count",
    "elf_progbits_entropy_max",
]

FEATURE_VERSION = 1


def _sampled_entropies(path: str, size: int) -> List[float]:
    windows = []
    with open(path, "rb") as fh:
        positions = [0] if size < 8192 else [0, size // 4, size // 2, (3 * size) // 4]
        for pos in positions:
            fh.seek(pos)
            blob = fh.read(65536)
            if blob:
                windows.append(shannon_entropy(blob))
    return windows


def extract_features(path: str) -> Dict[str, float]:
    size = os.path.getsize(path)
    feats: Dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
    feats["file_size"] = min(float(size), 2**31)

    entropies = _sampled_entropies(path, size)
    feats["entropy_mean"] = sum(entropies) / len(entropies) if entropies else 0.0
    feats["entropy_max"] = max(entropies) if entropies else 0.0

    data = read_capped(path, MAX_ANALYZE_BYTES)
    if data[:2] == b"MZ":
        try:
            pe = parse_pe(data)
        except NotPEError:
            return feats
        for key in ("machine", "num_sections", "timestamp", "characteristics", "subsystem"):
            feats[f"pe_{key}"] = float(pe[key])
        feats["pe_dll_characteristics"] = float(pe["dll_characteristics"])
        feats["pe_size_of_image"] = float(pe["size_of_image"])
        feats["pe_entry_rva"] = float(pe["entry_rva"])
        feats["pe_num_data_dirs"] = float(pe["num_data_dirs"])
        for flag in ("imports", "resources", "tls", "debug", "signature", "dotnet"):
            feats[f"pe_has_{flag}"] = 1.0 if pe[f"has_{flag}"] else 0.0
        feats["pe_overlay_size"] = float(pe["overlay_size"])
        feats["pe_suspicious_import_hits"] = float(
            suspicious_import_hits(pe.get("import_functions", []))
        )
        feats["pe_total_import_functions"] = float(pe.get("total_import_functions", 0))
        feats["pe_num_import_dlls"] = float(len(pe.get("import_dlls", [])))
        wx = sum(
            1
            for s in pe["sections"]
            if s["characteristics"] & 0x20000000 and s["characteristics"] & 0x80000000
        )
        feats["pe_writable_exec_sections"] = float(wx)
        ents = section_entropies(data, pe["sections"])
        if ents:
            feats["pe_section_entropy_max"] = max(ents)
            feats["pe_section_entropy_mean"] = sum(ents) / len(ents)
        feats["is_pe"] = 1.0
    elif data[:4] == b"\x7fELF":
        try:
            elf = parse_elf(data)
        except NotElfError:
            return feats
        feats["is_elf"] = 1.0
        feats["elf_class"] = float(elf["class"])
        feats["elf_type"] = float(elf["type"])
        feats["elf_machine"] = float(elf["machine"])
        feats["elf_pie"] = 1.0 if elf["pie"] else 0.0
        feats["elf_nx_stack"] = 1.0 if elf["nx_stack"] else 0.0
        feats["elf_num_sections"] = float(elf["num_sections"])
        feats["elf_dynsym_count"] = float(min(elf["dynsym_count"], 100000))
        ents = []
        from defentra.utils import shannon_entropy as _se

        for off, span in elf["progbits_spans"][:64]:
            blob = data[off : off + min(span, 1024 * 1024)]
            if blob:
                ents.append(_se(blob))
        if ents:
            feats["elf_progbits_entropy_max"] = max(ents)
    return feats


def vectorize(feats: Dict[str, float]) -> List[float]:
    return [float(feats.get(name, 0.0)) for name in FEATURE_NAMES]


def looks_executable(head: bytes) -> bool:
    return head[:2] == b"MZ" or head[:4] == b"\x7fELF"
