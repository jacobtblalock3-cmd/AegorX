"""Map EMBER 2018 JSONL records onto Defentra's runtime feature schema.

EMBER's raw per-file records carry everything the runtime PE parser extracts
(headers, sections, imports, data directories, overlay), so a model trained on
mapped records consumes exactly the same feature vector the engine computes at
scan time. Fields EMBER does not preserve (section RWX flags, whole-file
sampled entropy) are approximated and documented here.
"""

from __future__ import annotations

from typing import Dict, List

from defentra.ml.features import FEATURE_NAMES
from defentra.ml.pe_features import SUSPICIOUS_IMPORTS

CHARACTERISTIC_BITS = {
    "RELOCS_STRIPPED": 0x0001,
    "EXECUTABLE_IMAGE": 0x0002,
    "LINE_NUMS_STRIPPED": 0x0004,
    "LOCAL_SYMS_STRIPPED": 0x0008,
    "AGGRESIVE_WS_TRIM": 0x0010,
    "LARGE_ADDRESS_AWARE": 0x0020,
    "BYTES_REVERSED_LO": 0x0080,
    "32BIT_MACHINE": 0x0100,
    "DEBUG_STRIPPED": 0x0200,
    "REMOVABLE_RUN_FROM_SWAP": 0x0400,
    "NET_RUN_FROM_SWAP": 0x0800,
    "SYSTEM": 0x1000,
    "DLL": 0x2000,
    "UP_SYSTEM_ONLY": 0x4000,
    "BYTES_REVERSED_HI": 0x8000,
}

DLL_CHARACTERISTIC_BITS = {
    "HIGH_ENTROPY_VA": 0x20,
    "DYNAMIC_BASE": 0x40,
    "FORCE_INTEGRITY": 0x80,
    "NX_COMPAT": 0x100,
    "NO_ISOLATION": 0x200,
    "NO_SEH": 0x400,
    "NO_BIND": 0x800,
    "APPCONTAINER": 0x1000,
    "WDM_DRIVER": 0x2000,
    "GUARD_CF": 0x4000,
    "TERMINAL_SERVER_AWARE": 0x8000,
}

DATA_DIR_ALIASES = {
    "imports": ("IMAGE_DIRECTORY_ENTRY_IMPORT", "import_array"),
    "resources": ("IMAGE_DIRECTORY_ENTRY_RESOURCE", "resource_array"),
    "tls": ("IMAGE_DIRECTORY_ENTRY_TLS", "tls_array"),
    "debug": ("IMAGE_DIRECTORY_ENTRY_DEBUG", "debug_array"),
    "signature": ("IMAGE_DIRECTORY_ENTRY_SECURITY", "certificate_array"),
    "dotnet": ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", "clr_runtime_header_array"),
}

MAX_DLLS = 64
MAX_FUNCS_PER_DLL = 1024
MAX_SECTIONS = 96


def _as_int(value) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return 0
    return 0


def _flags_to_bits(names, table: Dict[str, int]) -> int:
    bits = 0
    for name in names or []:
        bits += table.get(str(name).upper(), 0)
    return bits


def _dir_flag(data_dirs: Dict, *keys: str) -> bool:
    for key in keys:
        entry = data_dirs.get(key)
        if isinstance(entry, dict):
            va = _as_int(entry.get("virtual_address", entry.get("value", 0)))
            if va != 0:
                return True
        elif entry:
            return True
    return False


def _is_suspicious(func_name: str) -> bool:
    name = func_name.lower()
    if name in SUSPICIOUS_IMPORTS:
        return True
    if len(name) > 1 and name[-1] in "AW" and name[:-1] in SUSPICIOUS_IMPORTS:
        return True
    return False


def _import_stats(imports: Dict):
    hits = 0
    total = 0
    dll_count = 0
    for _dll, funcs in list(imports.items())[:MAX_DLLS]:
        dll_count += 1
        total += min(len(funcs), MAX_FUNCS_PER_DLL)
        for func in list(funcs)[:MAX_FUNCS_PER_DLL]:
            if _is_suspicious(str(func)):
                hits += 1
    return hits, total, dll_count


def ember_record_to_features(record: Dict) -> Dict[str, float]:
    feats: Dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
    general = record.get("general") or {}
    header = record.get("header") or {}
    coff = header.get("coff") or {}
    optional = header.get("optional") or {}
    sections = (record.get("section") or [])[:MAX_SECTIONS]
    data_dirs = record.get("data_directories") or {}
    overlay = record.get("overlay") or {}

    feats["file_size"] = float(min(_as_int(general.get("size")), 2**31))
    feats["is_pe"] = 1.0
    feats["pe_machine"] = float(_as_int(coff.get("machine")))
    feats["pe_num_sections"] = float(len(sections))
    feats["pe_timestamp"] = float(_as_int(coff.get("timestamp")))
    feats["pe_characteristics"] = float(
        _flags_to_bits(coff.get("characteristics"), CHARACTERISTIC_BITS)
    )
    feats["pe_subsystem"] = float(_as_int(optional.get("subsystem")))
    feats["pe_dll_characteristics"] = float(
        _flags_to_bits(optional.get("dll_characteristics"), DLL_CHARACTERISTIC_BITS)
    )
    feats["pe_size_of_image"] = float(_as_int(optional.get("size_of_image")))
    feats["pe_entry_rva"] = float(_as_int(optional.get("address_of_entry_point")))
    feats["pe_num_data_dirs"] = float(len(data_dirs))

    for flag, aliases in DATA_DIR_ALIASES.items():
        if _dir_flag(data_dirs, *aliases):
            feats[f"pe_has_{flag}"] = 1.0

    feats["pe_overlay_size"] = float(min(_as_int(overlay.get("size")), 2**31))

    entropies: List[float] = []
    weights: List[float] = []
    for sec in sections:
        entropies.append(float(sec.get("entropy", 0) or 0))
        weights.append(float(sec.get("size", 0) or 0))
    if entropies:
        total_w = sum(weights)
        if total_w > 0:
            weighted = sum(e * w for e, w in zip(entropies, weights)) / total_w
        else:
            weighted = sum(entropies) / len(entropies)
        feats["entropy_max"] = max(entropies)
        feats["entropy_mean"] = weighted
        feats["pe_section_entropy_max"] = max(entropies)
        feats["pe_section_entropy_mean"] = sum(entropies) / len(entropies)

    hits, total_funcs, dlls = _import_stats(record.get("imports") or {})
    feats["pe_suspicious_import_hits"] = float(hits)
    feats["pe_total_import_functions"] = float(total_funcs)
    feats["pe_num_import_dlls"] = float(dlls)
    return feats


def parse_label(label) -> int | None:
    """EMBER labels: -1 unlabeled, 0 benign, 1 malicious."""
    try:
        lab = int(label)
    except (TypeError, ValueError):
        return None
    if lab in (0, 1):
        return lab
    return None
