import pytest

from aegorx.ml.ember_map import (
    CHARACTERISTIC_BITS,
    DLL_CHARACTERISTIC_BITS,
    _as_int,
    _is_suspicious,
    ember_record_to_features,
    parse_label,
)
from aegorx.ml.features import FEATURE_NAMES, vectorize


def sample_ember_record() -> dict:
    return {
        "sha256": "a" * 64,
        "label": 1,
        "general": {"size": 409600, "vhash": "x", "has_debug": 0},
        "header": {
            "coff": {
                "timestamp": 1377091234,
                "machine": 0x14C,
                "characteristics": ["EXECUTABLE_IMAGE", "32BIT_MACHINE", "DLL"],
            },
            "optional": {
                "magic": 0x10B,
                "subsystem": 2,
                "dll_characteristics": ["DYNAMIC_BASE", "NX_COMPAT"],
                "address_of_entry_point": 0x14C0,
                "size_of_image": 458752,
            },
        },
        "section": [
            {"name": ".text", "size": 20480, "entropy": 6.5, "virtual_size": 20480, "virtual_address": 0x1000},
            {"name": ".rsrc", "size": 1024, "entropy": 4.0, "virtual_size": 1024, "virtual_address": 0x8000},
        ],
        "imports": {
            "kernel32.dll": ["CreateFileW", "WriteProcessMemory", "VirtualAlloc"],
            "urlmon.dll": ["URLDownloadToFileW"],
        },
        "exports": [],
        "data_directories": {
            "IMAGE_DIRECTORY_ENTRY_IMPORT": {"virtual_address": 0x2000, "size": 40},
            "IMAGE_DIRECTORY_ENTRY_RESOURCE": {"virtual_address": 0x8000, "size": 1024},
            "IMAGE_DIRECTORY_ENTRY_TLS": {"virtual_address": 0, "size": 0},
            "IMAGE_DIRECTORY_ENTRY_DEBUG": {"virtual_address": 0, "size": 0},
            "IMAGE_DIRECTORY_ENTRY_SECURITY": {"virtual_address": 0x9100, "size": 512},
            "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR": {"virtual_address": 0, "size": 0},
        },
        "overlay": {"offset": 100000, "size": 309600},
    }


def test_machine_and_header_fields_mapped():
    feats = ember_record_to_features(sample_ember_record())
    assert feats["is_pe"] == 1.0
    assert feats["pe_machine"] == 0x14C
    assert feats["pe_num_sections"] == 2
    assert feats["pe_timestamp"] == 1377091234
    assert feats["pe_subsystem"] == 2
    assert feats["pe_entry_rva"] == 0x14C0
    assert feats["pe_size_of_image"] == 458752


def test_characteristic_bitmasks():
    rec = sample_ember_record()
    feats = ember_record_to_features(rec)
    expected = sum(CHARACTERISTIC_BITS[n] for n in ["EXECUTABLE_IMAGE", "32BIT_MACHINE", "DLL"])
    assert feats["pe_characteristics"] == float(expected)
    expected_dll = sum(DLL_CHARACTERISTIC_BITS[n] for n in ["DYNAMIC_BASE", "NX_COMPAT"])
    assert feats["pe_dll_characteristics"] == float(expected_dll)


def test_data_directory_flags():
    feats = ember_record_to_features(sample_ember_record())
    assert feats["pe_has_imports"] == 1.0
    assert feats["pe_has_resources"] == 1.0
    assert feats["pe_has_signature"] == 1.0
    assert feats["pe_has_tls"] == 0.0
    assert feats["pe_has_debug"] == 0.0
    assert feats["pe_has_dotnet"] == 0.0
    assert feats["pe_num_data_dirs"] == 6


def test_import_stats_and_suspicious_hits():
    feats = ember_record_to_features(sample_ember_record())
    assert feats["pe_num_import_dlls"] == 2
    assert feats["pe_total_import_functions"] == 4
    hits = feats["pe_suspicious_import_hits"]
    assert hits >= 2
    assert _is_suspicious("WriteProcessMemory")
    assert _is_suspicious("urldownloadtofilew")
    assert not _is_suspicious("CreateFileW")
    assert not _is_suspicious("")


def test_entropy_weighting_and_overlay():
    feats = ember_record_to_features(sample_ember_record())
    assert feats["entropy_max"] == 6.5
    expected_mean = (6.5 * 20480 + 4.0 * 1024) / (20480 + 1024)
    assert abs(feats["entropy_mean"] - expected_mean) < 1e-9
    assert feats["pe_section_entropy_max"] == 6.5
    assert feats["pe_overlay_size"] == 309600
    assert feats["file_size"] == 409600


def test_vectorize_shape_matches_runtime_schema():
    v = vectorize(ember_record_to_features(sample_ember_record()))
    assert len(v) == len(FEATURE_NAMES)
    assert all(isinstance(x, float) for x in v)


def test_as_int_hex_strings():
    assert _as_int("0x8664") == 0x8664
    assert _as_int(0x8664) == 0x8664
    assert _as_int(None) == 0
    assert _as_int("garbage") == 0


def test_parse_label_filters_unlabeled():
    assert parse_label(1) == 1
    assert parse_label(0) == 0
    assert parse_label(-1) is None
    assert parse_label("7") is None
    assert parse_label(None) is None


def test_minimal_record_all_zero_defaults():
    feats = ember_record_to_features({"label": 0})
    assert feats["is_pe"] == 1.0
    assert feats["file_size"] == 0.0
    vec = vectorize(feats)
    assert len(vec) == len(FEATURE_NAMES)
    nonzero = [n for n, x in zip(FEATURE_NAMES, vec) if x != 0.0]
    assert set(nonzero) == {"is_pe"}


@pytest.mark.parametrize(
    "record_key,value",
    [("machine", "0xAA64"), ("subsystem", "3"), ("timestamp", 1e9)],
)
def test_coercion_from_strings(record_key, value):
    rec = {
        "header": {
            "coff": {"machine": "0xAA64", "timestamp": 1e9},
            "optional": {"subsystem": "3"},
        }
    }
    feats = ember_record_to_features(rec)
    assert feats["pe_machine"] == 0xAA64
    assert feats["pe_subsystem"] == 3
    assert feats["pe_timestamp"] == int(1e9)
