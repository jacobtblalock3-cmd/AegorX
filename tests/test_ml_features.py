import pytest

from defentra.ml.elf_features import NotElfError, parse_elf
from defentra.ml.features import FEATURE_NAMES, extract_features, looks_executable, vectorize
from defentra.ml.pe_features import NotPEError, parse_pe, suspicious_import_hits


def test_reject_garbage_pe():
    with pytest.raises(NotPEError):
        parse_pe(b"\x00" * 64)
    with pytest.raises(NotPEError):
        parse_pe(b"MZ" + b"\x00" * 100)


def test_parse_minimal_pe(pe_file):
    with open(pe_file, "rb") as fh:
        pe = parse_pe(fh.read())
    assert pe["machine"] == 0x14C
    assert pe["num_sections"] == 1
    assert pe["subsystem"] == 2
    assert pe["has_imports"] is True
    assert "kernel32.dll" in pe["import_dlls"]
    assert any("WriteProcessMemory" in f for f in pe["import_functions"])
    assert suspicious_import_hits(pe["import_functions"]) >= 1


def test_parse_minimal_elf(elf_file):
    elf = parse_elf(open(elf_file, "rb").read())
    assert elf["type"] == 2
    assert elf["machine"] == 0x3E
    assert elf["pie"] is False
    assert elf["executable"] is True


def test_elf_magic_required():
    with pytest.raises(NotElfError):
        parse_elf(b"ELF" + b"\x00" * 60)


def test_feature_vector_shape_and_consistency(pe_file, elf_file):
    feats_pe = extract_features(pe_file)
    feats_elf = extract_features(elf_file)
    v_pe, v_elf = vectorize(feats_pe), vectorize(feats_elf)
    assert len(v_pe) == len(FEATURE_NAMES) == len(v_elf)
    assert all(isinstance(x, float) for x in v_pe)
    assert feats_pe["is_pe"] == 1.0
    assert feats_pe["pe_suspicious_import_hits"] >= 1
    assert feats_elf["is_elf"] == 1.0
    assert feats_elf["elf_machine"] == 0x3E
    assert feats_pe["entropy_max"] <= 8.0


def test_plain_text_not_executable(benign_file):
    head = open(benign_file, "rb").read(4)
    assert not looks_executable(head)
    feats = extract_features(benign_file)
    assert feats["is_pe"] == 0.0 and feats["is_elf"] == 0.0
