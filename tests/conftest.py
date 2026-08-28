from __future__ import annotations

import os
import struct
import sys

import pytest


SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)


@pytest.fixture
def tmp_home(tmp_path, monkeypatch):
    home = tmp_path / "aegorx-home"
    monkeypatch.setenv("AEGORX_HOME", str(home))
    return str(home)


EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def build_minimal_pe() -> bytes:
    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<H", opt, 68, 2)
    struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 8, 0x2000, 40)

    section = bytearray(40)
    section[0:6] = b".text\x00"
    struct.pack_into("<IIII", section, 8, 0x1400, 0x1000, 0x1400, 0x400)
    struct.pack_into("<I", section, 36, 0x60000020)

    body = bytearray(0x1400)

    idt_body = 0x1000
    dll_name_body = 0x1060
    thunk_body = 0x1080
    fname_body = 0x10A0

    def rva(file_offset: int) -> int:
        return file_offset - 0x400 + 0x1000

    idt_file = 0x400 + idt_body
    dll_name_file = 0x400 + dll_name_body
    thunk_file = 0x400 + thunk_body
    fname_file = 0x400 + fname_body

    body[idt_body : idt_body + 20] = struct.pack(
        "<IIIII",
        rva(thunk_file),
        0,
        0,
        rva(dll_name_file),
        rva(thunk_file),
    )
    dll_name = b"kernel32.dll\x00"
    func_name = b"\x00\x00WriteProcessMemory\x00"
    body[dll_name_body : dll_name_body + len(dll_name)] = dll_name
    body[fname_body : fname_body + len(func_name)] = func_name
    struct.pack_into("<Q", body, thunk_body, rva(fname_file))

    data = bytearray()
    data += dos
    data += pe_sig + coff + bytes(opt) + bytes(section)
    if len(data) < 0x400:
        data += b"\x00" * (0x400 - len(data))
    data += bytes(body)
    return bytes(data)


def build_minimal_elf() -> bytes:
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2
    ehdr[5] = 1
    ehdr[6] = 1
    struct.pack_into("<HH", ehdr, 16, 2, 0x3E)
    struct.pack_into("<Q", ehdr, 24, 0x1000)
    struct.pack_into("<Q", ehdr, 32, 0)
    struct.pack_into("<Q", ehdr, 40, 0)
    struct.pack_into("<HHHHHH", ehdr, 52, 64, 56, 0, 64, 0, 0)
    return bytes(ehdr)


@pytest.fixture
def pe_file(tmp_path):
    p = tmp_path / "sample.exe"
    p.write_bytes(build_minimal_pe())
    return str(p)


@pytest.fixture
def elf_file(tmp_path):
    p = tmp_path / "sample.elf"
    p.write_bytes(build_minimal_elf())
    return str(p)


@pytest.fixture
def eicar_file(tmp_path):
    p = tmp_path / "eicar.com"
    p.write_bytes(EICAR)
    return str(p)


@pytest.fixture
def benign_file(tmp_path):
    p = tmp_path / "readme.txt"
    p.write_bytes(b"hello aegorx\n" * 10)
    return str(p)


@pytest.fixture
def rules_dir():
    import aegorx.engine as engine_mod

    d = os.path.join(os.path.dirname(engine_mod.__file__), "..", "rules")
    return os.path.abspath(d)


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: slow tests")
