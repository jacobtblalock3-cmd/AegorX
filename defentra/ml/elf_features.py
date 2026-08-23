"""Static ELF (Linux executable) parsing and feature extraction in pure Python."""

from __future__ import annotations

import struct
from typing import Dict, List

PT_GNU_STACK = 0x6474E551
SHT_PROGBITS = 1
SHT_DYNSYM = 11


class NotElfError(ValueError):
    pass


def parse_elf(data: bytes) -> Dict:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise NotElfError("missing ELF magic")
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise NotElfError(f"unknown ELF class {ei_class}")
    if ei_data not in (1, 2):
        raise NotElfError(f"unknown ELF data encoding {ei_data}")

    fmt = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    e_type, e_machine = struct.unpack_from(fmt + "HH", data, 16)
    e_phoff = struct.unpack_from(fmt + ("Q" if is64 else "I"), data, 32)[0]
    e_shoff = struct.unpack_from(fmt + ("Q" if is64 else "I"), data, 40)[0]
    e_phentsize, e_phnum = struct.unpack_from(fmt + "HH", data, 54)
    e_shentsize, e_shnum = struct.unpack_from(fmt + "HH", data, 58)

    elf = {
        "class": ei_class,
        "type": e_type,
        "machine": e_machine,
        "pie": e_type == 3,
        "shared_object": e_type == 3,
        "executable": e_type == 2,
        "relocatable": e_type == 1,
    }

    nx_stack = False
    phnum = min(e_phnum, 128)
    for i in range(phnum):
        off = e_phoff + i * e_phentsize
        if off + 8 > len(data):
            break
        p_type = struct.unpack_from(fmt + "I", data, off)[0]
        if p_type == PT_GNU_STACK:
            flags_off = off + (28 if is64 else 24)
            if flags_off + 4 <= len(data):
                p_flags = struct.unpack_from(fmt + "I", data, flags_off)[0]
                nx_stack = not (p_flags & 0x1)
    elf["nx_stack"] = nx_stack

    shnum = min(e_shnum, 2048)
    progbits_sizes: List[int] = []
    dynsym_count = 0
    for i in range(shnum):
        off = e_shoff + i * e_shentsize
        if off + (64 if is64 else 40) > len(data):
            break
        if is64:
            sh_name, sh_type = struct.unpack_from(fmt + "II", data, off)
            sh_offset = struct.unpack_from(fmt + "Q", data, off + 24)[0]
            sh_size = struct.unpack_from(fmt + "Q", data, off + 32)[0]
            sh_entsize = struct.unpack_from(fmt + "Q", data, off + 56)[0]
        else:
            sh_name, sh_type = struct.unpack_from(fmt + "II", data, off)
            sh_offset = struct.unpack_from(fmt + "I", data, off + 16)[0]
            sh_size = struct.unpack_from(fmt + "I", data, off + 20)[0]
            sh_entsize = struct.unpack_from(fmt + "I", data, off + 36)[0]
        if sh_type == SHT_DYNSYM and sh_entsize:
            dynsym_count += sh_size // sh_entsize
        if sh_type == SHT_PROGBITS:
            progbits_sizes.append((sh_offset, sh_size))
    elf["num_sections"] = shnum
    elf["dynsym_count"] = dynsym_count
    elf["progbits_spans"] = progbits_sizes
    return elf
