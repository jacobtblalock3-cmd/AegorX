"""Static PE (Windows executable) parsing and feature extraction in pure Python."""

from __future__ import annotations

import struct
from typing import Dict, List

SUSPICIOUS_IMPORTS = {
    "virtualalloc": "memory_alloc",
    "virtualallocex": "remote_mem_alloc",
    "virtualprotect": "mem_protect",
    "writeprocessmemory": "process_write",
    "readprocessmemory": "process_read",
    "createremotethread": "thread_injection",
    "ntunmapviewofsection": "hollowing",
    "zwunmapviewofsection": "hollowing",
    "setwindowshookex": "hooking",
    "winexec": "exec",
    "shellexecutea": "exec",
    "shellexecutew": "exec",
    "createtoolhelp32snapshot": "enumeration",
    "isdebuggerpresent": "anti_debug",
    "checkremotedebuggerpresent": "anti_debug",
    "urldownloadtofilea": "downloader",
    "urldownloadtofilew": "downloader",
    "internetopena": "network",
    "wsastartup": "network",
    "adjusttokenprivileges": "privilege",
    "regsetvalueexa": "persistence",
    "regsetvalueexw": "persistence",
    "cryptencrypt": "ransomware_crypto",
    "getasynckeystate": "keylogger",
    "getkeystate": "keylogger",
}

SECTION_EXECUTE = 0x20000000
SECTION_WRITE = 0x80000000


class NotPEError(ValueError):
    pass


def parse_pe(data: bytes) -> Dict:
    if len(data) < 64 or data[:2] != b"MZ":
        raise NotPEError("missing MZ header")
    try:
        return _parse_pe_inner(data)
    except struct.error as exc:
        raise NotPEError(f"truncated PE structure: {exc}") from exc


def _parse_pe_inner(data: bytes) -> Dict:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise NotPEError("missing PE signature")

    coff = e_lfanew + 4
    machine, num_sections, _ts, _psym, _nsym, opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    opt_off = coff + 20
    if opt_off + 96 > len(data):
        raise NotPEError("truncated optional header")
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic not in (0x10B, 0x20B):
        raise NotPEError(f"unknown optional-header magic {magic:#x}")
    plus = magic == 0x20B

    entry_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
    image_base = struct.unpack_from("<Q" if plus else "<I", data, opt_off + 24)[0]
    size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
    subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
    dll_characteristics = struct.unpack_from("<H", data, opt_off + 70)[0]
    num_dirs_raw = struct.unpack_from("<I", data, opt_off + 92)[0]
    num_dirs = min(num_dirs_raw, 16)
    if opt_off + 96 + num_dirs * 8 > len(data):
        num_dirs = max(0, (len(data) - opt_off - 96) // 8)

    dirs = []
    for i in range(num_dirs):
        rva, size = struct.unpack_from("<II", data, opt_off + 96 + i * 8)
        dirs.append({"rva": rva, "size": size})

    sec_off = opt_off + opt_size
    sections: List[Dict] = []
    for i in range(min(num_sections, 96)):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off : off + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append(
            {
                "name": name,
                "virtual_size": vsize,
                "virtual_address": vaddr,
                "raw_size": rawsize,
                "raw_pointer": rawptr,
                "characteristics": chars,
            }
        )

    pe = {
        "machine": machine,
        "num_sections": num_sections,
        "timestamp": _ts,
        "characteristics": characteristics,
        "magic": magic,
        "entry_rva": entry_rva,
        "image_base": image_base,
        "size_of_image": size_of_image,
        "subsystem": subsystem,
        "dll_characteristics": dll_characteristics,
        "num_data_dirs": num_dirs,
        "sections": sections,
    }

    pe["has_imports"] = bool(dirs[1]["rva"]) if num_dirs > 1 else False
    pe["has_resources"] = bool(dirs[2]["rva"]) if num_dirs > 2 else False
    pe["has_tls"] = bool(dirs[9]["rva"]) if num_dirs > 9 else False
    pe["has_debug"] = bool(dirs[6]["rva"]) if num_dirs > 6 else False
    pe["has_signature"] = bool(dirs[4]["rva"]) if num_dirs > 4 else False
    pe["has_dotnet"] = bool(dirs[14]["rva"]) if num_dirs > 14 else False

    end_raw = max((s["raw_pointer"] + s["raw_size"] for s in sections), default=0)
    pe["overlay_size"] = max(0, len(data) - end_raw)

    pe.update(_extract_imports(data, dirs, sections, plus))
    return pe


def _extract_imports(data: bytes, dirs, sections, plus: bool) -> Dict:
    out = {"import_dlls": [], "import_functions": [], "total_import_functions": 0}
    if len(dirs) <= 1 or not dirs[1]["rva"]:
        return out
    from defentra.utils import rva_to_offset

    idt_off = rva_to_offset(dirs[1]["rva"], sections)
    if idt_off is None:
        return out
    thunk_size = 8 if plus else 4
    ordinal_flag = 1 << ((thunk_size * 8) - 1)
    dlls = []
    functions = []
    for i in range(64):
        desc_off = idt_off + i * 20
        if desc_off + 20 > len(data):
            break
        original_thunk, _ts, _fc, name_rva, _ft = struct.unpack_from("<IIIII", data, desc_off)
        if original_thunk == 0 and name_rva == 0:
            break
        dll_name = ""
        name_off = rva_to_offset(name_rva, sections)
        if name_off is not None:
            end = data.find(b"\x00", name_off)
            if end != -1:
                dll_name = data[name_off:end].decode("latin-1", errors="replace")
        dlls.append(dll_name)
        thunk_rva = original_thunk or _ft
        thunk_off = rva_to_offset(thunk_rva, sections)
        if thunk_off is None:
            continue
        for j in range(1024):
            t_off = thunk_off + j * thunk_size
            if t_off + thunk_size > len(data):
                break
            if plus:
                val = struct.unpack_from("<Q", data, t_off)[0]
            else:
                val = struct.unpack_from("<I", data, t_off)[0]
            if val == 0:
                break
            if val & ordinal_flag:
                functions.append(f"{dll_name}::#{val & 0xFFFF}")
                continue
            fname_off = rva_to_offset(val & 0x7FFFFFFF if plus else val, sections)
            if fname_off is None or fname_off + 2 > len(data):
                continue
            end = data.find(b"\x00", fname_off + 2)
            if end == -1:
                continue
            fname = data[fname_off + 2 : end].decode("latin-1", errors="replace")
            functions.append(f"{dll_name}::{fname}"[:256])
    out["import_dlls"] = dlls
    out["import_functions"] = functions
    out["total_import_functions"] = len(functions)
    return out


def suspicious_import_hits(import_functions: List[str]) -> int:
    hits = set()
    for full in import_functions:
        _, _, func = full.rpartition("::")
        tag = SUSPICIOUS_IMPORTS.get(func.lower())
        if tag:
            hits.add(tag)
    return len(hits)


def section_entropies(data: bytes, sections) -> List[float]:
    from defentra.utils import shannon_entropy

    entropies = []
    for s in sections:
        start, size = s["raw_pointer"], s["raw_size"]
        if start >= len(data) or size == 0:
            entropies.append(0.0)
            continue
        blob = data[start : start + min(size, 1024 * 1024)]
        entropies.append(shannon_entropy(blob))
    return entropies
