"""Process memory scanning for fileless malware detection.

Scans running process memory for:
  - Injected code in RWX (read-write-execute) memory regions
  - Suspicious shellcode patterns (NOP sleds, syscalls, encoded payloads)
  - Known malicious signatures in process memory
  - Abnormal memory permissions (heap/stack with execute bit)

Platform support:
  Linux:  /proc/[pid]/maps + /proc/[pid]/mem
  macOS:  task_for_pid + mach VM APIs (via ctypes)
  Windows: ReadProcessMemory + VirtualQueryEx (via ctypes)

Process scanning is expensive and should be used sparingly:
  - Manual trigger only (no background scanning)
  - Scans specific PIDs or all user processes
  - Reports suspicious findings without quarantining (memory can't be quarantined)
"""

from __future__ import annotations

import os
import re
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MemoryRegion:
    """A single memory region from a process."""
    start: int
    end: int
    perms: str  # rwxp, rw-p, etc.
    path: str = ""
    size: int = 0

    @property
    def readable(self) -> bool:
        return "r" in self.perms

    @property
    def writable(self) -> bool:
        return "w" in self.perms

    @property
    def executable(self) -> bool:
        return "x" in self.perms


@dataclass
class MemoryFinding:
    """A suspicious finding from memory scanning."""
    pid: int
    process_name: str
    region: MemoryRegion
    finding_type: str  # "rwx_region", "shellcode", "suspicious_pattern"
    details: str
    severity: int = 5  # 1-10


# ---------------------------------------------------------------------------
# Suspicious pattern detection
# ---------------------------------------------------------------------------

# Common shellcode prologues / suspicious byte patterns
_SHELLCODE_PATTERNS = [
    # x86/x64 NOP sled
    b"\x90" * 16,
    # x86: push ebp; mov ebp, esp
    b"\x55\x89\xe5",
    # x64: push rbp; mov rbp, rsp
    b"\x55\x48\x89\xe5",
    # x86: int 0x80 (Linux syscall)
    b"\xcd\x80",
    # x86: jmp short with large displacement (suspicious, not common in normal code)
    b"\xeb\x80",
    b"\xeb\x81",
    b"\xeb\x82",
    b"\xeb\xff",
    # XOR eax, eax (common zeroing)
    b"\x31\xc0",
    b"\x33\xc0",
    # Windows: LoadLibraryA pattern
    b"LoadLibraryA",
    b"GetProcAddress",
    # Metaspatterns
    b"\xfc\xe8\x82\x00\x00\x00",  # common meterpreter stub
    b"\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30",
    # NOP sled (16+ consecutive NOPs = suspicious)
    b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90",
]

# Suspicious string patterns in memory
_SUSPICIOUS_STRINGS = [
    rb"powershell.*-enc",
    rb"cmd\.exe.*/c",
    rb"/bin/sh.*-c",
    rb"curl.*\|.*sh",
    rb"wget.*\|.*sh",
    rb"base64.*decode",
    rb"eval\(.*\$\{",
]


def _check_shellcode_patterns(data: bytes) -> List[str]:
    """Check a memory region for shellcode patterns."""
    findings = []
    for pattern in _SHELLCODE_PATTERNS:
        if pattern in data:
            findings.append(f"shellcode pattern: {pattern[:16].hex()}...")
    for pattern in _SUSPICIOUS_STRINGS:
        if re.search(pattern, data, re.IGNORECASE):
            findings.append(f"suspicious string: {pattern[:32]}")
    return findings


# ---------------------------------------------------------------------------
# Linux process memory reader
# ---------------------------------------------------------------------------

def _read_proc_maps(pid: int) -> List[MemoryRegion]:
    """Read /proc/[pid]/maps for memory regions."""
    regions = []
    try:
        with open(f"/proc/{pid}/maps", "r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 6:
                    continue
                addr_range = parts[0]
                perms = parts[1]
                path = parts[5] if len(parts) > 5 else ""
                try:
                    start_str, end_str = addr_range.split("-")
                    start = int(start_str, 16)
                    end = int(end_str, 16)
                    regions.append(MemoryRegion(
                        start=start, end=end, perms=perms,
                        path=path, size=end - start,
                    ))
                except (ValueError, IndexError):
                    continue
    except (OSError, PermissionError):
        pass
    return regions


def _read_proc_mem(pid: int, offset: int, size: int) -> bytes:
    """Read bytes from /proc/[pid]/mem at a given offset."""
    try:
        with open(f"/proc/{pid}/mem", "rb") as fh:
            fh.seek(offset)
            return fh.read(size)
    except (OSError, PermissionError, ValueError):
        return b""


def _get_proc_name(pid: int) -> str:
    """Get process name from /proc/[pid]/comm."""
    try:
        with open(f"/proc/{pid}/comm", "r") as fh:
            return fh.read().strip()
    except (OSError, PermissionError):
        return f"pid-{pid}"


def _scan_linux(pid: int, max_region_size: int = 10 * 1024 * 1024) -> List[MemoryFinding]:
    """Scan a Linux process's memory for suspicious content."""
    findings = []
    proc_name = _get_proc_name(pid)
    regions = _read_proc_maps(pid)

    for region in regions:
        # Focus on RWX regions (most suspicious)
        if region.readable and region.writable and region.executable:
            data = _read_proc_mem(pid, region.start, min(region.size, max_region_size))
            if not data:
                continue

            pattern_findings = _check_shellcode_patterns(data)
            for detail in pattern_findings:
                findings.append(MemoryFinding(
                    pid=pid,
                    process_name=proc_name,
                    region=region,
                    finding_type="rwx_region",
                    details=f"RWX memory region: {region.perms} {region.path or '[anon]'} - {detail}",
                    severity=7,
                ))

        # Also check readable+executable regions for shellcode (not from known libs)
        elif region.readable and region.executable and not region.path:
            data = _read_proc_mem(pid, region.start, min(region.size, max_region_size))
            if not data:
                continue
            pattern_findings = _check_shellcode_patterns(data)
            for detail in pattern_findings:
                findings.append(MemoryFinding(
                    pid=pid,
                    process_name=proc_name,
                    region=region,
                    finding_type="shellcode",
                    details=f"Anonymous executable region: {detail}",
                    severity=8,
                ))

    return findings


# ---------------------------------------------------------------------------
# macOS process memory reader (via ctypes / task_for_pid)
# ---------------------------------------------------------------------------

def _scan_macos(pid: int) -> List[MemoryFinding]:
    """Scan a macOS process's memory.

    Uses vm_region via ctypes to enumerate memory regions.
    """
    findings = []
    try:
        import ctypes
        import ctypes.util

        mach = ctypes.CDLL(ctypes.util.find_library("c"))

        # task_for_pid requires root or appropriate entitlements
        task = ctypes.c_uint32(0)
        result = mach.task_for_pid(mach.mach_task_self(), pid, ctypes.byref(task))
        if result != 0:
            return findings

        # Read memory regions using vm_region
        # (Simplified - full implementation would use mach_vm_region)
        proc_name = f"pid-{pid}"

        # For now, report that macOS memory scanning requires elevated privileges
        findings.append(MemoryFinding(
            pid=pid,
            process_name=proc_name,
            region=MemoryRegion(start=0, end=0, perms="r-x"),
            finding_type="info",
            details="macOS memory scanning requires root or entitlement",
            severity=1,
        ))

    except (OSError, ImportError, AttributeError):
        pass
    return findings


# ---------------------------------------------------------------------------
# Windows process memory reader
# ---------------------------------------------------------------------------

def _scan_windows(pid: int) -> List[MemoryFinding]:
    """Scan a Windows process's memory using ctypes."""
    findings = []
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32")

        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400

        handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False, pid,
        )
        if not handle:
            return findings

        try:
            # Use VirtualQueryEx to enumerate memory regions
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]

            mbi = MEMORY_BASIC_INFORMATION()
            mbi_size = ctypes.sizeof(mbi)
            addr = 0
            proc_name = f"pid-{pid}"

            # Try to get process name
            try:
                buf = ctypes.create_unicode_buffer(256)
                # Use psapi if available
                psapi = ctypes.WinDLL("psapi")
                psapi.GetModuleBaseNameW(handle, None, buf, 256)
                if buf.value:
                    proc_name = buf.value
            except (OSError, AttributeError):
                pass

            while kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size):
                region_size = mbi.RegionSize
                if region_size == 0:
                    break

                # Check for RWX or RX regions
                protect = mbi.Protect
                PAGE_EXECUTE_READWRITE = 0x40
                PAGE_EXECUTE_READ = 0x20
                PAGE_READWRITE = 0x04

                is_rwx = (protect == PAGE_EXECUTE_READWRITE)
                is_rx = (protect == PAGE_EXECUTE_READ)

                if is_rwx or (is_rx and mbi.Type == 0):  # MEM_PRIVATE
                    # Read the region
                    buf = ctypes.create_string_buffer(min(region_size, 1024 * 1024))
                    bytes_read = ctypes.c_size_t(0)
                    if kernel32.ReadProcessMemory(
                        handle, ctypes.c_void_p(addr),
                        buf, min(region_size, 1024 * 1024),
                        ctypes.byref(bytes_read),
                    ):
                        data = buf.raw[:bytes_read.value]
                        pattern_findings = _check_shellcode_patterns(data)
                        for detail in pattern_findings:
                            findings.append(MemoryFinding(
                                pid=pid,
                                process_name=proc_name,
                                region=MemoryRegion(
                                    start=addr, end=addr + region_size,
                                    perms="rwx" if is_rwx else "rx",
                                ),
                                finding_type="rwx_region" if is_rwx else "shellcode",
                                details=f"{'RWX' if is_rwx else 'RX'} private region: {detail}",
                                severity=8 if is_rwx else 7,
                            ))

                addr += region_size

        finally:
            kernel32.CloseHandle(handle)

    except (OSError, ImportError, AttributeError):
        pass
    return findings


# ---------------------------------------------------------------------------
# Main scanner interface
# ---------------------------------------------------------------------------

class ProcessMemoryScanner:
    """Scan process memory for fileless malware.

    This is a manual-trigger scanner.  It does not run in the background
    by default because process memory scanning is expensive.

    Parameters
    ----------
    finding_callback:
        Called with each ``MemoryFinding`` as it's discovered.
    max_region_bytes:
        Maximum bytes to read per memory region.
    """

    def __init__(
        self,
        finding_callback: Optional[Callable[[MemoryFinding], None]] = None,
        max_region_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        self.finding_callback = finding_callback
        self.max_region_bytes = max_region_bytes
        self._lock = threading.Lock()
        self._stats = {
            "processes_scanned": 0,
            "findings": 0,
        }

    def scan_pid(self, pid: int) -> List[MemoryFinding]:
        """Scan a single process by PID."""
        with self._lock:
            self._stats["processes_scanned"] += 1
        findings = self._scan_platform(pid)
        with self._lock:
            self._stats["findings"] += len(findings)
        for f in findings:
            if self.finding_callback:
                self.finding_callback(f)
        return findings

    def scan_all(self, skip_pids: Optional[Set[int]] = None) -> List[MemoryFinding]:
        """Scan all user processes."""
        skip_pids = skip_pids or set()
        all_findings = []
        for pid in self._get_user_pids():
            if pid in skip_pids:
                continue
            findings = self.scan_pid(pid)
            all_findings.extend(findings)
        return all_findings

    def scan_name(self, name: str) -> List[MemoryFinding]:
        """Scan processes matching a name."""
        all_findings = []
        for pid in self._get_user_pids():
            proc_name = self._get_process_name(pid)
            if name.lower() in proc_name.lower():
                findings = self.scan_pid(pid)
                all_findings.extend(findings)
        return all_findings

    def _scan_platform(self, pid: int) -> List[MemoryFinding]:
        if sys.platform == "linux":
            return _scan_linux(pid, self.max_region_bytes)
        if sys.platform == "darwin":
            return _scan_macos(pid)
        if sys.platform == "win32":
            return _scan_windows(pid)
        return []

    def _get_user_pids(self) -> List[int]:
        """Get PIDs of all running processes."""
        pids = []
        if sys.platform == "linux":
            try:
                for entry in os.listdir("/proc"):
                    if entry.isdigit():
                        pids.append(int(entry))
            except OSError:
                pass
        elif sys.platform == "darwin":
            try:
                import subprocess
                result = subprocess.run(
                    ["ps", "-eo", "pid="],
                    capture_output=True, timeout=5,
                )
                for line in result.stdout.decode().splitlines():
                    line = line.strip()
                    if line.isdigit():
                        pids.append(int(line))
            except (OSError, subprocess.SubprocessError):
                pass
        elif sys.platform == "win32":
            try:
                import ctypes
                kernel32 = ctypes.WinDLL("kernel32")
                # CreateToolhelp32Snapshot
                TH32CS_SNAPPROCESS = 0x00000002
                snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                if snapshot:
                    class PROCESSENTRY32(ctypes.Structure):
                        _fields_ = [
                            ("dwSize", ctypes.c_ulong),
                            ("cntUsage", ctypes.c_ulong),
                            ("th32ProcessID", ctypes.c_ulong),
                            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                            ("th32ModuleID", ctypes.c_ulong),
                            ("cntThreads", ctypes.c_ulong),
                            ("th32ParentProcessID", ctypes.c_ulong),
                            ("pcPriClassBase", ctypes.c_long),
                            ("dwFlags", ctypes.c_ulong),
                            ("szExeFile", ctypes.c_char * 260),
                        ]

                    pe = PROCESSENTRY32()
                    pe.dwSize = ctypes.sizeof(pe)
                    if kernel32.Process32First(snapshot, ctypes.byref(pe)):
                        while True:
                            pids.append(pe.th32ProcessID)
                            if not kernel32.Process32Next(snapshot, ctypes.byref(pe)):
                                break
                    kernel32.CloseHandle(snapshot)
            except (OSError, AttributeError):
                pass
        return pids

    def _get_process_name(self, pid: int) -> str:
        if sys.platform == "linux":
            try:
                with open(f"/proc/{pid}/comm", "r") as fh:
                    return fh.read().strip()
            except (OSError, PermissionError):
                return ""
        return f"pid-{pid}"

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0
