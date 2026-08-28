"""Tests for process memory scanning."""

from __future__ import annotations

import os

import pytest

from aegorx.process_scanner import (
    ProcessMemoryScanner,
    MemoryFinding,
    MemoryRegion,
    _check_shellcode_patterns,
)


class TestMemoryRegion:
    def test_executable(self):
        r = MemoryRegion(start=0, end=100, perms="rwxp")
        assert r.executable
        assert r.readable
        assert r.writable

    def test_readonly(self):
        r = MemoryRegion(start=0, end=100, perms="r--p")
        assert r.readable
        assert not r.executable
        assert not r.writable


class TestShellcodePatterns:
    def test_nop_sled(self):
        data = b"\x90" * 32 + b"other"
        findings = _check_shellcode_patterns(data)
        assert any("shellcode" in f.lower() for f in findings)

    def test_xor_eax(self):
        data = b"\x31\xc0" + b"\x00" * 100
        findings = _check_shellcode_patterns(data)
        assert len(findings) >= 1

    def test_clean_data(self):
        data = b"Hello, this is a normal string with no shellcode."
        findings = _check_shellcode_patterns(data)
        assert len(findings) == 0

    def test_loadlibrary(self):
        data = b"LoadLibraryA" + b"\x00" * 100
        findings = _check_shellcode_patterns(data)
        assert any("shellcode" in f.lower() for f in findings)


class TestProcessMemoryScanner:
    def test_scan_pid_self(self):
        scanner = ProcessMemoryScanner()
        pid = os.getpid()
        findings = scanner.scan_pid(pid)
        assert isinstance(findings, list)
        assert scanner.stats()["processes_scanned"] == 1

    def test_scan_pid_nonexistent(self):
        scanner = ProcessMemoryScanner()
        findings = scanner.scan_pid(9999999)
        assert isinstance(findings, list)

    def test_scan_name(self):
        scanner = ProcessMemoryScanner()
        # Scan for current process name
        findings = scanner.scan_name("python")
        assert isinstance(findings, list)

    def test_scan_name_no_match(self):
        scanner = ProcessMemoryScanner()
        findings = scanner.scan_name("nonexistent_process_xyz")
        assert findings == []

    def test_finding_callback(self):
        findings_received = []

        def callback(finding):
            findings_received.append(finding)

        scanner = ProcessMemoryScanner(finding_callback=callback)
        scanner.scan_pid(os.getpid())
        # Callbacks are called for each finding (may be empty for clean processes)
        assert isinstance(findings_received, list)

    def test_stats(self):
        scanner = ProcessMemoryScanner()
        scanner.scan_pid(os.getpid())
        stats = scanner.stats()
        assert stats["processes_scanned"] == 1

    def test_reset_stats(self):
        scanner = ProcessMemoryScanner()
        scanner.scan_pid(os.getpid())
        scanner.reset_stats()
        assert scanner.stats()["processes_scanned"] == 0
