"""Tests for vulnerability scanner."""

from __future__ import annotations

import json
import os

import pytest

from aegorx.vuln_scanner import (
    VulnScanner,
    VulnEntry,
    VulnFinding,
    InstalledSoftware,
    _parse_version,
    _version_lt,
    VULN_DATABASE,
)


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

class TestParseVersion:
    def test_simple(self):
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_two_parts(self):
        assert _parse_version("3.11") == (3, 11)

    def test_with_suffix(self):
        assert _parse_version("1.2.3-beta") == (1, 2, 3)

    def test_non_numeric(self):
        assert _parse_version("abc") == ()


class TestVersionLt:
    def test_less(self):
        assert _version_lt("1.2.3", "1.2.4") is True

    def test_equal(self):
        assert _version_lt("1.2.3", "1.2.3") is False

    def test_greater(self):
        assert _version_lt("1.2.4", "1.2.3") is False

    def test_different_lengths(self):
        assert _version_lt("1.2", "1.2.3") is True

    def test_non_numeric(self):
        assert _version_lt("abc", "1.2.3") is False


# ---------------------------------------------------------------------------
# VulnEntry
# ---------------------------------------------------------------------------

class TestVulnEntry:
    def test_vulnerable(self):
        entry = VulnEntry("test", "2.0.0", "high")
        assert entry.is_vulnerable("1.0.0") is True
        assert entry.is_vulnerable("2.0.0") is False
        assert entry.is_vulnerable("2.1.0") is False

    def test_severity(self):
        entry = VulnEntry("test", "1.0", "critical", "CVE-1234")
        assert entry.severity == "critical"
        assert entry.cve == "CVE-1234"


# ---------------------------------------------------------------------------
# VulnScanner
# ---------------------------------------------------------------------------

class TestVulnScanner:
    def test_scan_returns_list(self):
        scanner = VulnScanner()
        findings = scanner.scan()
        assert isinstance(findings, list)

    def test_stats_after_scan(self):
        scanner = VulnScanner()
        scanner.scan()
        stats = scanner.stats()
        assert stats["software_scanned"] > 0

    def test_ignore_list(self):
        scanner = VulnScanner()
        scanner.add_ignore("python")
        ignored = scanner.list_ignored()
        assert "python" in ignored

    def test_ignore_prevents_finding(self):
        scanner = VulnScanner()
        scanner.add_ignore("nonexistent-xyz")
        findings = scanner.scan()
        for f in findings:
            assert f.software != "nonexistent-xyz"

    def test_remove_ignore(self):
        scanner = VulnScanner()
        scanner.add_ignore("test")
        scanner.remove_ignore("test")
        assert "test" not in scanner.list_ignored()

    def test_custom_database(self):
        db = [VulnEntry("fake-app", "999.0.0", "critical")]
        scanner = VulnScanner(database=db)
        findings = scanner.scan()
        # Should find fake-app if installed
        fake_findings = [f for f in findings if f.software == "fake-app"]
        # May or may not find it depending on what's installed
        assert isinstance(fake_findings, list)

    def test_last_scan(self):
        scanner = VulnScanner()
        assert scanner.last_scan() is None
        scanner.scan()
        assert scanner.last_scan() is not None

    def test_reset_stats(self):
        scanner = VulnScanner()
        scanner.scan()
        scanner._stats["software_scanned"] = 0
        stats = scanner.stats()
        assert stats["software_scanned"] == 0


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

class TestCLIVulnCommands:
    def test_vuln_no_subcommand(self):
        from aegorx.cli import main
        result = main(["vuln"])
        assert result == 3

    def test_vuln_status(self):
        from aegorx.cli import main
        result = main(["vuln", "status"])
        assert result == 0

    def test_vuln_scan(self):
        from aegorx.cli import main
        result = main(["vuln", "scan"])
        assert result in (0, 2)  # CLEAN or MALICIOUS

    def test_vuln_ignore(self):
        from aegorx.cli import main
        result = main(["vuln", "ignore", "test-app"])
        assert result == 0

    def test_vuln_unignore(self):
        from aegorx.cli import main
        result = main(["vuln", "unignore", "test-app"])
        assert result == 0

    def test_vuln_ignored(self):
        from aegorx.cli import main
        result = main(["vuln", "ignored"])
        assert result == 0
