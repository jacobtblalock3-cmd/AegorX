"""Tests for DNS-based domain filtering."""

from __future__ import annotations

import json
import os

import pytest

from aegorx.network.dns_filter import DNSFilter, BLOCK_IP


@pytest.fixture()
def dns(tmp_path):
    """Create a DNSFilter with temporary paths."""
    blocklist = str(tmp_path / "blocklist.json")
    custom = str(tmp_path / "custom.json")
    return DNSFilter(blocklist_path=blocklist, custom_blocklist_path=custom)


class TestDNSFilter:
    def test_empty_blocklist_allows_all(self, dns):
        assert dns.lookup("example.com") is False
        assert dns.lookup("google.com") is False
        assert dns.count() == 0

    def test_block_domain(self, dns):
        assert dns.block("evil.com") is True
        assert dns.count() == 1
        assert dns.lookup("evil.com") is True

    def test_block_duplicate(self, dns):
        dns.block("evil.com")
        assert dns.block("evil.com") is False
        assert dns.count() == 1

    def test_unblock_domain(self, dns):
        dns.block("evil.com")
        assert dns.unblock("evil.com") is True
        assert dns.lookup("evil.com") is False
        assert dns.count() == 0

    def test_unblock_nonexistent(self, dns):
        assert dns.unblock("notblocked.com") is False

    def test_subdomain_of_blocked(self, dns):
        dns.block("evil.com")
        assert dns.lookup("sub.evil.com") is True
        assert dns.lookup("deep.sub.evil.com") is True

    def test_domain_not_subdomain(self, dns):
        dns.block("evil.com")
        assert dns.lookup("notevil.com") is False
        assert dns.lookup("evil.com.au") is False

    def test_case_insensitive(self, dns):
        dns.block("Evil.COM")
        assert dns.lookup("evil.com") is True
        assert dns.lookup("EVIL.COM") is True

    def test_leading_dot_stripped(self, dns):
        dns.block(".evil.com")
        assert dns.lookup("evil.com") is True

    def test_allow_list(self, dns):
        dns.block("example.com")
        assert dns.lookup("example.com") is True
        dns.allow("example.com")
        assert dns.is_allowed("example.com") is True
        assert dns.lookup("example.com") is False

    def test_persistence(self, tmp_path):
        blocklist = str(tmp_path / "blocklist.json")
        custom = str(tmp_path / "custom.json")
        dns1 = DNSFilter(blocklist_path=blocklist, custom_blocklist_path=custom)
        dns1.block("evil.com")
        dns1.block("malware.org")

        # Reload from disk
        dns2 = DNSFilter(blocklist_path=blocklist, custom_blocklist_path=custom)
        assert dns2.count() == 2
        assert dns2.lookup("evil.com") is True
        assert dns2.lookup("malware.org") is True

    def test_import_blocklist(self, dns):
        domains = ["a.com", "b.com", "c.com", "a.com"]  # dup
        added = dns.import_blocklist(domains)
        assert added == 3
        assert dns.count() == 3

    def test_domains_list_sorted(self, dns):
        dns.block("c.com")
        dns.block("a.com")
        dns.block("b.com")
        assert dns.domains() == ["a.com", "b.com", "c.com"]

    def test_stats_tracking(self, dns):
        dns.block("evil.com")
        dns.lookup("evil.com")
        dns.lookup("good.com")
        stats = dns.stats()
        assert stats["queries"] == 2
        assert stats["blocked"] == 1
        assert stats["allowed"] == 1

    def test_reset_stats(self, dns):
        dns.block("evil.com")
        dns.lookup("evil.com")
        dns.reset_stats()
        assert dns.stats()["queries"] == 0

    def test_empty_domain_ignored(self, dns):
        assert dns.block("") is False
        assert dns.block("  ") is False
        assert dns.lookup("") is False

    def test_block_ip_style_domain(self, dns):
        dns.block("192.168.1.1.evil.com")
        assert dns.lookup("192.168.1.1.evil.com") is True

    def test_many_domains(self, dns):
        for i in range(1000):
            dns.block(f"domain{i:04d}.com")
        assert dns.count() == 1000
        assert dns.lookup("domain0500.com") is True
        assert dns.lookup("domain0999.com") is True
        assert dns.lookup("domain1000.com") is False

    def test_block_ip_constant(self):
        assert BLOCK_IP == "0.0.0.0"
