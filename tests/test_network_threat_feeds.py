"""Tests for threat intelligence feed fetching and merging."""

from __future__ import annotations

import json
import os

import pytest

from aegorx.network.threat_feeds import (
    extract_domains_from_hosts,
    extract_domains_from_urlhaus,
    extract_domains_from_text,
    extract_ips_from_text,
    merge_domains,
    load_domain_store,
    save_domain_store,
    prune_old_domains,
    _is_valid_ip,
)


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------

class TestExtractDomainsFromHosts:
    def test_standard_hosts_file(self):
        data = b"""127.0.0.1 localhost
0.0.0.0 evil.com
0.0.0.0 malware.org
0.0.0.0 ads.tracker.com
# comment line
"""
        domains = extract_domains_from_hosts(data)
        assert "evil.com" in domains
        assert "malware.org" in domains
        assert "ads.tracker.com" in domains
        assert "localhost" not in domains

    def test_empty_file(self):
        assert extract_domains_from_hosts(b"") == []

    def test_all_comments(self):
        data = b"# this is a comment\n# another comment\n"
        assert extract_domains_from_hosts(data) == []

    def test_preserves_order(self):
        data = b"0.0.0.0 alpha.com\n0.0.0.0 beta.com\n0.0.0.0 gamma.com\n"
        domains = extract_domains_from_hosts(data)
        assert domains == ["alpha.com", "beta.com", "gamma.com"]


class TestExtractDomainsFromUrlhaus:
    def test_urls_response(self):
        payload = {
            "urls": [
                {"url": "https://evil.com/malware.exe"},
                {"url": "https://malware.org/payload.bin"},
            ]
        }
        domains = extract_domains_from_urlhaus(payload)
        assert "evil.com" in domains
        assert "malware.org" in domains

    def test_payloads_response(self):
        payload = {
            "payloads": [
                {"url": "http://download.bad.com/trojan"},
            ]
        }
        domains = extract_domains_from_urlhaus(payload)
        assert "download.bad.com" in domains

    def test_empty_response(self):
        assert extract_domains_from_urlhaus({}) == []
        assert extract_domains_from_urlhaus({"urls": None}) == []


class TestExtractDomainsFromText:
    def test_plain_list(self):
        data = b"evil.com\nmalware.org\n# comment\nphishing.net\n"
        domains = extract_domains_from_text(data)
        assert "evil.com" in domains
        assert "malware.org" in domains
        assert "phishing.net" in domains

    def test_skips_ips(self):
        data = b"192.168.1.1\nevil.com\n"
        domains = extract_domains_from_text(data)
        assert "evil.com" in domains
        assert "192.168.1.1" not in domains

    def test_empty(self):
        assert extract_domains_from_text(b"") == []


class TestExtractIpsFromText:
    def test_valid_ips(self):
        data = b"10.0.0.1\n192.168.1.1\nnot-an-ip\n8.8.8.8\n"
        ips = extract_ips_from_text(data)
        assert ips == ["10.0.0.1", "192.168.1.1", "8.8.8.8"]

    def test_empty(self):
        assert extract_ips_from_text(b"") == []


# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------

class TestIsValidIp:
    def test_valid(self):
        assert _is_valid_ip("0.0.0.0") is True
        assert _is_valid_ip("255.255.255.255") is True
        assert _is_valid_ip("192.168.1.1") is True

    def test_invalid(self):
        assert _is_valid_ip("256.0.0.1") is False
        assert _is_valid_ip("abc") is False
        assert _is_valid_ip("") is False
        assert _is_valid_ip("192.168.1") is False


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

class TestMergeDomains:
    def test_basic_merge(self):
        existing = ["a.com", "b.com"]
        incoming = ["b.com", "c.com"]
        merged, added = merge_domains(existing, incoming)
        assert merged == ["a.com", "b.com", "c.com"]
        assert added == 1

    def test_empty_existing(self):
        merged, added = merge_domains([], ["a.com", "b.com"])
        assert merged == ["a.com", "b.com"]
        assert added == 2

    def test_empty_incoming(self):
        merged, added = merge_domains(["a.com"], [])
        assert merged == ["a.com"]
        assert added == 0

    def test_case_normalization(self):
        merged, added = merge_domains([], ["Evil.COM", "evil.com"])
        assert len(merged) == 1
        assert added == 1

    def test_sorted_output(self):
        merged, _ = merge_domains([], ["z.com", "a.com", "m.com"])
        assert merged == ["a.com", "m.com", "z.com"]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

class TestDomainStorePersistence:
    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "store.json")
        store = {"domains": ["a.com", "b.com"], "updated_utc": 100.0, "version": 1}
        save_domain_store(path, store)
        loaded = load_domain_store(path)
        assert loaded["domains"] == ["a.com", "b.com"]
        assert loaded["updated_utc"] == 100.0

    def test_load_missing_file(self, tmp_path):
        loaded = load_domain_store(str(tmp_path / "nonexistent.json"))
        assert loaded["domains"] == []
        assert loaded["version"] == 1

    def test_load_corrupt_file(self, tmp_path):
        path = str(tmp_path / "corrupt.json")
        with open(path, "w") as f:
            f.write("not json!!!")
        loaded = load_domain_store(path)
        assert loaded["domains"] == []

    def test_atomic_write(self, tmp_path):
        path = str(tmp_path / "atomic.json")
        save_domain_store(path, {"domains": ["a.com"]})
        assert os.path.exists(path)
        assert not os.path.exists(path + ".tmp")


# ---------------------------------------------------------------------------
# Pruning
# ---------------------------------------------------------------------------

class TestPruneOldDomains:
    def test_under_limit(self):
        domains = [f"d{i}.com" for i in range(100)]
        pruned, removed = prune_old_domains(domains, max_age_days=90)
        assert len(pruned) == 100
        assert removed == 0

    def test_over_limit(self):
        domains = [f"d{i}.com" for i in range(600000)]
        pruned, removed = prune_old_domains(domains, max_age_days=90)
        assert len(pruned) == 500000
        assert removed == 100000
