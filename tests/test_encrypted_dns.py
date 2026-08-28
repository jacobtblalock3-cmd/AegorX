"""Tests for encrypted DNS (DoH/DoT)."""

from __future__ import annotations

import json
import os
import struct
import socket

import pytest

from aegorx.network.encrypted_dns import (
    EncryptedDNS,
    DNSCache,
    DoHProvider,
    DOH_PROVIDERS,
    _build_dns_query,
    _parse_dns_response,
    _decode_name,
)


# ---------------------------------------------------------------------------
# DNS message construction
# ---------------------------------------------------------------------------

class TestBuildDNSQuery:
    def test_builds_valid_packet(self):
        packet = _build_dns_query("example.com")
        assert len(packet) >= 12
        # Transaction ID (2 bytes) + Flags (2 bytes) + Counts (8 bytes)
        tx_id = packet[:2]
        flags = struct.unpack("!H", packet[2:4])[0]
        qdcount = struct.unpack("!H", packet[4:6])[0]
        assert qdcount == 1
        assert flags & 0x80 == 0  # QR bit = 0 (query)

    def test_a_record_type(self):
        packet = _build_dns_query("test.com", qtype=1)
        assert len(packet) > 12

    def test_aaaa_record_type(self):
        packet = _build_dns_query("test.com", qtype=28)
        assert len(packet) > 12


# ---------------------------------------------------------------------------
# DNS response parsing
# ---------------------------------------------------------------------------

class TestParseDNSResponse:
    def test_short_response(self):
        result = _parse_dns_response(b"\x00")
        assert "error" in result

    def test_nxdomain(self):
        # Build a response with RCODE=3 (NXDOMAIN)
        header = b"\x00\x01"  # tx_id
        flags = struct.pack("!H", 0x8183)  # QR=1, RCODE=3
        counts = struct.pack("!HHHH", 1, 0, 0, 0)  # 1 question
        question = b"\x07example\x03com\x00\x00\x01\x00\x01"  # QNAME + QTYPE + QCLASS
        result = _parse_dns_response(header + flags + counts + question)
        assert "error" in result
        assert "NXDOMAIN" in result["error"]


# ---------------------------------------------------------------------------
# DNS Cache
# ---------------------------------------------------------------------------

class TestDNSCache:
    def test_put_and_get(self):
        cache = DNSCache(max_size=10)
        cache.put("example.com:1", [{"type": "A", "data": "1.2.3.4", "ttl": 300}], 300)
        result = cache.get("example.com:1")
        assert result is not None
        assert result[0]["data"] == "1.2.3.4"

    def test_cache_miss(self):
        cache = DNSCache(max_size=10)
        result = cache.get("nonexistent.com:1")
        assert result is None

    def test_eviction(self):
        cache = DNSCache(max_size=2)
        cache.put("a.com:1", [{"type": "A", "data": "1.1.1.1", "ttl": 300}], 300)
        cache.put("b.com:1", [{"type": "A", "data": "2.2.2.2", "ttl": 300}], 300)
        cache.put("c.com:1", [{"type": "A", "data": "3.3.3.3", "ttl": 300}], 300)
        assert cache.stats()["entries"] == 2

    def test_clear(self):
        cache = DNSCache(max_size=10)
        cache.put("example.com:1", [{"type": "A", "data": "1.2.3.4", "ttl": 300}], 300)
        cache.clear()
        assert cache.get("example.com:1") is None


# ---------------------------------------------------------------------------
# DoH Provider
# ---------------------------------------------------------------------------

class TestDoHProvider:
    def test_providers_exist(self):
        assert "cloudflare" in DOH_PROVIDERS
        assert "google" in DOH_PROVIDERS
        assert "quad9" in DOH_PROVIDERS

    def test_provider_urls_are_https(self):
        for provider in DOH_PROVIDERS.values():
            assert provider.url.startswith("https://")


# ---------------------------------------------------------------------------
# EncryptedDNS
# ---------------------------------------------------------------------------

class TestEncryptedDNS:
    def test_init_cloudflare(self):
        resolver = EncryptedDNS(provider="cloudflare")
        assert resolver._provider.name == "Cloudflare"

    def test_init_google(self):
        resolver = EncryptedDNS(provider="google")
        assert resolver._provider.name == "Google"

    def test_init_quad9(self):
        resolver = EncryptedDNS(provider="quad9")
        assert resolver._provider.name == "Quad9"

    def test_init_unknown_provider(self):
        with pytest.raises(ValueError):
            EncryptedDNS(provider="unknown")

    def test_set_provider(self):
        resolver = EncryptedDNS(provider="cloudflare")
        resolver.set_provider("google")
        assert resolver._provider.name == "Google"

    def test_set_mode(self):
        resolver = EncryptedDNS(provider="cloudflare")
        resolver.set_mode("dot")
        assert resolver._mode == "dot"

    def test_set_mode_invalid(self):
        resolver = EncryptedDNS(provider="cloudflare")
        with pytest.raises(ValueError):
            resolver.set_mode("invalid")

    def test_providers_list(self):
        resolver = EncryptedDNS(provider="cloudflare")
        providers = resolver.providers()
        assert "cloudflare" in providers
        assert "google" in providers
        assert "quad9" in providers

    def test_stats(self):
        resolver = EncryptedDNS(provider="cloudflare")
        stats = resolver.stats()
        assert "queries" in stats
        assert "cache_hits" in stats
        assert "failures" in stats

    def test_cache_stats(self):
        resolver = EncryptedDNS(provider="cloudflare")
        cache = resolver.cache_stats()
        assert "entries" in cache
        assert "max_size" in cache

    def test_clear_cache(self):
        resolver = EncryptedDNS(provider="cloudflare")
        resolver.clear_cache()
        assert resolver.cache_stats()["entries"] == 0


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

class TestCLIDNSCommands:
    def test_dns_no_subcommand(self):
        from aegorx.cli import main
        result = main(["dns"])
        assert result == 3

    def test_dns_status(self):
        from aegorx.cli import main
        result = main(["dns", "status"])
        assert result == 0

    def test_dns_providers(self):
        from aegorx.cli import main
        result = main(["dns", "providers"])
        assert result == 0

    def test_dns_clear_cache(self):
        from aegorx.cli import main
        result = main(["dns", "clear-cache"])
        assert result == 0

    def test_dns_config_show(self):
        from aegorx.cli import main
        result = main(["dns", "config"])
        assert result == 0

    def test_dns_config_set_provider(self):
        from aegorx.cli import main
        result = main(["dns", "config", "--provider", "google"])
        assert result == 0

    def test_dns_config_set_mode(self):
        from aegorx.cli import main
        result = main(["dns", "config", "--mode", "dot"])
        assert result == 0
