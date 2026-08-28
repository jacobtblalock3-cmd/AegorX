"""Tests for DNS enforcement (hosts file writer)."""

from __future__ import annotations

import os

import pytest

from aegorx.network.enforcement import (
    HostsFileEnforcer,
    _HOSTS_MARKER_START,
    _HOSTS_MARKER_END,
    BLOCK_IP,
)


@pytest.fixture()
def enforcer(tmp_path):
    hosts_path = str(tmp_path / "hosts")
    with open(hosts_path, "w") as fh:
        fh.write("127.0.0.1 localhost\n")
    return HostsFileEnforcer(hosts_path=hosts_path)


class TestHostsFileEnforcer:
    def test_install_adds_domains(self, enforcer):
        enforcer.install({"evil.com", "malware.org"})
        content = open(enforcer.hosts_path).read()
        assert "evil.com" in content
        assert "malware.org" in content
        assert BLOCK_IP in content
        assert _HOSTS_MARKER_START in content
        assert _HOSTS_MARKER_END in content

    def test_install_preserves_existing_hosts(self, enforcer):
        enforcer.install({"evil.com"})
        content = open(enforcer.hosts_path).read()
        assert "127.0.0.1 localhost" in content

    def test_remove_cleans_block(self, enforcer):
        enforcer.install({"evil.com"})
        assert enforcer.is_active()
        enforcer.remove()
        content = open(enforcer.hosts_path).read()
        assert "evil.com" not in content
        assert _HOSTS_MARKER_START not in content
        assert "127.0.0.1 localhost" in content

    def test_is_active(self, enforcer):
        assert not enforcer.is_active()
        enforcer.install({"test.com"})
        assert enforcer.is_active()

    def test_install_empty_removes_block(self, enforcer):
        enforcer.install({"evil.com"})
        enforcer.install(set())
        assert not enforcer.is_active()

    def test_idempotent_install(self, enforcer):
        enforcer.install({"a.com", "b.com"})
        enforcer.install({"a.com", "b.com", "c.com"})
        content = open(enforcer.hosts_path).read()
        assert content.count("a.com") == 1
        assert content.count("c.com") == 1

    def test_reinstall_updates_domains(self, enforcer):
        enforcer.install({"old.com"})
        enforcer.install({"new.com"})
        content = open(enforcer.hosts_path).read()
        assert "old.com" not in content
        assert "new.com" in content

    def test_many_domains(self, enforcer):
        domains = {f"evil{i:04d}.com" for i in range(100)}
        enforcer.install(domains)
        content = open(enforcer.hosts_path).read()
        assert content.count("evil") == 100
        enforcer.remove()
        content = open(enforcer.hosts_path).read()
        assert "evil" not in content


class TestEnforcementIntegration:
    def test_network_protector_enforces(self, tmp_path):
        from aegorx.network.dns_filter import DNSFilter
        from aegorx.network.protector import NetworkProtector

        hosts_path = str(tmp_path / "hosts")
        with open(hosts_path, "w") as fh:
            fh.write("127.0.0.1 localhost\n")

        dns = DNSFilter(
            blocklist_path=str(tmp_path / "blocklist.json"),
            custom_blocklist_path=str(tmp_path / "custom.json"),
        )
        protector = NetworkProtector(
            dns_filter=dns,
            enforce=False,  # skip platform enforcer in test
        )
        protector.block_domain("evil.com")
        assert protector.check_domain("evil.com") is True
