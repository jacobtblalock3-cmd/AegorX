"""Platform-specific DNS enforcement for the domain blocklist.

Translates the DNSFilter blocklist into actual network blocking:

  Linux:  /etc/hosts + iptables rules (drop traffic to blocked IPs)
  macOS:  /etc/hosts + pf (packet filter) rules
  Windows: hosts file (checked by OS before DNS resolution)

All enforcement classes share a common interface:
  - install():   write blocking rules
  - remove():    remove blocking rules
  - is_active(): check if rules are in place
  - sync():      reconcile current rules with the DNSFilter blocklist
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Optional, Set

BLOCK_IP = "0.0.0.0"

# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class DNSEnforcer:
    """Base class for platform-specific DNS enforcement."""

    def install(self, domains: Set[str]) -> bool:
        raise NotImplementedError

    def remove(self) -> bool:
        raise NotImplementedError

    def is_active(self) -> bool:
        raise NotImplementedError

    def sync(self, domains: Set[str]) -> bool:
        return self.install(domains)


# ---------------------------------------------------------------------------
# /etc/hosts writer (cross-platform base)
# ---------------------------------------------------------------------------

_HOSTS_MARKER_START = "# === aegorx blocklist start ==="
_HOSTS_MARKER_END = "# === aegorx blocklist end ==="


class HostsFileEnforcer(DNSEnforcer):
    """Block domains by writing to the system hosts file.

    Works on all platforms.  Requires write access to /etc/hosts.
    Blocked domains resolve to 0.0.0.0 so connections fail immediately.
    """

    def __init__(self, hosts_path: Optional[str] = None) -> None:
        self.hosts_path = hosts_path or _default_hosts_path()

    def install(self, domains: Set[str]) -> bool:
        if not domains:
            return self.remove()
        try:
            current = self._read()
            # Remove old block
            cleaned = self._strip_block(current)
            # Build new block
            lines = sorted(f"{BLOCK_IP}  {d}" for d in sorted(domains))
            block = f"{_HOSTS_MARKER_START}\n" + "\n".join(lines) + f"\n{_HOSTS_MARKER_END}\n"
            self._write(cleaned + block)
            return True
        except (OSError, PermissionError):
            return False

    def remove(self) -> bool:
        try:
            current = self._read()
            cleaned = self._strip_block(current)
            if cleaned != current:
                self._write(cleaned)
            return True
        except (OSError, PermissionError):
            return False

    def is_active(self) -> bool:
        try:
            content = self._read()
            return _HOSTS_MARKER_START in content
        except (OSError, PermissionError):
            return False

    def _read(self) -> str:
        with open(self.hosts_path, "r", encoding="utf-8") as fh:
            return fh.read()

    def _write(self, content: str) -> None:
        parent = os.path.dirname(self.hosts_path)
        tmp = self.hosts_path + ".aegorx-tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.hosts_path)

    @staticmethod
    def _strip_block(content: str) -> str:
        """Remove the aegorx block from hosts file content."""
        lines = content.splitlines(keepends=True)
        result = []
        inside_block = False
        for line in lines:
            if line.strip() == _HOSTS_MARKER_START:
                inside_block = True
                continue
            if line.strip() == _HOSTS_MARKER_END:
                inside_block = False
                continue
            if not inside_block:
                result.append(line)
        return "".join(result)


def _default_hosts_path() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


# ---------------------------------------------------------------------------
# Linux: iptables enforcement
# ---------------------------------------------------------------------------

class IptablesEnforcer(DNSEnforcer):
    """Block connections to malicious IPs using iptables.

    Creates a custom chain ``AEGORX_BLOCK`` and inserts a DROP rule
    in the OUTPUT chain.  Domains are resolved to IPs and blocked
    individually.  Requires root.
    """

    CHAIN = "AEGORX_BLOCK"

    def install(self, domains: Set[str]) -> bool:
        if not self._is_root():
            return False
        try:
            self._ensure_chain()
            self._flush_chain()
            # Note: domain-to-IP resolution happens at sync time via dns_filter IPs
            # For domain-based blocking we rely on /etc/hosts + this chain for known IPs
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def remove(self) -> bool:
        if not self._is_root():
            return False
        try:
            # Remove jump rule from OUTPUT
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-j", self.CHAIN],
                capture_output=True, timeout=5,
            )
            # Delete chain
            subprocess.run(
                ["iptables", "-X", self.CHAIN],
                capture_output=True, timeout=5,
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def is_active(self) -> bool:
        try:
            result = subprocess.run(
                ["iptables", "-L", self.CHAIN, "-n"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0 and "DEFENTRA" in result.stdout.decode()
        except (OSError, subprocess.SubprocessError):
            return False

    def add_ip(self, ip: str) -> bool:
        """Add a single IP to the block chain."""
        if not self._is_root():
            return False
        try:
            self._ensure_chain()
            subprocess.run(
                ["iptables", "-A", self.CHAIN, "-d", ip, "-j", "DROP"],
                capture_output=True, timeout=5,
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def remove_ip(self, ip: str) -> bool:
        if not self._is_root():
            return False
        try:
            subprocess.run(
                ["iptables", "-D", self.CHAIN, "-d", ip, "-j", "DROP"],
                capture_output=True, timeout=5,
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def _ensure_chain(self) -> None:
        """Create the chain if it doesn't exist, and add jump rule."""
        subprocess.run(
            ["iptables", "-N", self.CHAIN],
            capture_output=True, timeout=5,
        )
        # Add jump rule if not already present
        check = subprocess.run(
            ["iptables", "-C", "OUTPUT", "-j", self.CHAIN],
            capture_output=True, timeout=5,
        )
        if check.returncode != 0:
            subprocess.run(
                ["iptables", "-I", "OUTPUT", "1", "-j", self.CHAIN],
                capture_output=True, timeout=5,
            )

    def _flush_chain(self) -> None:
        subprocess.run(
            ["iptables", "-F", self.CHAIN],
            capture_output=True, timeout=5,
        )

    @staticmethod
    def _is_root() -> bool:
        return os.name == "posix" and os.geteuid() == 0


# ---------------------------------------------------------------------------
# macOS: pf enforcement
# ---------------------------------------------------------------------------

class PFEnforcer(DNSEnforcer):
    """Block connections to malicious IPs using macOS packet filter (pf).

    Writes a pf anchor configuration and loads it.  Requires root.
    """

    ANCHOR = "aegorx"
    PF_CONF = "/etc/pf.conf"
    ANCHOR_DIR = "/etc/pf.anchors"

    def __init__(self) -> None:
        self._anchor_path = os.path.join(self.ANCHOR_DIR, self.ANCHOR)

    def install(self, domains: Set[str]) -> bool:
        if not self._is_root() or not self._is_available():
            return False
        try:
            os.makedirs(self.ANCHOR_DIR, exist_ok=True)
            with open(self._anchor_path, "w") as fh:
                fh.write("# aegorx blocklist anchor\n")
                fh.write("block drop quick on any proto from any to <aegorx_block>\n")
            self._ensure_anchor_in_pf_conf()
            self._reload()
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def remove(self) -> bool:
        if not self._is_root():
            return False
        try:
            if os.path.exists(self._anchor_path):
                os.unlink(self._anchor_path)
            self._remove_anchor_from_pf_conf()
            self._reload()
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def is_active(self) -> bool:
        try:
            result = subprocess.run(
                ["pfctl", "-s", "anchors"],
                capture_output=True, timeout=5,
            )
            return self.ANCHOR in result.stdout.decode()
        except (OSError, subprocess.SubprocessError):
            return False

    def add_ips_to_table(self, ips: Set[str]) -> bool:
        """Add IPs to the pf table (used by sync)."""
        if not self._is_root():
            return False
        try:
            # Flush and re-add all IPs using list args (no shell interpolation)
            subprocess.run(
                ["pfctl", "-t", "aegorx_block", "-T", "flush"],
                capture_output=True, timeout=5,
            )
            if ips:
                # Validate each IP to prevent injection
                valid_ips = [ip for ip in ips if self._validate_ip(ip)]
                if valid_ips:
                    # Add each IP individually via list args (safe from injection)
                    for ip in valid_ips:
                        subprocess.run(
                            ["pfctl", "-t", "aegorx_block", "-T", "add", ip],
                            capture_output=True, timeout=5,
                        )
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate that a string is a proper IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _ensure_anchor_in_pf_conf(self) -> None:
        """Insert anchor reference into pf.conf if not present."""
        try:
            with open(self.PF_CONF, "r") as fh:
                content = fh.read()
        except OSError:
            content = ""
        anchor_line = f"anchor \"{self.ANCHOR}\""
        if anchor_line not in content:
            with open(self.PF_CONF, "a") as fh:
                fh.write(f"\n{anchor_line}\n")

    def _remove_anchor_from_pf_conf(self) -> None:
        try:
            with open(self.PF_CONF, "r") as fh:
                lines = fh.readlines()
            with open(self.PF_CONF, "w") as fh:
                for line in lines:
                    if f'anchor "{self.ANCHOR}"' not in line:
                        fh.write(line)
        except OSError:
            pass

    def _reload(self) -> None:
        # Only reload the aegorx anchor, NOT the entire pf.conf
        # Reloading the entire pf.conf would flush ALL rules (SSH, VPN, etc.)
        subprocess.run(
            ["pfctl", "-a", self.ANCHOR, "-f", self._anchor_path],
            capture_output=True, timeout=5,
        )

    @staticmethod
    def _is_root() -> bool:
        return os.name == "posix" and os.geteuid() == 0

    @staticmethod
    def _is_available() -> bool:
        return shutil.which("pfctl") is not None


# ---------------------------------------------------------------------------
# Windows: hosts file is primary (no iptables equivalent without WFP driver)
# ---------------------------------------------------------------------------

class WindowsHostsEnforcer(HostsFileEnforcer):
    """Windows hosts file enforcement.

    Same as HostsFileEnforcer but uses the Windows hosts path.
    WFP (Windows Filtering Platform) would be the proper approach
    but requires a kernel driver.  The hosts file is the pragmatic choice.
    """

    def __init__(self) -> None:
        super().__init__(hosts_path=_default_hosts_path())


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_enforcer() -> DNSEnforcer:
    """Return the appropriate platform-specific enforcer."""
    if sys.platform == "linux":
        if os.name == "posix" and os.geteuid() == 0 and shutil.which("iptables"):
            return IptablesEnforcer()
        return HostsFileEnforcer()
    if sys.platform == "darwin":
        if os.name == "posix" and os.geteuid() == 0 and shutil.which("pfctl"):
            return PFEnforcer()
        return HostsFileEnforcer()
    if sys.platform == "win32":
        return WindowsHostsEnforcer()
    return HostsFileEnforcer()
