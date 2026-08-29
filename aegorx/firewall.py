"""Outbound firewall — blocks malware from phoning home.

Monitors and filters outbound network connections to prevent:
  - C2 (command-and-control) communication
  - Data exfiltration
  - Malware download of additional payloads
  - Connection to known malicious IPs/ports

Platform enforcement:
  Linux:   iptables OUTPUT chain rules
  macOS:   pf (packet filter) outbound rules
  Windows: Windows Firewall via netsh advfirewall

Also provides a software-level fallback that monitors the connection
table and alerts on suspicious outbound connections.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Set

from aegorx.network.conn_monitor import Connection, ConnectionMonitor


# ---------------------------------------------------------------------------
# Known malicious ports (commonly used by malware)
# ---------------------------------------------------------------------------

SUSPICIOUS_OUTBOUND_PORTS = frozenset({
    6666, 6667, 6668, 6669,   # IRC (common C2)
    4444,                      # Metasploit default
    5555,                      # Backdoor
    1337,                      # Leet / common C2
    31337,                     # Back Orifice
    12345, 12346,              # NetBus
    27374,                     # Sub7
    7777, 7778,                # Backdoor
    9999,                      # Backdoor
    1080,                      # SOCKS proxy (often abused)
    9050, 9051,                # Tor
    8333,                      # Bitcoin
    50050,                     # Malware callback
    50000,                     # SAP / malware
    443,                       # HTTPS (monitor for suspicious destinations)
    53,                        # DNS (should not be direct from apps)
})

# Well-known safe ports (whitelist for common legitimate services)
SAFE_OUTBOUND_PORTS = frozenset({
    80,    # HTTP
    443,   # HTTPS
    53,    # DNS
    22,    # SSH
    25,    # SMTP
    110,   # POP3
    143,   # IMAP
    993,   # IMAPS
    995,   # POP3S
    587,   # SMTP submission
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    27017, # MongoDB
})

# Common C2 domains (subset - in production, use threat intel feeds)
KNOWN_C2_DOMAINS = frozenset({
    "evil-c2.example.com",
    "malware-callback.example.com",
    "botnet-controller.example.com",
})


# ---------------------------------------------------------------------------
# Outbound Firewall
# ---------------------------------------------------------------------------

class OutboundFirewall:
    """Monitor and filter outbound network connections.

    Parameters
    ----------
    blocked_ips:
        IP addresses to block outbound connections to.
    blocked_ports:
        Destination ports to block.
    blocked_domains:
        Domains to resolve and block.
    alert_callback:
        Called with ``(Connection, reason)`` when a blocked connection is detected.
    poll_interval:
        Seconds between connection scans (software mode).
    strict_mode:
        If True, block ALL outbound except whitelisted ports.
        If False, only block suspicious ports + blocked IPs.
    """

    def __init__(
        self,
        blocked_ips: Optional[Set[str]] = None,
        blocked_ports: Optional[Set[int]] = None,
        blocked_domains: Optional[Set[str]] = None,
        alert_callback: Optional[Callable[[Connection, str], None]] = None,
        poll_interval: float = 5.0,
        strict_mode: bool = False,
    ) -> None:
        self.blocked_ips = set(blocked_ips or [])
        self.blocked_ports = set(blocked_ports or SUSPICIOUS_OUTBOUND_PORTS)
        self.blocked_domains = set(blocked_domains or [])
        self.alert_callback = alert_callback
        self.poll_interval = poll_interval
        self.strict_mode = strict_mode
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._monitor = ConnectionMonitor()
        self._seen: Set[str] = set()
        self._lock = threading.Lock()
        self._stats = {
            "connections_checked": 0,
            "connections_blocked": 0,
            "alerts_fired": 0,
        }

    def start(self) -> None:
        """Start outbound monitoring in background thread."""
        if self._thread is not None:
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="aegorx-firewall"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop outbound monitoring."""
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop_evt.wait(timeout=self.poll_interval):
            self.scan()

    def scan(self) -> List[Connection]:
        """Scan outbound connections and block suspicious ones."""
        conns = self._monitor.scan_once()
        blocked = []
        for conn in conns:
            self._stats["connections_checked"] += 1
            verdict = self._check_connection(conn)
            if verdict:
                self._stats["connections_blocked"] += 1
                self._stats["alerts_fired"] += 1
                blocked.append(conn)
                if self.alert_callback:
                    self.alert_callback(conn, verdict)
        return blocked

    def _check_connection(self, conn: Connection) -> Optional[str]:
        """Check a connection against block rules. Returns reason or None."""
        # Skip loopback connections
        remote = conn.remote_addr
        if remote.startswith("127.") or remote == "::1" or remote == "localhost":
            return None

        with self._lock:
            blocked_ips = self.blocked_ips.copy()
            blocked_ports = self.blocked_ports.copy()

        # Check blocked IPs
        if conn.remote_addr in blocked_ips:
            return f"blocked IP: {conn.remote_addr}"

        # Check blocked ports
        if conn.remote_port in blocked_ports:
            if conn.remote_port not in SAFE_OUTBOUND_PORTS or self.strict_mode:
                return f"suspicious port: {conn.remote_port}"

        # Check for direct DNS from non-DNS processes (port 53 from non-53)
        if conn.remote_port == 53 and conn.local_port != 53:
            return "direct DNS query from non-DNS process"

        return None

    def add_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self.blocked_ips.add(ip)

    def remove_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self.blocked_ips.discard(ip)

    def add_blocked_port(self, port: int) -> None:
        with self._lock:
            self.blocked_ports.add(port)

    def remove_blocked_port(self, port: int) -> None:
        with self._lock:
            self.blocked_ports.discard(port)

    def is_running(self) -> bool:
        return self._thread is not None

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0


# ---------------------------------------------------------------------------
# Linux: iptables outbound enforcement
# ---------------------------------------------------------------------------

class IptablesOutboundEnforcer:
    """Enforce outbound blocking rules via iptables.

    Creates a AEGORX_OUTBOUND chain that drops packets matching
    blocked IPs and ports.  Requires root.
    """

    CHAIN = "AEGORX_OUTBOUND"

    def __init__(self) -> None:
        self._active = False

    def install(self, blocked_ips: Set[str], blocked_ports: Set[int]) -> bool:
        if not self._is_root():
            return False
        try:
            self._ensure_chain()
            self._flush_chain()
            # Block specific IPs
            for ip in blocked_ips:
                subprocess.run(
                    ["iptables", "-A", self.CHAIN, "-d", ip, "-j", "DROP"],
                    capture_output=True, timeout=5,
                )
            # Block specific ports
            for port in blocked_ports:
                if port not in SAFE_OUTBOUND_PORTS:
                    subprocess.run(
                        ["iptables", "-A", self.CHAIN, "-p", "tcp", "--dport", str(port), "-j", "DROP"],
                        capture_output=True, timeout=5,
                    )
            self._active = True
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def remove(self) -> bool:
        if not self._is_root():
            return False
        try:
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-j", self.CHAIN],
                capture_output=True, timeout=5,
            )
            subprocess.run(
                ["iptables", "-X", self.CHAIN],
                capture_output=True, timeout=5,
            )
            self._active = False
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def is_active(self) -> bool:
        return self._active

    def _ensure_chain(self) -> None:
        subprocess.run(
            ["iptables", "-N", self.CHAIN],
            capture_output=True, timeout=5,
        )
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
# macOS: pf outbound enforcement
# ---------------------------------------------------------------------------

class PFOutboundEnforcer:
    """Enforce outbound blocking rules via macOS pf.

    Writes anchor rules for outbound traffic filtering.
    Requires root.
    """

    ANCHOR = "aegorx-outbound"
    PF_CONF = "/etc/pf.conf"
    ANCHOR_DIR = "/etc/pf.anchors"

    def __init__(self) -> None:
        self._anchor_path = os.path.join(self.ANCHOR_DIR, self.ANCHOR)
        self._active = False

    def install(self, blocked_ips: Set[str], blocked_ports: Set[int]) -> bool:
        if not self._is_root() or not self._is_available():
            return False
        try:
            os.makedirs(self.ANCHOR_DIR, exist_ok=True)
            rules = ["# aegorx outbound firewall\n"]
            for ip in blocked_ips:
                rules.append(f"block drop out quick on any proto from any to {ip}")
            for port in blocked_ports:
                if port not in SAFE_OUTBOUND_PORTS:
                    rules.append(f"block drop out quick on any proto from any to any port {port}")
            with open(self._anchor_path, "w") as fh:
                fh.write("\n".join(rules) + "\n")
            self._ensure_anchor_in_pf_conf()
            self._reload()
            self._active = True
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
            self._active = False
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def is_active(self) -> bool:
        return self._active

    def _ensure_anchor_in_pf_conf(self) -> None:
        try:
            with open(self.PF_CONF, "r") as fh:
                content = fh.read()
        except OSError:
            content = ""
        anchor_line = f'anchor "{self.ANCHOR}"'
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
        # Only reload the aegorx-outbound anchor, NOT the entire pf.conf
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
# Windows: netsh advfirewall outbound enforcement
# ---------------------------------------------------------------------------

class WindowsOutboundEnforcer:
    """Enforce outbound blocking rules via Windows Firewall (netsh).

    Creates outbound block rules for specific IPs and ports.
    """

    def __init__(self) -> None:
        self._active = False
        self._rule_name_prefix = "AegorX-Outbound"

    def install(self, blocked_ips: Set[str], blocked_ports: Set[int]) -> bool:
        try:
            # Block specific IPs using list args (no shell=True)
            for ip in blocked_ips:
                if not self._validate_ip(ip):
                    continue
                rule_name = f"{self._rule_name_prefix}-IP-{ip}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}", "dir=out", "action=block",
                     f"remoteip={ip}"],
                    capture_output=True, timeout=10,
                )
            # Block specific ports using list args
            for port in blocked_ports:
                if port not in SAFE_OUTBOUND_PORTS:
                    rule_name = f"{self._rule_name_prefix}-Port-{port}"
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={rule_name}", "dir=out", "action=block",
                         "protocol=tcp", f"remoteport={port}"],
                        capture_output=True, timeout=10,
                    )
            self._active = True
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def remove(self) -> bool:
        try:
            # List rules and find aegorx ones
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 "name=all", "dir=out"],
                capture_output=True, timeout=10,
            )
            for line in result.stdout.decode(errors="replace").splitlines():
                if self._rule_name_prefix in line:
                    rule_name = line.strip()
                    if rule_name:
                        subprocess.run(
                            ["netsh", "advfirewall", "firewall", "delete",
                             "rule", f"name={rule_name}"],
                            capture_output=True, timeout=10,
                        )
            self._active = False
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def is_active(self) -> bool:
        return self._active

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate that a string is a proper IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


class SinkholeOutboundEnforcer:
    """Non-root outbound blocking via hosts file sinkholing.

    Works on all platforms without elevated privileges by redirecting
    blocked domains/IPs to 0.0.0.0 in the hosts file. This is the
    fallback when kernel-level filtering is unavailable.
    """

    MARKER = "# AEGORX_BLOCK_START"
    MARKER_END = "# AEGORX_BLOCK_END"

    def __init__(self):
        self._active = False
        self._hosts_path = self._find_hosts_file()
        self._blocked: set = set()

    @staticmethod
    def _find_hosts_file() -> str:
        if sys.platform == "win32":
            return os.path.join(
                os.environ.get("SystemRoot", r"C:\Windows"),
                "System32", "drivers", "etc", "hosts",
            )
        return "/etc/hosts"

    def add_block(self, ip_or_domain: str) -> bool:
        if ip_or_domain in self._blocked:
            return True
        self._blocked.add(ip_or_domain)
        return self._flush()

    def remove_block(self, ip_or_domain: str) -> bool:
        if ip_or_domain not in self._blocked:
            return True
        self._blocked.discard(ip_or_domain)
        return self._flush()

    def clear_all(self) -> bool:
        self._blocked.clear()
        return self._flush()

    def _flush(self) -> bool:
        try:
            existing = ""
            if os.path.exists(self._hosts_path):
                with open(self._hosts_path, "r", encoding="utf-8", errors="replace") as f:
                    existing = f.read()

            # Remove old block section
            start = existing.find(self.MARKER)
            end = existing.find(self.MARKER_END)
            if start != -1 and end != -1:
                end += len(self.MARKER_END)
                while end < len(existing) and existing[end] in ("\n", "\r"):
                    end += 1
                existing = existing[:start] + existing[end:]
            elif start != -1:
                existing = existing[:start]

            # Build new block section
            if self._blocked:
                lines = [self.MARKER]
                for entry in sorted(self._blocked):
                    lines.append(f"0.0.0.0 {entry}")
                lines.append(self.MARKER_END)
                block = "\n".join(lines) + "\n"
                existing = existing.rstrip("\n") + "\n" + block

            with open(self._hosts_path, "w", encoding="utf-8") as f:
                f.write(existing)

            self._active = bool(self._blocked)
            return True
        except (OSError, PermissionError) as e:
            logger.warning("Sinkhole flush failed: %s", e)
            return False

    def is_active(self) -> bool:
        return self._active


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_outbound_enforcer():
    """Return the appropriate platform-specific outbound enforcer."""
    if sys.platform == "linux":
        if os.name == "posix" and os.geteuid() == 0 and shutil.which("iptables"):
            return IptablesOutboundEnforcer()
        return SinkholeOutboundEnforcer()
    if sys.platform == "darwin":
        enforcer = PFOutboundEnforcer()
        if enforcer._is_available():
            return enforcer
        return SinkholeOutboundEnforcer()
    if sys.platform == "win32":
        return WindowsOutboundEnforcer()
    return SinkholeOutboundEnforcer()
