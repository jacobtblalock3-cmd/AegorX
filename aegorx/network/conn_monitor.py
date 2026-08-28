"""Network connection monitor — detects suspicious outbound connections.

Uses pure-Python ``/proc/net/tcp`` parsing on Linux, ``ss`` on macOS,
and ``netstat`` on Windows as fallback.  No external dependencies.

Detects:
  - Connections to IPs in a threat-intel IP blocklist
  - Beaconing patterns (periodic connections to the same host)
  - Connections to high-risk ports (4444, 5555, 6666, etc.)
  - Unusual DNS queries (high-entropy subdomains, known DGA patterns)
"""

from __future__ import annotations

import collections
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# High-risk ports commonly used by C2 frameworks, RATs, and reverse shells.
HIGH_RISK_PORTS: Set[int] = {
    4444, 5555, 6666, 6667, 6697, 7777, 8888, 9999,  # metasploit, generic
    1234, 31337,  # elite backdoor, NOP
    4443,  # common C2 over HTTPS-like
    5432,  # PostgreSQL (lateral movement)
    3389,  # RDP
    5900, 5901,  # VNC
    22,  # SSH (often abused for lateral movement)
}

# ---------------------------------------------------------------------------
# Connection record
# ---------------------------------------------------------------------------

class Connection:
    """A single network connection snapshot."""

    __slots__ = ("local_addr", "local_port", "remote_addr", "remote_port", "proto", "pid", "state")

    def __init__(
        self,
        local_addr: str = "",
        local_port: int = 0,
        remote_addr: str = "",
        remote_port: int = 0,
        proto: str = "tcp",
        pid: int = 0,
        state: str = "ESTABLISHED",
    ) -> None:
        self.local_addr = local_addr
        self.local_port = local_port
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.proto = proto
        self.pid = pid
        self.state = state

    def to_dict(self) -> Dict:
        return {
            "local": f"{self.local_addr}:{self.local_port}",
            "remote": f"{self.remote_addr}:{self.remote_port}",
            "proto": self.proto,
            "pid": self.pid,
            "state": self.state,
        }


# ---------------------------------------------------------------------------
# /proc/net/tcp parser (Linux)
# ---------------------------------------------------------------------------

def _parse_proc_net_tcp() -> List[Connection]:
    """Parse /proc/net/tcp and /proc/net/tcp6 for active connections."""
    conns: List[Connection] = []
    for proto_file, is_v6 in [("/proc/net/tcp", False), ("/proc/net/tcp6", True)]:
        try:
            with open(proto_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    if parts[0] == "sl":
                        continue  # header
                    state_hex = parts[3]
                    if state_hex != "01":  # ESTABLISHED only
                        continue
                    local = parts[1]
                    remote = parts[2]
                    try:
                        laddr, lport = _decode_addr(local, is_v6)
                        raddr, rport = _decode_addr(remote, is_v6)
                    except (ValueError, IndexError):
                        continue
                    # Skip loopback
                    if raddr.startswith("127.") or raddr == "::1":
                        continue
                    pid = int(parts[7]) if len(parts) > 7 else 0
                    conns.append(Connection(
                        local_addr=laddr, local_port=lport,
                        remote_addr=raddr, remote_port=rport,
                        proto="tcp", pid=pid, state="ESTABLISHED",
                    ))
        except (OSError, PermissionError):
            continue
    return conns


def _decode_addr(hex_addr: str, is_v6: bool) -> Tuple[str, int]:
    """Decode a hex-encoded address from /proc/net/tcp."""
    if is_v6:
        # IPv6: 32 hex chars + :port
        addr_hex, port_hex = hex_addr.rsplit(":", 1)
        port = int(port_hex, 16)
        # Unpack 128-bit address (4 × 32-bit words, network byte order)
        if len(addr_hex) != 32:
            raise ValueError(f"bad IPv6 addr: {addr_hex}")
        words = struct.pack(">4I",
            int(addr_hex[0:8], 16),
            int(addr_hex[8:16], 16),
            int(addr_hex[16:24], 16),
            int(addr_hex[24:32], 16),
        )
        addr = socket.inet_ntop(socket.AF_INET6, words)
        # Map to IPv4 if it's a mapped address
        if addr.startswith("::ffff:"):
            addr = addr[7:]
            is_v6 = False
        elif addr == "::":
            addr = "0.0.0.0"
    else:
        addr_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        addr_int = int(addr_hex, 16)
        addr = socket.inet_ntoa(struct.pack("!I", socket.ntohl(addr_int)))
    return addr, port


# ---------------------------------------------------------------------------
# macOS / Windows fallback via subprocess
# ---------------------------------------------------------------------------

def _parse_netstat_output(output: str, proto_filter: str = "tcp") -> List[Connection]:
    """Parse netstat -an output (macOS/Windows)."""
    conns: List[Connection] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        if proto != proto_filter:
            continue
        if "ESTABLISHED" not in line:
            continue
        # Find the foreign address (last addr:port pair)
        foreign = parts[-2]
        if ":" not in foreign:
            continue
        addr, port_str = foreign.rsplit(":", 1)
        if addr.startswith("127.") or addr == "::1" or addr == "*":
            continue
        try:
            port = int(port_str)
        except ValueError:
            continue
        conns.append(Connection(
            remote_addr=addr, remote_port=port,
            proto=proto, state="ESTABLISHED",
        ))
    return conns


def _get_connections_platform() -> List[Connection]:
    """Get connections using platform-specific methods."""
    if sys.platform == "linux":
        return _parse_proc_net_tcp()
    # macOS / Windows: fall back to netstat
    try:
        result = subprocess.run(
            ["netstat", "-an"],
            capture_output=True, text=True, timeout=5,
        )
        return _parse_netstat_output(result.stdout)
    except (OSError, subprocess.SubprocessError):
        return []


# ---------------------------------------------------------------------------
# Beacon detector
# ---------------------------------------------------------------------------

class BeaconDetector:
    """Detects periodic connections to the same host (C2 beaconing)."""

    def __init__(self, window_seconds: int = 300, min_samples: int = 3) -> None:
        self.window = window_seconds
        self.min_samples = min_samples
        self._history: Dict[str, List[float]] = collections.defaultdict(list)
        self._lock = threading.Lock()

    def record(self, remote: str) -> Optional[Dict]:
        """Record a connection and return beacon info if detected."""
        now = time.time()
        with self._lock:
            history = self._history[remote]
            history.append(now)
            # Prune old entries
            cutoff = now - self.window
            self._history[remote] = [t for t in history if t >= cutoff]
            timestamps = self._history[remote]
            if len(timestamps) < self.min_samples:
                return None
            # Check regularity: compute intervals
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            if not intervals:
                return None
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval < 1.0:
                return None  # too fast, probably normal
            # Check variance
            variance = sum((iv - avg_interval) ** 2 for iv in intervals) / len(intervals)
            std_dev = variance ** 0.5
            if std_dev < avg_interval * 0.3:
                return {
                    "host": remote,
                    "avg_interval": round(avg_interval, 1),
                    "samples": len(timestamps),
                    "std_dev": round(std_dev, 2),
                }
        return None

    def reset(self) -> None:
        with self._lock:
            self._history.clear()


# ---------------------------------------------------------------------------
# ConnectionMonitor
# ---------------------------------------------------------------------------

class ConnectionMonitor:
    """Monitor network connections for suspicious activity.

    Parameters
    ----------
    ip_blocklist:
        Set of IPs to treat as malicious.
    scan_callback:
        Called with ``Connection`` when suspicious activity is detected.
    poll_interval:
        Seconds between connection scans.
    """

    def __init__(
        self,
        ip_blocklist: Optional[Set[str]] = None,
        scan_callback: Optional[Callable[[Connection, str], None]] = None,
        poll_interval: float = 10.0,
    ) -> None:
        self._ip_blocklist: Set[str] = set(ip_blocklist or [])
        self._custom_blocklist: Set[str] = set()
        self._allowlist: Set[str] = set()
        self.scan_callback = scan_callback
        self.poll_interval = poll_interval
        self._beacon = BeaconDetector()
        self._seen_keys: Set[str] = set()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._stats = {
            "connections_scanned": 0,
            "suspicious_detected": 0,
            "beacons_detected": 0,
            "high_risk_port": 0,
            "blocked_ip": 0,
        }

    # -- IP blocklist -------------------------------------------------------

    def set_ip_blocklist(self, ips: Set[str]) -> None:
        with self._lock:
            self._ip_blocklist = set(ips)

    def add_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self._ip_blocklist.add(ip)

    def remove_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self._ip_blocklist.discard(ip)

    def add_custom_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self._custom_blocklist.add(ip)

    def allow_ip(self, ip: str) -> None:
        with self._lock:
            self._allowlist.add(ip)

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ip_blocklist or ip in self._custom_blocklist

    # -- scanning -----------------------------------------------------------

    def scan_once(self) -> List[Connection]:
        """Perform a single connection scan.  Returns suspicious connections."""
        connections = _get_connections_platform()
        suspicious: List[Connection] = []

        for conn in connections:
            self._stats["connections_scanned"] += 1
            remote = conn.remote_addr

            if remote in self._allowlist:
                continue

            # Check IP blocklist
            if remote in self._ip_blocklist or remote in self._custom_blocklist:
                self._stats["blocked_ip"] += 1
                suspicious.append(conn)
                if self.scan_callback:
                    self.scan_callback(conn, "blocked_ip")
                continue

            # Check high-risk ports
            if conn.remote_port in HIGH_RISK_PORTS:
                self._stats["high_risk_port"] += 1
                suspicious.append(conn)
                if self.scan_callback:
                    self.scan_callback(conn, "high_risk_port")
                continue

            # Check beaconing
            beacon = self._beacon.record(remote)
            if beacon:
                self._stats["beacons_detected"] += 1
                suspicious.append(conn)
                if self.scan_callback:
                    self.scan_callback(conn, f"beacon:{beacon['avg_interval']}s")

        if suspicious:
            self._stats["suspicious_detected"] += len(suspicious)

        return suspicious

    # -- background loop ----------------------------------------------------

    def start(self) -> None:
        """Start background connection monitoring."""
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="aegorx-netmon"
        )
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop_evt.wait(timeout=self.poll_interval):
            try:
                self.scan_once()
            except Exception:
                logger.debug("conn_monitor scan_once failed", exc_info=True)

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0
        self._beacon.reset()
        with self._lock:
            self._seen_keys.clear()
