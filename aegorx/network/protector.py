"""NetworkProtector — unified network protection manager.

Coordinates DNS filtering, connection monitoring, threat intel feeds,
and DNS enforcement into a single service that can be started/stopped
as a daemon.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Set

from aegorx.network.conn_monitor import Connection, ConnectionMonitor
from aegorx.network.dns_filter import DNSFilter
from aegorx.network.threat_feeds import update_threat_intel
from aegorx.utils import state_dir


class NetworkProtector:
    """Unified network protection service.

    Combines DNS-based domain blocking with connection monitoring,
    threat intel feed updates, and DNS enforcement (hosts file / iptables / pf).

    Parameters
    ----------
    dns_filter:
        Custom ``DNSFilter`` instance (created with defaults if None).
    conn_monitor:
        Custom ``ConnectionMonitor`` instance (created with defaults if None).
    auto_update_interval:
        Seconds between threat intel feed refreshes.  0 = disabled.
    enforce:
        Whether to enforce DNS blocking via hosts file / iptables / pf.
    scan_callback:
        Called with ``(Connection, reason)`` when suspicious connections
        are detected.  Used to feed events into the realtime monitor.
    """

    def __init__(
        self,
        dns_filter: Optional[DNSFilter] = None,
        conn_monitor: Optional[ConnectionMonitor] = None,
        auto_update_interval: float = 3600.0,
        enforce: bool = True,
        scan_callback: Optional[Callable[[Connection, str], None]] = None,
    ) -> None:
        self.dns = dns_filter or DNSFilter()
        self.monitor = conn_monitor or ConnectionMonitor(scan_callback=scan_callback)
        self.auto_update_interval = auto_update_interval
        self._enforce = enforce
        self._enforcer = None
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._started_at = 0.0
        self._feed_thread: Optional[threading.Thread] = None
        self._feed_stop = threading.Event()
        self._feed_lock = threading.Lock()
        self._updating = threading.Event()

    def _get_enforcer(self):
        if self._enforcer is None and self._enforce:
            from aegorx.network.enforcement import get_enforcer
            self._enforcer = get_enforcer()
        return self._enforcer

    def start(self) -> None:
        """Start network protection services."""
        if self._thread is not None:
            return
        self._started_at = time.time()
        self._stop_evt.clear()

        # Start connection monitoring
        self.monitor.start()

        # Apply DNS enforcement
        if self._enforce:
            enforcer = self._get_enforcer()
            if enforcer:
                enforcer.sync(self.dns.domains())

        # Start background feed updater
        if self.auto_update_interval > 0:
            self._feed_stop.clear()
            self._feed_thread = threading.Thread(
                target=self._feed_loop, daemon=True, name="aegorx-netfeed"
            )
            self._feed_thread.start()

    def _feed_loop(self) -> None:
        """Background loop to refresh threat intel feeds."""
        # Initial update on startup
        try:
            self.update_feeds()
        except Exception:
            pass

        while not self._feed_stop.wait(timeout=self.auto_update_interval):
            try:
                self.update_feeds()
            except Exception:
                pass

    def stop(self) -> None:
        """Stop all network protection services."""
        self._stop_evt.set()
        self._feed_stop.set()
        self.monitor.stop()
        with self._feed_lock:
            if self._feed_thread is not None:
                self._feed_thread.join(timeout=2.0)
                self._feed_thread = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def update_feeds(self) -> Dict:
        """Manually trigger a threat intel feed update."""
        if self._updating.is_set():
            return {"status": "already updating"}
        self._updating.set()
        try:
            result = update_threat_intel(self.dns, self.monitor)
            # Re-enforce after feed update
            if self._enforce:
                enforcer = self._get_enforcer()
                if enforcer:
                    enforcer.sync(self.dns.domains())
            return result
        finally:
            self._updating.clear()

    def check_domain(self, domain: str) -> bool:
        """Check if a domain is blocked."""
        if self.dns.is_allowed(domain):
            return False
        return self.dns.lookup(domain)

    def block_domain(self, domain: str) -> bool:
        result = self.dns.block(domain)
        if result and self._enforce:
            enforcer = self._get_enforcer()
            if enforcer:
                enforcer.sync(self.dns.domains())
        return result

    def unblock_domain(self, domain: str) -> bool:
        result = self.dns.unblock(domain)
        if result and self._enforce:
            enforcer = self._get_enforcer()
            if enforcer:
                enforcer.sync(self.dns.domains())
        return result

    def scan_connections(self) -> List[Connection]:
        """Perform a one-shot connection scan."""
        return self.monitor.scan_once()

    def enforce_status(self) -> Dict:
        """Return DNS enforcement status."""
        enforcer = self._get_enforcer()
        if enforcer is None:
            return {"active": False, "reason": "enforcement disabled"}
        return {
            "active": enforcer.is_active(),
            "type": type(enforcer).__name__,
        }

    def is_running(self) -> bool:
        return self._thread is not None or self.monitor._thread is not None

    def status(self) -> Dict:
        """Return comprehensive status dict."""
        uptime = int(time.time() - self._started_at) if self._started_at else 0
        return {
            "running": self.is_running(),
            "uptime_seconds": uptime,
            "dns_filter": {
                "blocked_domains": self.dns.count(),
                "stats": self.dns.stats(),
            },
            "connection_monitor": {
                "stats": self.monitor.stats(),
            },
            "enforcement": self.enforce_status(),
        }

    def summary_text(self) -> str:
        """Human-readable status summary."""
        status = self.status()
        running = "running" if status["running"] else "stopped"
        dns = status["dns_filter"]
        mon_stats = status["connection_monitor"]["stats"]
        enforcement = status["enforcement"]
        enforce_str = "active" if enforcement.get("active") else "inactive"
        lines = [
            f"[network] status={running} uptime={status['uptime_seconds']}s",
            f"[network] dns: blocked={dns['blocked_domains']} queries={dns['stats']['queries']} "
            f"blocked_hits={dns['stats']['blocked']}",
            f"[network] enforcement: {enforce_str} ({enforcement.get('type', 'none')})",
            f"[network] connections: scanned={mon_stats['connections_scanned']} "
            f"suspicious={mon_stats['suspicious_detected']} beacons={mon_stats['beacons_detected']}",
        ]
        return "\n".join(lines)
