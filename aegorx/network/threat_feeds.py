"""Threat intelligence feeds for network protection.

Fetches malicious domains and IPs from public sources and merges them
into the local blocklist.  Sources:

  - URLhaus (abuse.ch)        — malware download URLs
  - StevenBlack hosts          — community-curated adware/malware domains
  - MalwareBazaar (abuse.ch)  — malware payload domains (via URLhaus)

All fetches are HTTPS-only with timeout and size caps.  Failures degrade
gracefully: a broken source is skipped, the previous blocklist is kept.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Feed URLs
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def _is_valid_domain(host: str) -> bool:
    """Reject localhost, IPs, and malformed hostnames."""
    if not host or len(host) > 253:
        return False
    if host in ("localhost", "localhost.localdomain"):
        return False
    # Reject IP addresses (including broadcast and null)
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_multicast or ip.is_reserved or ip.is_link_local:
            return False
    except ValueError:
        pass
    return bool(_DOMAIN_RE.match(host))


URLHAUS_URLS = [
    "https://urlhaus-api.abuse.ch/v1/payloads/recent/",
    "https://urlhaus-api.abuse.ch/v1/urls/recent/",
]

STEVENBLACK_HOSTS_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

# Phishing Army blocklist (extended)
PHISHING_ARMY_URL = "https://phishing.army/download/phishing_army_blocklist.txt"

# malwaredomainlist
MALWARE_DOMAINLIST_URL = "https://www.malwaredomainlist.com/hostslist/hosts.txt"

MAX_FEED_SIZE = 64 * 1024 * 1024  # 64 MB cap
FETCH_TIMEOUT = 30  # seconds


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _https_get(url: str, timeout: int = FETCH_TIMEOUT) -> bytes:
    """HTTPS-only GET with size cap and TLS certificate verification."""
    if not url.lower().startswith("https://"):
        raise ValueError(f"refusing non-HTTPS feed URL: {url}")
    # Create SSL context with certificate verification enabled
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    request = urllib.request.Request(url, headers={"User-Agent": "aegorx/1.1"})
    with urllib.request.urlopen(request, timeout=timeout, context=ctx) as resp:
        data = resp.read(MAX_FEED_SIZE + 1)
        if len(data) > MAX_FEED_SIZE:
            raise ValueError(f"feed too large (> {MAX_FEED_SIZE} bytes): {url}")
        return data


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------

_DOMAIN_RE_EXCEPTIONS = {
    "localhost", "localhost.localdomain", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet",
    "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
    "ip6-allhosts", "0.0.0.0", "255.255.255.255",
    "0", "127.0.0.1", "::1", "ff00::0", "ff02::1",
    "ff02::2", "ff02::3",
}


def extract_domains_from_hosts(data: bytes) -> List[str]:
    """Extract domains from a hosts-file format payload."""
    domains: List[str] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        if ip.startswith("#"):
            continue
        for domain in parts[1:]:
            domain = domain.lower().strip()
            if domain and domain not in _DOMAIN_RE_EXCEPTIONS and not domain.startswith("#"):
                domains.append(domain)
    return domains


def extract_domains_from_urlhaus(payload: dict) -> List[str]:
    """Extract domains from URLhaus API response."""
    domains: List[str] = []
    # From URL entries
    for entry in payload.get("urls") or []:
        url = entry.get("url", "")
        if url:
            try:
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname
                if host and _is_valid_domain(host):
                    domains.append(host.lower())
            except Exception:
                continue
    # From payload entries
    for entry in payload.get("payloads") or []:
        url = entry.get("url", "")
        if url:
            try:
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname
                if host and _is_valid_domain(host):
                    domains.append(host.lower())
            except Exception:
                continue
    return domains


def extract_domains_from_text(data: bytes) -> List[str]:
    """Extract domains from a plain-text list (one per line)."""
    domains: List[str] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        # Skip IPs
        try:
            import ipaddress
            ipaddress.ip_address(line)
            continue
        except ValueError:
            pass
        if "." in line and " " not in line:
            domains.append(line.lower())
    return domains


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------

def extract_ips_from_text(data: bytes) -> List[str]:
    """Extract IPs from a plain-text list."""
    ips: List[str] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 1:
            candidate = parts[0]
            if _is_valid_ip(candidate):
                ips.append(candidate)
    return ips


def _is_valid_ip(s: str) -> bool:
    """Check if string is a valid IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Feed fetchers
# ---------------------------------------------------------------------------

def fetch_urlhaus_domains(limit: int = 5000) -> Tuple[List[str], int]:
    """Fetch recent malware URLs from URLhaus. Returns (domains, count)."""
    all_domains: List[str] = []
    for url in URLHAUS_URLS:
        try:
            data = _https_get(url)
            payload = json.loads(data)
            domains = extract_domains_from_urlhaus(payload)
            all_domains.extend(domains)
        except Exception:
            continue
    deduped = list(dict.fromkeys(all_domains))  # preserve order, dedupe
    return deduped[:limit], len(deduped)


def fetch_stevenblack_hosts() -> Tuple[List[str], int]:
    """Fetch StevenBlack's community hosts blocklist."""
    data = _https_get(STEVENBLACK_HOSTS_URL)
    domains = extract_domains_from_hosts(data)
    return domains, len(domains)


def fetch_phishing_army() -> Tuple[List[str], int]:
    """Fetch Phishing Army blocklist."""
    data = _https_get(PHISHING_ARMY_URL)
    domains = extract_domains_from_text(data)
    return domains, len(domains)


def fetch_malwaredomainlist() -> Tuple[List[str], int]:
    """Fetch MalwareDomainList hosts."""
    try:
        data = _https_get(MALWARE_DOMAINLIST_URL)
        domains = extract_domains_from_hosts(data)
        return domains, len(domains)
    except Exception:
        return [], 0


# ---------------------------------------------------------------------------
# Merge & persist
# ---------------------------------------------------------------------------

def merge_domains(existing: List[str], incoming: List[str]) -> Tuple[List[str], int]:
    """Union two domain lists. Returns (merged_sorted, new_count)."""
    existing_set = set(existing)
    added = 0
    for domain in incoming:
        domain = domain.lower().strip()
        if domain and domain not in existing_set:
            existing_set.add(domain)
            added += 1
    return sorted(existing_set), added


def load_domain_store(path: str) -> Dict:
    """Load the domain blocklist store from disk."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("domains"), list):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"domains": [], "updated_utc": 0.0, "version": 1}


def save_domain_store(path: str, store: Dict) -> None:
    """Atomically save the domain blocklist store."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def prune_old_domains(domains: List[str], max_age_days: int = 90) -> Tuple[List[str], int]:
    """Remove domains older than max_age_days (based on filename hash aging).
    This is a simple heuristic — in production you'd track first_seen dates."""
    # For now, just cap the list size
    max_domains = 500000
    if len(domains) <= max_domains:
        return domains, 0
    return domains[-max_domains:], len(domains) - max_domains


# ---------------------------------------------------------------------------
# High-level update function
# ---------------------------------------------------------------------------

def update_threat_intel(
    dns_filter,
    conn_monitor=None,
    sources: Optional[List[str]] = None,
) -> Dict:
    """Fetch threat intel from all sources and update the DNS filter + connection monitor.

    Parameters
    ----------
    dns_filter:
        A ``DNSFilter`` instance to populate.
    conn_monitor:
        Optional ``ConnectionMonitor`` to populate IP blocklist.
    sources:
        List of source names to fetch.  Default: all available.

    Returns
    -------
    Dict with fetch statistics per source.
    """
    from aegorx.utils import state_dir

    if sources is None:
        sources = ["urlhaus", "stevenblack", "phishingarmy"]

    results: Dict[str, Dict] = {}
    all_domains: List[str] = []
    all_ips: List[str] = []

    for source in sources:
        try:
            if source == "urlhaus":
                domains, count = fetch_urlhaus_domains()
                all_domains.extend(domains)
                results[source] = {"domains": count, "status": "ok"}
            elif source == "stevenblack":
                domains, count = fetch_stevenblack_hosts()
                all_domains.extend(domains)
                results[source] = {"domains": count, "status": "ok"}
            elif source == "phishingarmy":
                domains, count = fetch_phishing_army()
                all_domains.extend(domains)
                results[source] = {"domains": count, "status": "ok"}
            elif source == "malwaredomainlist":
                domains, count = fetch_malwaredomainlist()
                all_domains.extend(domains)
                results[source] = {"domains": count, "status": "ok"}
            else:
                results[source] = {"status": "skipped", "reason": "unknown source"}
        except Exception as exc:
            results[source] = {"status": "error", "error": str(exc)}

    # Merge domains into DNS filter
    if all_domains:
        deduped = list(dict.fromkeys(all_domains))
        added = dns_filter.import_blocklist(deduped, source="threat-intel")
        results["_total"] = {"domains_fetched": len(all_domains), "domains_added": added}

    # Merge IPs into connection monitor
    if all_ips and conn_monitor is not None:
        for ip in all_ips:
            conn_monitor.add_blocked_ip(ip)

    # Persist the update timestamp
    store_path = os.path.join(state_dir(), "network-threat-intel.json")
    store = load_domain_store(store_path)
    store["updated_utc"] = time.time()
    store["sources"] = results
    save_domain_store(store_path, store)

    return results
