"""Encrypted DNS — DNS over HTTPS (DoH) and DNS over TLS (DoT).

Protects DNS queries from manipulation, surveillance, and spoofing by
encrypting them before they leave the machine.

Supported providers:
  - Cloudflare (1.1.1.1) — https://cloudflare-dns.com/dns-query
  - Google (8.8.8.8) — https://dns.google/resolve
  - Quad9 (9.9.9.9) — https://dns.quad9.net/dns-query

Features:
  - DoH: DNS resolution via HTTPS POST (RFC 8484)
  - DoT: DNS resolution via TLS on port 853 (RFC 7858)
  - Response caching with TTL respect
  - Fallback to system resolver on failure
  - CLI: aegorx dns status|resolve|config|providers
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from aegorx.utils import state_dir


# ---------------------------------------------------------------------------
# DNS message construction (minimal RFC 1035)
# ---------------------------------------------------------------------------

def _build_dns_query(name: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet.

    Args:
        name: Domain name to query (e.g., "example.com")
        qtype: Query type (1=A, 28=AAAA, 5=CNAME, etc.)
    """
    # Transaction ID
    tx_id = os.urandom(2)
    # Flags: standard query, recursion desired
    flags = b"\x01\x20"
    # Questions: 1, Answer/Auth/Additional: 0
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    # QNAME
    qname = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii", errors="replace")
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"
    # QTYPE and QCLASS
    qtype_bytes = struct.pack("!HH", qtype, 1)  # 1 = IN
    return tx_id + flags + counts + qname + qtype_bytes


def _parse_dns_response(data: bytes) -> Dict:
    """Parse a DNS response packet into a simplified structure."""
    if len(data) < 12:
        return {"error": "response too short"}

    # Header
    tx_id = data[:2]
    flags = struct.unpack("!H", data[2:4])[0]
    rcode = flags & 0x0F
    qdcount = struct.unpack("!H", data[4:6])[0]
    ancount = struct.unpack("!H", data[6:8])[0]

    if rcode != 0:
        codes = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                 4: "NOTIMP", 5: "REFUSED"}
        return {"error": codes.get(rcode, f"RCODE={rcode}")}

    # Skip question section
    offset = 12
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            length = data[offset]
            if length >= 0xC0:  # compression pointer
                offset += 2
                break
            offset += 1 + length
        else:
            offset += 1  # null terminator
        offset += 4  # QTYPE + QCLASS

    # Parse answer section
    answers = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        # Name (possibly compressed)
        if data[offset] >= 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == 1 and rdlength == 4:  # A record
            answers.append({
                "type": "A",
                "data": socket.inet_ntoa(rdata),
                "ttl": ttl,
            })
        elif rtype == 28 and rdlength == 16:  # AAAA record
            answers.append({
                "type": "AAAA",
                "data": socket.inet_ntop(socket.AF_INET6, rdata),
                "ttl": ttl,
            })
        elif rtype == 5:  # CNAME
            answers.append({
                "type": "CNAME",
                "data": _decode_name(rdata, data),
                "ttl": ttl,
            })

    return {"answers": answers, "ttl": min((a["ttl"] for a in answers), default=300)}


def _decode_name(data: bytes, full: bytes) -> str:
    """Decode a DNS name from response data (handles compression)."""
    labels = []
    offset = 0
    seen = set()
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        if length >= 0xC0:  # compression pointer
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if pointer in seen:
                break  # prevent infinite loop
            seen.add(pointer)
            offset = pointer
            data = full
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels)


# ---------------------------------------------------------------------------
# DNS Cache
# ---------------------------------------------------------------------------

@dataclass
class CacheEntry:
    answers: List[Dict]
    expiry: float  # time.monotonic()


class DNSCache:
    """Simple DNS response cache with TTL respect."""

    def __init__(self, max_size: int = 1000) -> None:
        self._cache: Dict[str, CacheEntry] = {}
        self._max_size = max_size

    def get(self, key: str) -> Optional[List[Dict]]:
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.monotonic() > entry.expiry:
            del self._cache[key]
            return None
        return entry.answers

    def put(self, key: str, answers: List[Dict], ttl: int = 300) -> None:
        if len(self._cache) >= self._max_size:
            # Evict oldest
            oldest_key = min(self._cache, key=lambda k: self._cache[k].expiry)
            del self._cache[oldest_key]
        self._cache[key] = CacheEntry(
            answers=answers,
            expiry=time.monotonic() + min(ttl, 3600),  # cap at 1 hour
        )

    def clear(self) -> None:
        self._cache.clear()

    def stats(self) -> Dict[str, int]:
        return {"entries": len(self._cache), "max_size": self._max_size}


# ---------------------------------------------------------------------------
# DoH Provider
# ---------------------------------------------------------------------------

@dataclass
class DoHProvider:
    """A DNS-over-HTTPS provider."""
    name: str
    url: str
    bootstrap_ips: List[str] = field(default_factory=list)


DOH_PROVIDERS = {
    "cloudflare": DoHProvider(
        name="Cloudflare",
        url="https://cloudflare-dns.com/dns-query",
        bootstrap_ips=["1.1.1.1", "1.0.0.1"],
    ),
    "google": DoHProvider(
        name="Google",
        url="https://dns.google/resolve",
        bootstrap_ips=["8.8.8.8", "8.8.4.4"],
    ),
    "quad9": DoHProvider(
        name="Quad9",
        url="https://dns.quad9.net/dns-query",
        bootstrap_ips=["9.9.9.9", "149.112.112.112"],
    ),
}


# ---------------------------------------------------------------------------
# Encrypted DNS Resolver
# ---------------------------------------------------------------------------

class EncryptedDNS:
    """Resolve DNS queries over encrypted channels (DoH or DoT).

    Parameters
    ----------
    provider:
        DoH provider name ("cloudflare", "google", "quad9") or custom DoHProvider.
    mode:
        "doh" for DNS over HTTPS, "dot" for DNS over TLS.
    cache_size:
        Maximum number of cached DNS responses.
    timeout:
        Seconds to wait for DNS response.
    fallback:
        If True, fall back to system resolver on failure.
    """

    def __init__(
        self,
        provider: str = "cloudflare",
        mode: str = "doh",
        cache_size: int = 1000,
        timeout: int = 5,
        fallback: bool = True,
    ) -> None:
        if isinstance(provider, str):
            self._provider = DOH_PROVIDERS.get(provider)
            if self._provider is None:
                raise ValueError(f"unknown provider: {provider}")
        else:
            self._provider = provider
        self._mode = mode
        self._cache = DNSCache(max_size=cache_size)
        self._timeout = timeout
        self._fallback = fallback
        self._stats = {
            "queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "failures": 0,
            "fallbacks": 0,
        }
        self._config_path = os.path.join(state_dir(), "dns-config.json")
        self._load_config()

    def resolve(self, domain: str, qtype: int = 1) -> Dict:
        """Resolve a domain name.

        Returns dict with keys:
          - "addresses": list of IP strings
          - "source": "doh", "dot", "cache", or "fallback"
          - "ttl": seconds
        """
        self._stats["queries"] += 1
        cache_key = f"{domain}:{qtype}"

        # Check cache
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return {
                "addresses": [a["data"] for a in cached if a["type"] in ("A", "AAAA")],
                "source": "cache",
                "ttl": 0,
            }
        self._stats["cache_misses"] += 1

        # Try encrypted resolution
        try:
            if self._mode == "doh":
                result = self._resolve_doh(domain, qtype)
            else:
                result = self._resolve_dot(domain, qtype)
            # Cache the result
            if result["addresses"]:
                self._cache.put(cache_key, [{"type": "A", "data": a, "ttl": result["ttl"]} for a in result["addresses"]], result["ttl"])
            return result
        except Exception as exc:
            self._stats["failures"] += 1
            if self._fallback:
                return self._resolve_fallback(domain, qtype)
            raise

    def _resolve_doh(self, domain: str, qtype: int = 1) -> Dict:
        """Resolve via DNS over HTTPS (RFC 8484)."""
        query_packet = _build_dns_query(domain, qtype)
        # DoH uses base64url encoding of the wire format
        doh_params = base64.urlsafe_b64encode(query_packet).rstrip(b"=").decode()
        url = f"{self._provider.url}?dns={doh_params}"

        ctx = ssl.create_default_context()
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/dns-message",
                "User-Agent": "aegorx-dns/1.0",
            },
        )
        with urllib.request.urlopen(request, timeout=self._timeout, context=ctx) as resp:
            data = resp.read(4096)
        parsed = _parse_dns_response(data)
        if "error" in parsed:
            raise RuntimeError(f"DNS query failed: {parsed['error']}")
        addresses = [a["data"] for a in parsed["answers"] if a["type"] in ("A", "AAAA")]
        return {"addresses": addresses, "source": "doh", "ttl": parsed.get("ttl", 300)}

    def _resolve_dot(self, domain: str, qtype: int = 1) -> Dict:
        """Resolve via DNS over TLS (RFC 7858)."""
        query_packet = _build_dns_query(domain, qtype)
        # DoT sends raw DNS wire format over TLS on port 853
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Connect to provider's DoT server
        dot_host = self._provider.bootstrap_ips[0] if self._provider.bootstrap_ips else "1.1.1.1"
        sock = socket.create_connection((dot_host, 853), timeout=self._timeout)
        try:
            with ctx.wrap_socket(sock, server_hostname=dot_host) as ssock:
                # DoT uses length-prefixed messages
                length_prefix = struct.pack("!H", len(query_packet))
                ssock.sendall(length_prefix + query_packet)
                # Read response
                resp_len_data = ssock.recv(2)
                if len(resp_len_data) < 2:
                    raise RuntimeError("DoT response too short")
                resp_len = struct.unpack("!H", resp_len_data)[0]
                resp_data = b""
                while len(resp_data) < resp_len:
                    chunk = ssock.recv(resp_len - len(resp_data))
                    if not chunk:
                        break
                    resp_data += chunk
        finally:
            sock.close()

        parsed = _parse_dns_response(resp_data)
        if "error" in parsed:
            raise RuntimeError(f"DNS query failed: {parsed['error']}")
        addresses = [a["data"] for a in parsed["answers"] if a["type"] in ("A", "AAAA")]
        return {"addresses": addresses, "source": "dot", "ttl": parsed.get("ttl", 300)}

    def _resolve_fallback(self, domain: str, qtype: int = 1) -> Dict:
        """Fallback to system resolver."""
        self._stats["fallbacks"] += 1
        try:
            if qtype == 28:  # AAAA
                results = socket.getaddrinfo(domain, None, socket.AF_INET6)
            else:
                results = socket.getaddrinfo(domain, None, socket.AF_INET)
            addresses = [r[4][0] for r in results]
            return {"addresses": addresses, "source": "fallback", "ttl": 300}
        except socket.gaierror:
            return {"addresses": [], "source": "fallback", "ttl": 0}

    def set_provider(self, provider: str) -> None:
        """Switch to a different DoH provider."""
        if provider not in DOH_PROVIDERS:
            raise ValueError(f"unknown provider: {provider}")
        self._provider = DOH_PROVIDERS[provider]
        self._cache.clear()
        self._save_config()

    def set_mode(self, mode: str) -> None:
        """Switch between "doh" and "dot" modes."""
        if mode not in ("doh", "dot"):
            raise ValueError(f"mode must be 'doh' or 'dot', got: {mode}")
        self._mode = mode
        self._save_config()

    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def cache_stats(self) -> Dict[str, int]:
        return self._cache.stats()

    def clear_cache(self) -> None:
        self._cache.clear()

    def providers(self) -> Dict[str, str]:
        """Return available providers."""
        return {k: v.name for k, v in DOH_PROVIDERS.items()}

    def _save_config(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._config_path), exist_ok=True)
            config = {
                "provider": self._provider.name,
                "mode": self._mode,
                "timeout": self._timeout,
                "fallback": self._fallback,
            }
            fd = os.open(self._config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(config, fh, indent=2)
        except OSError:
            pass

    def _load_config(self) -> None:
        try:
            with open(self._config_path, "r") as fh:
                config = json.load(fh)
            if isinstance(config, dict):
                mode = config.get("mode")
                if mode in ("doh", "dot"):
                    self._mode = mode
                timeout = config.get("timeout")
                if isinstance(timeout, (int, float)) and 1 <= timeout <= 30:
                    self._timeout = int(timeout)
        except (OSError, json.JSONDecodeError):
            pass
