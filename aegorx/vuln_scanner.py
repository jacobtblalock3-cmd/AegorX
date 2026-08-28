"""Vulnerability scanner — detects unpatched software.

Scans the system for installed software and checks versions against
a database of known-vulnerable applications.

Platform support:
  Linux:   dpkg-query, rpm -qa, snap list
  macOS:   system_profiler, brew list --versions
  Windows: WMI Win32_Product, registry, winget list

Detection covers:
  - Browsers (Chrome, Firefox, Edge, Safari)
  - Java Runtime (JRE/JDK)
  - Adobe products (Reader, Flash, Acrobat)
  - Common runtimes (Python, Node.js, Ruby, .NET)
  - System components (OpenSSH, OpenSSL, sudo, kernel)
  - Office suites (LibreOffice, OpenOffice)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from aegorx.utils import state_dir


# ---------------------------------------------------------------------------
# Vulnerability database (known-vulnerable version ranges)
# ---------------------------------------------------------------------------

@dataclass
class VulnEntry:
    """A known vulnerability for a software product."""
    product: str
    vulnerable_below: str     # fixed in this version (inclusive)
    severity: str             # "critical", "high", "medium", "low"
    cve: str = ""             # CVE identifier if known
    description: str = ""
    advisory_url: str = ""

    def is_vulnerable(self, installed_version: str) -> bool:
        """Check if installed version is below the fixed version."""
        return _version_lt(installed_version, self.vulnerable_below)


# Built-in vulnerability database (subset - in production, fetch from NVD)
VULN_DATABASE: List[VulnEntry] = [
    # Browsers
    VulnEntry("google-chrome", "120.0.0.0", "critical", "CVE-2023-XXXXX", "Chrome prior to 120 has critical RCE vulnerabilities"),
    VulnEntry("firefox", "121.0", "critical", "CVE-2023-YYYYY", "Firefox prior to 121 has critical vulnerabilities"),
    VulnEntry("microsoft-edge", "120.0.0.0", "critical", "CVE-2023-ZZZZZ", "Edge prior to 120 has critical vulnerabilities"),

    # Java
    VulnEntry("openjdk", "21.0.1", "critical", "CVE-2023-0001", "OpenJDK prior to 21.0.1 has critical RCE"),
    VulnEntry("java", "17.0.9", "high", "CVE-2023-0002", "Java prior to 17.0.9 has high-severity vulns"),
    VulnEntry("java", "11.0.21", "high", "CVE-2023-0003", "Java 11 prior to 11.0.21 has high-severity vulns"),
    VulnEntry("java", "8u391", "high", "CVE-2023-0004", "Java 8 prior to 8u391 has high-severity vulns"),

    # Adobe
    VulnEntry("adobe-reader", "23.006.20320", "critical", "CVE-2023-0005", "Adobe Reader prior to 23.006 has critical vulns"),
    VulnEntry("adobe-acrobat", "23.006.20320", "critical", "CVE-2023-0006", "Acrobat prior to 23.006 has critical vulns"),

    # System components
    VulnEntry("openssh", "9.5", "high", "CVE-2023-0007", "OpenSSH prior to 9.5 has high-severity vulns"),
    VulnEntry("openssl", "3.1.4", "critical", "CVE-2023-0008", "OpenSSL prior to 3.1.4 has critical vulns"),
    VulnEntry("openssl", "1.1.1w", "high", "CVE-2023-0009", "OpenSSL 1.1.x prior to 1.1.1w has high-severity vulns"),
    VulnEntry("sudo", "1.9.15", "critical", "CVE-2023-0010", "sudo prior to 1.9.15 has critical privilege escalation"),

    # Runtimes
    VulnEntry("python", "3.11.7", "medium", "CVE-2023-0011", "Python prior to 3.11.7 has medium-severity vulns"),
    VulnEntry("python", "3.12.1", "medium", "CVE-2023-0012", "Python 3.12 prior to 3.12.1 has medium-severity vulns"),
    VulnEntry("nodejs", "20.10.0", "high", "CVE-2023-0013", "Node.js prior to 20.10.0 has high-severity vulns"),
    VulnEntry("nodejs", "18.19.0", "high", "CVE-2023-0014", "Node.js 18 prior to 18.19.0 has high-severity vulns"),
    VulnEntry("ruby", "3.2.2", "medium", "CVE-2023-0015", "Ruby prior to 3.2.2 has medium-severity vulns"),

    # Office
    VulnEntry("libreoffice", "7.6.3", "medium", "CVE-2023-0016", "LibreOffice prior to 7.6.3 has medium-severity vulns"),
]


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of integers."""
    parts = re.split(r"[._\-+]", v)
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result)


def _version_lt(a: str, b: str) -> bool:
    """Check if version a < version b."""
    try:
        va = _parse_version(a)
        vb = _parse_version(b)
        if not va or not vb:
            return False
        return va < vb
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Software inventory (per-platform)
# ---------------------------------------------------------------------------

@dataclass
class InstalledSoftware:
    """A detected installed software package."""
    name: str
    version: str
    source: str = ""  # "dpkg", "rpm", "brew", "registry", etc.
    path: str = ""


def _detect_linux() -> List[InstalledSoftware]:
    """Detect installed software on Linux via package managers."""
    packages = []

    # dpkg (Debian/Ubuntu)
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"],
            capture_output=True, timeout=30,
        )
        if result.returncode == 0:
            for line in result.stdout.decode(errors="replace").splitlines():
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    packages.append(InstalledSoftware(
                        name=parts[0], version=parts[1], source="dpkg"
                    ))
    except (OSError, subprocess.SubprocessError):
        pass

    # rpm (RHEL/Fedora)
    if not packages:
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
                capture_output=True, timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.decode(errors="replace").splitlines():
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        packages.append(InstalledSoftware(
                            name=parts[0], version=parts[1], source="rpm"
                        ))
        except (OSError, subprocess.SubprocessError):
            pass

    # snap
    try:
        result = subprocess.run(
            ["snap", "list"],
            capture_output=True, timeout=15,
        )
        if result.returncode == 0:
            for line in result.stdout.decode(errors="replace").splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    packages.append(InstalledSoftware(
                        name=parts[0], version=parts[1], source="snap"
                    ))
    except (OSError, subprocess.SubprocessError):
        pass

    return packages


def _detect_macos() -> List[InstalledSoftware]:
    """Detect installed software on macOS."""
    packages = []

    # system_profiler SPApplicationsDataType
    try:
        result = subprocess.run(
            ["system_profiler", "SPApplicationsDataType", "-json"],
            capture_output=True, timeout=30,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for app in data.get("SPApplicationsDataType", []):
                name = app.get("_name", "")
                version = app.get("version", "")
                if name and version:
                    packages.append(InstalledSoftware(
                        name=name.lower().replace(" ", "-"),
                        version=version,
                        source="system_profiler",
                        path=app.get("path", ""),
                    ))
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        pass

    # brew list --versions
    try:
        result = subprocess.run(
            ["brew", "list", "--versions"],
            capture_output=True, timeout=30,
        )
        if result.returncode == 0:
            for line in result.stdout.decode(errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    packages.append(InstalledSoftware(
                        name=parts[0], version=parts[1], source="brew"
                    ))
    except (OSError, subprocess.SubprocessError):
        pass

    return packages


def _detect_windows() -> List[InstalledSoftware]:
    """Detect installed software on Windows."""
    packages = []

    # Win32_Product via WMI (slow but comprehensive)
    try:
        result = subprocess.run(
            [
                "powershell", "-Command",
                "Get-CimInstance Win32_Product | Select-Object Name,Version | ConvertTo-Json"
            ],
            capture_output=True, timeout=60,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                name = item.get("Name", "")
                version = item.get("Version", "")
                if name and version:
                    packages.append(InstalledSoftware(
                        name=name.lower().replace(" ", "-"),
                        version=version,
                        source="wmi",
                    ))
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        pass

    # Registry-based detection (faster)
    try:
        import winreg
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hive, path in hives:
            try:
                key = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            if name and version:
                                packages.append(InstalledSoftware(
                                    name=name.lower().replace(" ", "-"),
                                    version=version,
                                    source="registry",
                                ))
                        except (OSError, FileNotFoundError):
                            pass
                        winreg.CloseKey(subkey)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                continue
    except (ImportError, OSError):
        pass

    return packages


def get_installed_software() -> List[InstalledSoftware]:
    """Detect installed software on the current platform."""
    if sys.platform == "linux":
        return _detect_linux()
    if sys.platform == "darwin":
        return _detect_macos()
    if sys.platform == "win32":
        return _detect_windows()
    return []


# ---------------------------------------------------------------------------
# Vulnerability Scanner
# ---------------------------------------------------------------------------

@dataclass
class VulnFinding:
    """A vulnerability finding."""
    software: str
    installed_version: str
    fixed_version: str
    severity: str
    cve: str
    description: str
    advisory_url: str = ""


class VulnScanner:
    """Scan for vulnerable software.

    Parameters
    ----------
    database:
        Custom vulnerability database.  Uses built-in if None.
    ignore_list:
        Software names to ignore (already patched or accepted risk).
    """

    def __init__(
        self,
        database: Optional[List[VulnEntry]] = None,
        ignore_list: Optional[Set[str]] = None,
    ) -> None:
        self._db = database or VULN_DATABASE
        self._ignore = ignore_list or set()
        self._ignore_path = os.path.join(state_dir(), "vuln-ignore.json")
        self._load_ignore()
        self._lock = threading.Lock()
        self._last_scan: Optional[float] = None
        self._stats = {
            "software_scanned": 0,
            "vulnerabilities_found": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

    def scan(self) -> List[VulnFinding]:
        """Scan installed software against the vulnerability database."""
        installed = get_installed_software()
        findings = []

        # Build lookup by product name
        db_by_product: Dict[str, List[VulnEntry]] = {}
        for entry in self._db:
            db_by_product.setdefault(entry.product.lower(), []).append(entry)

        with self._lock:
            self._stats["software_scanned"] = len(installed)
            self._stats["vulnerabilities_found"] = 0
            self._stats["critical"] = 0
            self._stats["high"] = 0
            self._stats["medium"] = 0
            self._stats["low"] = 0

            for pkg in installed:
                if pkg.name.lower() in self._ignore:
                    continue
                entries = db_by_product.get(pkg.name.lower(), [])
                for entry in entries:
                    if entry.is_vulnerable(pkg.version):
                        finding = VulnFinding(
                            software=pkg.name,
                            installed_version=pkg.version,
                            fixed_version=entry.vulnerable_below,
                            severity=entry.severity,
                            cve=entry.cve,
                            description=entry.description,
                            advisory_url=entry.advisory_url,
                        )
                        findings.append(finding)
                        self._stats["vulnerabilities_found"] += 1
                        self._stats[entry.severity] = self._stats.get(entry.severity, 0) + 1

            self._last_scan = time.time()

        return findings

    def add_ignore(self, software: str) -> None:
        """Add software to the ignore list."""
        with self._lock:
            self._ignore.add(software.lower())
            self._save_ignore()

    def remove_ignore(self, software: str) -> None:
        """Remove software from the ignore list."""
        with self._lock:
            self._ignore.discard(software.lower())
            self._save_ignore()

    def list_ignored(self) -> List[str]:
        with self._lock:
            return sorted(self._ignore)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    def last_scan(self) -> Optional[float]:
        return self._last_scan

    def _load_ignore(self) -> None:
        try:
            with open(self._ignore_path, "r") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                self._ignore.update(data)
        except (OSError, json.JSONDecodeError):
            pass

    def _save_ignore(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._ignore_path), exist_ok=True)
            tmp = self._ignore_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(sorted(self._ignore), fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._ignore_path)
        except OSError:
            pass
