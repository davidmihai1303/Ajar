"""Dataclasses shared by the whole app: Port, Device, Finding, ScanResult.

CONTRACT FILE (see AGENTS.md): changing a field here needs agreement of the analysis
and API owners, because api/schemas.py and frontend/src/api/types.ts mirror it.

Rules for these models:
* Immutable (frozen) and built only from the XML, so the same file always gives
  equal objects (NFR-05).
* Never hold a full MAC address. The parser masks it before building a Device
  (NFR-02), so nothing downstream (CSV, API, UI, logs, history) can leak it.
* Text that came from the network (banners, titles, hostnames) is untrusted. The
  parser strips control characters and limits its length, but the UI must still
  escape it (NFR-03).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ScanResult.error values. The UI maps them to Romanian / English text.
ERROR_UNREADABLE = "unreadable"   # missing, empty, truncated or not well-formed XML (e.g. V7_broken.xml)
ERROR_TOO_LARGE = "too_large"     # bigger than the configured size limit
ERROR_UNSAFE = "unsafe"           # XML entities or external references (XXE, "billion laughs")
ERROR_NOT_NMAP = "not_nmap"       # well-formed XML, but not an nmap report

ERROR_CODES = (ERROR_UNREADABLE, ERROR_TOO_LARGE, ERROR_UNSAFE, ERROR_NOT_NMAP)


@dataclass(frozen=True)
class Port:
    """One <port> of a host, whatever its state. The rules decide what counts."""

    protocol: str                 # "tcp" or "udp"
    port: int                     # 0-65535
    state: str                    # "open", "closed", "filtered", "open|filtered", ...
    service: str = ""             # nmap service name: "http", "telnet", "ms-wbt-server", ... ("" if none)
    product: str = ""             # e.g. "vsftpd", "OpenSSH"
    version: str = ""             # e.g. "2.3.4", "8.4p1 Debian 5+deb11u3"
    extrainfo: str = ""
    tunnel: str = ""              # "ssl" for HTTPS and other TLS-wrapped services, else ""
    scripts: dict = field(default_factory=dict)   # script id -> output, e.g. {"http-title": "Admin Login"}

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def http_title(self) -> str:
        return self.scripts.get("http-title", "")


@dataclass(frozen=True)
class Device:
    """One host that nmap reported as up."""

    ip: str
    mac_masked: str = ""          # "D8:43:AE:xx:xx:xx", or "" when nmap saw no MAC
    vendor: str = ""              # from the MAC prefix (OUI), "" when unknown
    hostname: str = ""
    device_type: str = "unknown"  # guess for the UI only, never used by the rules
    ports: tuple = ()             # tuple[Port, ...], sorted by (protocol, port)

    @property
    def open_ports(self) -> tuple:
        return tuple(p for p in self.ports if p.is_open)


@dataclass(frozen=True)
class Finding:
    """One row of findings.csv. Produced by analysis/rules.py, never by an LLM."""

    ip: str
    port: Optional[int]           # None for UNKNOWN_DEVICE (empty CSV column)
    protocol: str                 # "tcp" / "udp", "" when port is None
    code: str                     # catalog code, e.g. "TELNET_OPEN"
    severity: str                 # "high" / "medium" / "low" / "info"
    points: int                   # 20 / 10 / 5 / 0
    evidence: str = ""            # short proof from the scan, e.g. "tcp/2323 telnet (BusyBox telnetd)"


@dataclass(frozen=True)
class ScanResult:
    """Everything the parser read from one nmap XML file."""

    file: str                     # file name only (no folders), as written in the CSV
    devices: tuple = ()           # tuple[Device, ...], sorted by IP (numeric)
    error: Optional[str] = None   # one of ERROR_CODES, or None when the file was read
    started: Optional[int] = None  # nmap start time (Unix seconds), when present

    @property
    def ok(self) -> bool:
        return self.error is None
