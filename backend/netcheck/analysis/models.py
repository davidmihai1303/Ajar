"""Dataclasses: Port, Device, Finding, ScanResult (ScanResult.error set for unreadable files)."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Port:
    portid: int
    protocol: str  # "tcp" | "udp"
    state: str     # "open", "closed", "filtered", etc.
    service_name: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""  # "ssl" when encrypted
    http_title: str = ""


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    ports: list[Port] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    file: str
    ip: str
    port: int | None  # None for UNKNOWN_DEVICE
    finding_code: str
    severity: str  # lowercase: "high", "medium", "low", "info"
    points: int = 0
    evidence: str = ""


@dataclass
class ScanResult:
    file: str
    devices: list[Device] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int | None = None  # None if error=True
    error: bool = False
