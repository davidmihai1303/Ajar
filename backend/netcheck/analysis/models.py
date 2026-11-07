"""Dataclasses for analysis: Port, Device, Finding, ScanResult.

Pure data structures without dependencies on SQLite, network, or external APIs.
Contract file shared across backend analysis, API, and history.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Port:
    port: int
    protocol: str = "tcp"  # "tcp" or "udp"
    state: str = "open"    # "open", "filtered", "closed", etc.
    service_name: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""       # e.g. "ssl"
    title: str = ""        # from http-title script or banner


@dataclass
class Device:
    ip: str
    mac: str = ""          # masked or raw
    vendor: str = ""
    hostname: str = ""
    device_type: str = "unknown"
    ports: list[Port] = field(default_factory=list)


@dataclass
class Finding:
    code: str              # e.g. "HTTP_ADMIN_CLEARTEXT"
    severity: str          # "high", "medium", "low", "info"
    points: int            # 20, 10, 5, 0
    ip: str
    port: Optional[int] = None  # None for UNKNOWN_DEVICE
    evidence: str = ""


@dataclass
class ScanResult:
    scan_id: str
    file_name: str = ""
    timestamp: str = ""
    score: Optional[int] = None
    error: Optional[str] = None
    devices: list[Device] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
