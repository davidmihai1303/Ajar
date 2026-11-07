"""Official finding catalog as DATA: code -> severity, points, matching services.

Single source of truth for all finding definitions.
Never use scattered 'if' statements to change rules.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Set


@dataclass(frozen=True)
class CatalogEntry:
    code: str
    severity: str  # "high", "medium", "low", "info"
    points: int
    matching_services: Set[str]
    description: str


CATALOG: dict[str, CatalogEntry] = {
    "TELNET_OPEN": CatalogEntry(
        code="TELNET_OPEN",
        severity="high",
        points=20,
        matching_services={"telnet"},
        description="Remote login without encryption",
    ),
    "RDP_EXPOSED": CatalogEntry(
        code="RDP_EXPOSED",
        severity="high",
        points=20,
        matching_services={"ms-wbt-server"},
        description="Remote desktop reachable",
    ),
    "VNC_EXPOSED": CatalogEntry(
        code="VNC_EXPOSED",
        severity="high",
        points=20,
        matching_services={"vnc"},
        description="Remote screen sharing reachable",
    ),
    "DB_EXPOSED": CatalogEntry(
        code="DB_EXPOSED",
        severity="high",
        points=20,
        matching_services={"mysql", "postgresql", "redis", "mongodb"},
        description="Database reachable from the network",
    ),
    "CAMERA_STREAM_EXPOSED": CatalogEntry(
        code="CAMERA_STREAM_EXPOSED",
        severity="high",
        points=20,
        matching_services={"rtsp"},
        description="Video stream reachable",
    ),
    "OUTDATED_SERVICE": CatalogEntry(
        code="OUTDATED_SERVICE",
        severity="high",
        points=20,
        matching_services=set(),
        description="Software version with known security problems",
    ),
    "FTP_CLEARTEXT": CatalogEntry(
        code="FTP_CLEARTEXT",
        severity="medium",
        points=10,
        matching_services={"ftp"},
        description="File transfer without encryption",
    ),
    "HTTP_ADMIN_CLEARTEXT": CatalogEntry(
        code="HTTP_ADMIN_CLEARTEXT",
        severity="medium",
        points=10,
        matching_services={"http"},
        description="Admin page over plain HTTP",
    ),
    "SMB_EXPOSED": CatalogEntry(
        code="SMB_EXPOSED",
        severity="medium",
        points=10,
        matching_services={"microsoft-ds", "netbios-ssn"},
        description="Windows file sharing open",
    ),
    "MQTT_EXPOSED": CatalogEntry(
        code="MQTT_EXPOSED",
        severity="medium",
        points=10,
        matching_services={"mqtt"},
        description="IoT message broker reachable",
    ),
    "UPNP_EXPOSED": CatalogEntry(
        code="UPNP_EXPOSED",
        severity="medium",
        points=10,
        matching_services={"upnp"},
        description="Device can open router ports automatically (UDP only)",
    ),
    "SNMP_EXPOSED": CatalogEntry(
        code="SNMP_EXPOSED",
        severity="medium",
        points=10,
        matching_services={"snmp"},
        description="Device management protocol reachable (UDP only)",
    ),
    "PRINTER_RAW_EXPOSED": CatalogEntry(
        code="PRINTER_RAW_EXPOSED",
        severity="low",
        points=5,
        matching_services={"jetdirect"},
        description="Anyone can send jobs to the printer",
    ),
    "UNKNOWN_DEVICE": CatalogEntry(
        code="UNKNOWN_DEVICE",
        severity="low",
        points=5,
        matching_services=set(),
        description="Device that cannot be identified",
    ),
    "SSH_OPEN": CatalogEntry(
        code="SSH_OPEN",
        severity="info",
        points=0,
        matching_services={"ssh"},
        description="Encrypted remote login, shown for awareness",
    ),
}

# Keywords for HTTP_ADMIN_CLEARTEXT detection in page title (case-insensitive)
HTTP_ADMIN_KEYWORDS: set[str] = {
    "login",
    "admin",
    "config",
    "setup",
    "router",
    "settings",
}
