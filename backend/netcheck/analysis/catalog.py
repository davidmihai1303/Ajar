"""Official finding catalog as DATA: code -> severity, points, matching services. Single source of truth."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogEntry:
    code: str
    severity: str  # lowercase: "high", "medium", "low", "info"
    points: int
    services: frozenset[str] = frozenset()
    udp_only: bool = False


# Admin title keywords (case-insensitive) for HTTP_ADMIN_CLEARTEXT
HTTP_ADMIN_KEYWORDS: tuple[str, ...] = (
    "login",
    "admin",
    "config",
    "setup",
    "router",
    "settings",
)
HTTP_ADMIN_TITLE = re.compile("|".join(map(re.escape, HTTP_ADMIN_KEYWORDS)), re.IGNORECASE | re.ASCII)

CATALOG: dict[str, CatalogEntry] = {
    "TELNET_OPEN": CatalogEntry(
        code="TELNET_OPEN",
        severity="high",
        points=20,
        services=frozenset({"telnet"}),
    ),
    "RDP_EXPOSED": CatalogEntry(
        code="RDP_EXPOSED",
        severity="high",
        points=20,
        services=frozenset({"ms-wbt-server"}),
    ),
    "VNC_EXPOSED": CatalogEntry(
        code="VNC_EXPOSED",
        severity="high",
        points=20,
        services=frozenset({"vnc"}),
    ),
    "DB_EXPOSED": CatalogEntry(
        code="DB_EXPOSED",
        severity="high",
        points=20,
        services=frozenset({"mysql", "postgresql", "redis", "mongodb"}),
    ),
    "CAMERA_STREAM_EXPOSED": CatalogEntry(
        code="CAMERA_STREAM_EXPOSED",
        severity="high",
        points=20,
        services=frozenset({"rtsp"}),
    ),
    "OUTDATED_SERVICE": CatalogEntry(
        code="OUTDATED_SERVICE",
        severity="high",
        points=20,
    ),
    "FTP_CLEARTEXT": CatalogEntry(
        code="FTP_CLEARTEXT",
        severity="medium",
        points=10,
        services=frozenset({"ftp"}),
    ),
    "HTTP_ADMIN_CLEARTEXT": CatalogEntry(
        code="HTTP_ADMIN_CLEARTEXT",
        severity="medium",
        points=10,
        services=frozenset({"http"}),
    ),
    "SMB_EXPOSED": CatalogEntry(
        code="SMB_EXPOSED",
        severity="medium",
        points=10,
        services=frozenset({"microsoft-ds", "netbios-ssn"}),
    ),
    "MQTT_EXPOSED": CatalogEntry(
        code="MQTT_EXPOSED",
        severity="medium",
        points=10,
        services=frozenset({"mqtt"}),
    ),
    "UPNP_EXPOSED": CatalogEntry(
        code="UPNP_EXPOSED",
        severity="medium",
        points=10,
        services=frozenset({"upnp"}),
        udp_only=True,
    ),
    "SNMP_EXPOSED": CatalogEntry(
        code="SNMP_EXPOSED",
        severity="medium",
        points=10,
        services=frozenset({"snmp"}),
        udp_only=True,
    ),
    "PRINTER_RAW_EXPOSED": CatalogEntry(
        code="PRINTER_RAW_EXPOSED",
        severity="low",
        points=5,
        services=frozenset({"jetdirect"}),
    ),
    "UNKNOWN_DEVICE": CatalogEntry(
        code="UNKNOWN_DEVICE",
        severity="low",
        points=5,
    ),
    "SSH_OPEN": CatalogEntry(
        code="SSH_OPEN",
        severity="info",
        points=0,
        services=frozenset({"ssh"}),
    ),
}
