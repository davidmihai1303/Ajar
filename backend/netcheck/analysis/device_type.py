"""Device-type guess (FR-03): router, camera, printer, server, pc, iot, unknown."""
from __future__ import annotations

from typing import Iterable
from netcheck.analysis.models import Port


def guess_device_type(
    ip: str,
    vendor: str = "",
    hostname: str = "",
    ports: Iterable[Port] = (),
) -> str:
    """Guess device type based on vendor, hostname, and open services."""
    v_lower = (vendor or "").lower()
    h_lower = (hostname or "").lower()
    services = {p.service_name.lower() for p in ports if p.state == "open"}
    products = " ".join(p.product.lower() for p in ports if p.state == "open")
    titles = " ".join(p.title.lower() for p in ports if p.state == "open")

    # 1. Router / Gateway
    if any(k in h_lower for k in ["router", "gateway"]):
        return "router"
    if any(k in titles for k in ["router login", "router setup", "tp-link router"]):
        return "router"
    if any(k in v_lower for k in ["tp-link", "netgear", "ubiquiti", "asus", "cisco"]):
        if any(p.port in (53, 80, 443, 1900) for p in ports if p.state == "open"):
            return "router"

    # 2. Camera / Surveillance
    if "rtsp" in services or any(k in h_lower for k in ["cam", "ipcam", "nvr"]):
        return "camera"
    if any(k in v_lower for k in ["hikvision", "dahua", "axis", "reolink", "amcrest"]):
        return "camera"

    # 3. Printer
    if "jetdirect" in services or "ipp" in services or "printer" in h_lower:
        return "printer"
    if any(k in v_lower for k in ["brother", "canon", "epson", "xerox", "lexmark"]):
        return "printer"
    if "hp" in v_lower and ("printer" in h_lower or 9100 in [p.port for p in ports]):
        return "printer"

    # 4. IoT / Smart Hub
    if "mqtt" in services or any(k in h_lower for k in ["plug", "smart", "smarthub", "sensor", "hub"]):
        return "iot"
    if any(k in v_lower for k in ["espressif", "raspberry pi", "tuya", "sonoff"]):
        return "iot"

    # 5. Server / NAS
    if any(k in h_lower for k in ["srv", "server", "nas", "db"]):
        return "server"
    if any(s in services for s in ["mysql", "postgresql", "redis", "mongodb", "microsoft-ds"]):
        return "server"
    if "synology" in v_lower or "qnap" in v_lower:
        return "server"

    # 6. Laptop / Desktop PC
    if any(k in h_lower for k in ["laptop", "desk", "pc", "macbook", "workstation"]):
        return "pc"
    if "ms-wbt-server" in services:
        return "pc"
    if any(k in v_lower for k in ["dell", "lenovo", "apple", "hp", "samsung"]):
        return "pc"

    return "unknown"
