"""Evaluate the official catalog against the evidence for each scanned IP."""
import ipaddress
from collections import defaultdict
from collections.abc import Iterable

from .catalog import CATALOG, HTTP_ADMIN_KEYWORDS, CatalogEntry
from .models import Device, Finding, Port
from .versions import is_outdated_service


_SERVICE_TO_ENTRY = {service: entry for entry in CATALOG.values() for service in entry.services}


def _port_finding(ip: str, port: Port, entry: CatalogEntry, evidence: str) -> Finding:
    return Finding(ip=ip, port=port.port, protocol=port.protocol, code=entry.code,
                   severity=entry.severity, points=entry.points, evidence=evidence)


def _findings_for_ip(ip: str, devices: list[Device]) -> list[Finding]:
    # Repeated host records belong to the same IP. Prefer TCP evidence when both
    # transports would produce the same CSV row (the CSV has no protocol column).
    ports = sorted((p for device in devices for p in device.open_ports),
                   key=lambda p: (p.port, p.protocol))
    findings: dict[tuple[int, str], Finding] = {}
    smb_ports: list[Port] = []
    for port in ports:
        entry = _SERVICE_TO_ENTRY.get(port.service.lower())
        evidence = f"{port.protocol}/{port.port} {port.service}"
        if entry and (not entry.udp_only or port.protocol == "udp"):
            if entry.code == "SMB_EXPOSED":
                smb_ports.append(port)
            elif entry.code == "HTTP_ADMIN_CLEARTEXT":
                if port.tunnel.lower() != "ssl" and any(word in port.http_title.lower() for word in HTTP_ADMIN_KEYWORDS):
                    findings.setdefault((port.port, entry.code),
                                        _port_finding(ip, port, entry, f"{evidence}: {port.http_title}"))
            else:
                findings.setdefault((port.port, entry.code), _port_finding(ip, port, entry, evidence))

        if is_outdated_service(port.service, port.product, port.version):
            entry = CATALOG["OUTDATED_SERVICE"]
            findings.setdefault((port.port, entry.code),
                                _port_finding(ip, port, entry, f"{evidence}: {port.product} {port.version}"))

    if smb_ports:
        port = min(smb_ports, key=lambda p: (p.port != 445, p.port != 139, p.port, p.protocol))
        entry = CATALOG["SMB_EXPOSED"]
        findings[port.port, entry.code] = _port_finding(ip, port, entry, f"{port.protocol}/{port.port} {port.service}")

    result = [findings[key] for key in sorted(findings)]
    if ports and not any(device.vendor.strip() or device.hostname.strip() for device in devices):
        entry = CATALOG["UNKNOWN_DEVICE"]
        result.append(Finding(ip=ip, port=None, protocol="", code=entry.code, severity=entry.severity,
                              points=entry.points, evidence="Open port observed without a vendor or hostname"))
    return result


def evaluate_device(device: Device) -> list[Finding]:
    return _findings_for_ip(device.ip, [device])


def evaluate_devices(devices: Iterable[Device]) -> list[Finding]:
    """Return one finding per (IP, port, code) in the order required by findings.csv."""
    by_ip: dict[str, list[Device]] = defaultdict(list)
    for device in devices:
        by_ip[device.ip].append(device)

    def ip_order(ip: str) -> tuple[int, int, str]:
        address = ipaddress.ip_address(ip)
        return address.version, int(address), ip

    return [finding for ip in sorted(by_ip, key=ip_order) for finding in _findings_for_ip(ip, by_ip[ip])]
