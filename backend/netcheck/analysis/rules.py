"""⑤ Apply catalog rules: open ports only, decide by service name, tunnel=ssl, SMB one-per-device, UNKNOWN_DEVICE (FR-06)."""
import ipaddress
from typing import Sequence
from netcheck.analysis.catalog import CATALOG, HTTP_ADMIN_KEYWORDS, CatalogEntry
from netcheck.analysis.models import Device, Finding, Port
from netcheck.analysis.versions import is_outdated_service

# Special codes with structural rules beyond simple service-name lookup
_SPECIAL_CODES = frozenset({
    "HTTP_ADMIN_CLEARTEXT",
    "SMB_EXPOSED",
    "OUTDATED_SERVICE",
    "UNKNOWN_DEVICE",
})

# Build data-driven lookup from service_name -> CatalogEntry for standard catalog entries
_SERVICE_TO_ENTRY: dict[str, CatalogEntry] = {
    svc: entry
    for code, entry in CATALOG.items()
    if code not in _SPECIAL_CODES
    for svc in entry.services
}


def sort_key_finding(f: Finding) -> tuple[str, int, tuple[int, int], str]:
    """Canonical sort key: file -> IP (numeric) -> port (numeric, empty last) -> code."""
    try:
        ip_num = int(ipaddress.ip_address(f.ip))
    except ValueError:
        ip_num = 0
    port_key = (0, f.port) if f.port is not None else (1, 0)
    return (f.file, ip_num, port_key, f.finding_code)


def _check_outdated(filename: str, ip: str, port: Port, findings: list[Finding]) -> None:
    """Append OUTDATED_SERVICE if the port's product/version is on the outdated list."""
    if is_outdated_service(port.service_name, port.product, port.version):
        entry = CATALOG["OUTDATED_SERVICE"]
        findings.append(Finding(
            file=filename,
            ip=ip,
            port=port.portid,
            finding_code=entry.code,
            severity=entry.severity,
            points=entry.points,
            evidence=f"Outdated version: {port.product} {port.version} on port {port.portid}",
        ))


def evaluate_device(filename: str, device: Device) -> list[Finding]:
    """Pure function applying official finding rules to a single device."""
    findings: list[Finding] = []

    # 1. Only process ports in state "open" (FR-06 / AGENTS.md)
    open_ports = [p for p in device.ports if p.state == "open"]
    smb_ports: list[Port] = []

    http_entry = CATALOG["HTTP_ADMIN_CLEARTEXT"]
    smb_entry = CATALOG["SMB_EXPOSED"]

    for port in open_ports:
        s_name = (port.service_name or "").lower()

        # SMB is collected per device (445 preferred over 139)
        if s_name in smb_entry.services:
            smb_ports.append(port)
            continue

        # HTTP_ADMIN_CLEARTEXT: plain HTTP (no ssl tunnel) + admin keyword in http-title
        if s_name in http_entry.services:
            if port.tunnel != "ssl":
                title_lower = (port.http_title or "").lower()
                if any(kw in title_lower for kw in HTTP_ADMIN_KEYWORDS):
                    findings.append(Finding(
                        file=filename,
                        ip=device.ip,
                        port=port.portid,
                        finding_code=http_entry.code,
                        severity=http_entry.severity,
                        points=http_entry.points,
                        evidence=f"HTTP admin page titled '{port.http_title}' on port {port.portid}",
                    ))
            _check_outdated(filename, device.ip, port, findings)
            continue

        # Standard data-driven catalog lookup by service name
        entry = _SERVICE_TO_ENTRY.get(s_name)
        if entry is not None:
            if not entry.udp_only or port.protocol == "udp":
                findings.append(Finding(
                    file=filename,
                    ip=device.ip,
                    port=port.portid,
                    finding_code=entry.code,
                    severity=entry.severity,
                    points=entry.points,
                    evidence=f"Service '{port.service_name}' on port {port.portid}/{port.protocol}",
                ))

        # Check OUTDATED_SERVICE (in addition to the service's own finding)
        _check_outdated(filename, device.ip, port, findings)

    # SMB_EXPOSED rule: one finding per device (port 445 if open, else 139)
    if smb_ports:
        port_445 = next((p for p in smb_ports if p.portid == 445), None)
        chosen_smb = port_445 or next((p for p in smb_ports if p.portid == 139), smb_ports[0])
        findings.append(Finding(
            file=filename,
            ip=device.ip,
            port=chosen_smb.portid,
            finding_code=smb_entry.code,
            severity=smb_entry.severity,
            points=smb_entry.points,
            evidence=f"SMB exposed on port {chosen_smb.portid}/{chosen_smb.protocol}",
        ))
        _check_outdated(filename, device.ip, chosen_smb, findings)

    # UNKNOWN_DEVICE rule: no MAC vendor and no hostname and >= 1 open port (port column empty)
    has_vendor = bool(device.vendor and device.vendor.strip())
    has_hostname = bool(device.hostname and device.hostname.strip())
    if not has_vendor and not has_hostname and len(open_ports) >= 1:
        unknown_entry = CATALOG["UNKNOWN_DEVICE"]
        findings.append(Finding(
            file=filename,
            ip=device.ip,
            port=None,
            finding_code=unknown_entry.code,
            severity=unknown_entry.severity,
            points=unknown_entry.points,
            evidence=f"Device at {device.ip} has {len(open_ports)} open port(s) but no vendor or hostname",
        ))

    return sorted(findings, key=sort_key_finding)


def evaluate_devices(filename: str, devices: Sequence[Device]) -> list[Finding]:
    """Evaluate all devices in a scan and return findings sorted in canonical order."""
    all_findings: list[Finding] = []
    for d in devices:
        all_findings.extend(evaluate_device(filename, d))
    return sorted(all_findings, key=sort_key_finding)
