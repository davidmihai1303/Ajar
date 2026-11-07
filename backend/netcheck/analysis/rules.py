"""Applies the official finding catalog to devices and open ports (FR-06).

Rules:
1. Report only ports with state="open". Ignore filtered, closed, open|filtered.
2. Decide by service name, never by port number.
3. HTTPS: service name="http" + tunnel="ssl" -> not HTTP_ADMIN_CLEARTEXT.
4. HTTP_ADMIN_CLEARTEXT: http without ssl tunnel and http-title contains
   (case-insensitive) login, admin, config, setup, router or settings.
5. SMB_EXPOSED: one per device: port 445 if open, else 139.
6. OUTDATED_SERVICE: in addition to the service's own finding.
7. UNKNOWN_DEVICE: no MAC vendor and no hostname and >= 1 open port (port column None).
8. UPNP_EXPOSED and SNMP_EXPOSED only on UDP.
"""
from __future__ import annotations

from typing import List

from netcheck.analysis.catalog import CATALOG, HTTP_ADMIN_KEYWORDS
from netcheck.analysis.models import Device, Finding, Port
from netcheck.analysis.versions import check_outdated_service


def classify_port_findings(ip: str, port: Port) -> List[Finding]:
    """Classify findings for a single open port. Only call for port.state == 'open'."""
    findings: List[Finding] = []
    if port.state != "open":
        return findings

    s_name = (port.service_name or "").lower()
    proto = (port.protocol or "tcp").lower()
    tunnel = (port.tunnel or "").lower()

    # 1. TELNET_OPEN
    if s_name in CATALOG["TELNET_OPEN"].matching_services:
        cat = CATALOG["TELNET_OPEN"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"Service '{s_name}' on port {port.port}/{proto}",
            )
        )

    # 2. RDP_EXPOSED
    if s_name in CATALOG["RDP_EXPOSED"].matching_services:
        cat = CATALOG["RDP_EXPOSED"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"Service '{s_name}' on port {port.port}/{proto}",
            )
        )

    # 3. VNC_EXPOSED
    if s_name in CATALOG["VNC_EXPOSED"].matching_services:
        cat = CATALOG["VNC_EXPOSED"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"Service '{s_name}' on port {port.port}/{proto}",
            )
        )

    # 4. DB_EXPOSED
    if s_name in CATALOG["DB_EXPOSED"].matching_services:
        cat = CATALOG["DB_EXPOSED"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"Database '{s_name}' exposed on port {port.port}/{proto}",
            )
        )

    # 5. CAMERA_STREAM_EXPOSED
    if s_name in CATALOG["CAMERA_STREAM_EXPOSED"].matching_services:
        cat = CATALOG["CAMERA_STREAM_EXPOSED"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"Video stream '{s_name}' exposed on port {port.port}/{proto}",
            )
        )

    # 6. FTP_CLEARTEXT
    if s_name in CATALOG["FTP_CLEARTEXT"].matching_services:
        cat = CATALOG["FTP_CLEARTEXT"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"Cleartext FTP on port {port.port}/{proto}",
            )
        )

    # 7. HTTP_ADMIN_CLEARTEXT
    # Must be http WITHOUT ssl tunnel, and title contains one of HTTP_ADMIN_KEYWORDS
    if s_name == "http" and tunnel != "ssl":
        t_lower = (port.title or "").lower()
        matched_kw = [kw for kw in HTTP_ADMIN_KEYWORDS if kw in t_lower]
        if matched_kw:
            cat = CATALOG["HTTP_ADMIN_CLEARTEXT"]
            findings.append(
                Finding(
                    code=cat.code,
                    severity=cat.severity,
                    points=cat.points,
                    ip=ip,
                    port=port.port,
                    evidence=f"Plaintext HTTP admin page (title: '{port.title}', matched: {', '.join(matched_kw)})",
                )
            )

    # 8. MQTT_EXPOSED
    if s_name in CATALOG["MQTT_EXPOSED"].matching_services:
        cat = CATALOG["MQTT_EXPOSED"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"MQTT broker on port {port.port}/{proto}",
            )
        )

    # 9. UPNP_EXPOSED (UDP only)
    if s_name in CATALOG["UPNP_EXPOSED"].matching_services and proto == "udp":
        cat = CATALOG["UPNP_EXPOSED"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"UPnP exposed on UDP port {port.port}",
            )
        )

    # 10. SNMP_EXPOSED (UDP only)
    if s_name in CATALOG["SNMP_EXPOSED"].matching_services and proto == "udp":
        cat = CATALOG["SNMP_EXPOSED"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"SNMP management exposed on UDP port {port.port}",
            )
        )

    # 11. PRINTER_RAW_EXPOSED
    if s_name in CATALOG["PRINTER_RAW_EXPOSED"].matching_services:
        cat = CATALOG["PRINTER_RAW_EXPOSED"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"Raw printer port (jetdirect) open on port {port.port}/{proto}",
            )
        )

    # 12. SSH_OPEN (Info)
    if s_name in CATALOG["SSH_OPEN"].matching_services:
        cat = CATALOG["SSH_OPEN"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=f"SSH service active on port {port.port}/{proto}",
            )
        )

    # 13. OUTDATED_SERVICE (reported in addition to the service finding)
    outdated_reason = check_outdated_service(port.service_name, port.product, port.version)
    if outdated_reason:
        cat = CATALOG["OUTDATED_SERVICE"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=ip,
                port=port.port,
                evidence=outdated_reason,
            )
        )

    return findings


def analyze_device_findings(device: Device) -> List[Finding]:
    """Analyze all findings for a single device, enforcing device-wide rules."""
    findings: List[Finding] = []

    # Filter only open ports
    open_ports = [p for p in device.ports if p.state == "open"]

    # 1. Per-port findings
    for port in open_ports:
        findings.extend(classify_port_findings(device.ip, port))

    # 2. SMB_EXPOSED: exactly ONE per device (port 445 if open, else 139)
    smb_services = CATALOG["SMB_EXPOSED"].matching_services
    smb_ports_open = [
        p for p in open_ports
        if p.service_name.lower() in smb_services or p.port in (445, 139) and "samba" in p.product.lower()
    ]
    if smb_ports_open:
        # Prefer port 445 if present and open, else 139, else first open SMB port
        port_445 = next((p for p in smb_ports_open if p.port == 445), None)
        chosen_port = port_445 if port_445 else next((p for p in smb_ports_open if p.port == 139), smb_ports_open[0])
        cat = CATALOG["SMB_EXPOSED"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=device.ip,
                port=chosen_port.port,
                evidence=f"SMB file sharing on port {chosen_port.port}",
            )
        )

    # 3. UNKNOWN_DEVICE: no MAC vendor and no hostname and >= 1 open port (port column left empty)
    has_vendor = bool((device.vendor or "").strip())
    has_hostname = bool((device.hostname or "").strip())
    if not has_vendor and not has_hostname and len(open_ports) >= 1:
        cat = CATALOG["UNKNOWN_DEVICE"]
        findings.append(
            Finding(
                code=cat.code,
                severity=cat.severity,
                points=cat.points,
                ip=device.ip,
                port=None,
                evidence="Device has no identifiable MAC vendor and no hostname, but has open ports",
            )
        )

    return findings


def analyze_devices(devices: List[Device]) -> List[Finding]:
    """Analyze all devices and return list of all findings."""
    all_findings: List[Finding] = []
    for d in devices:
        all_findings.extend(analyze_device_findings(d))
    return all_findings
