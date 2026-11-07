"""⑤ Apply catalog rules: open ports only, decide by service name, tunnel=ssl, SMB one-per-device, UNKNOWN_DEVICE (FR-06)."""
from typing import Sequence
from netcheck.analysis.catalog import CATALOG, HTTP_ADMIN_KEYWORDS
from netcheck.analysis.models import Device, Finding, Port
from netcheck.analysis.versions import is_outdated_service


def evaluate_device(filename: str, device: Device) -> list[Finding]:
    """Pure function applying official finding rules to a single device."""
    findings: list[Finding] = []
    
    # 1. Only process ports in state "open" (FR-06 / AGENTS.md)
    open_ports = [p for p in device.ports if p.state == "open"]

    smb_ports: list[Port] = []

    for port in open_ports:
        s_name = (port.service_name or "").lower()

        # Catalog service matching (decide by service name, NOT port number)
        if s_name == "telnet":
            entry = CATALOG["TELNET_OPEN"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"Service '{port.service_name}' on port {port.portid}/{port.protocol}"
            ))

        elif s_name == "ms-wbt-server":
            entry = CATALOG["RDP_EXPOSED"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"Service '{port.service_name}' on port {port.portid}/{port.protocol}"
            ))

        elif s_name == "vnc":
            entry = CATALOG["VNC_EXPOSED"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"Service '{port.service_name}' on port {port.portid}/{port.protocol}"
            ))

        elif s_name in CATALOG["DB_EXPOSED"].services:
            entry = CATALOG["DB_EXPOSED"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"Database service '{port.service_name}' on port {port.portid}/{port.protocol}"
            ))

        elif s_name == "rtsp":
            entry = CATALOG["CAMERA_STREAM_EXPOSED"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"Video stream service '{port.service_name}' on port {port.portid}/{port.protocol}"
            ))

        elif s_name == "ftp":
            entry = CATALOG["FTP_CLEARTEXT"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"Cleartext FTP on port {port.portid}/{port.protocol}"
            ))

        elif s_name == "http":
            # HTTPS has tunnel="ssl" -> NOT HTTP_ADMIN_CLEARTEXT
            if port.tunnel != "ssl":
                title_lower = (port.http_title or "").lower()
                if any(kw in title_lower for kw in HTTP_ADMIN_KEYWORDS):
                    entry = CATALOG["HTTP_ADMIN_CLEARTEXT"]
                    findings.append(Finding(
                        file=filename, ip=device.ip, port=port.portid,
                        finding_code=entry.code, severity=entry.severity, points=entry.points,
                        evidence=f"HTTP admin page titled '{port.http_title}' on port {port.portid}"
                    ))

        elif s_name in ("microsoft-ds", "netbios-ssn"):
            smb_ports.append(port)

        elif s_name == "mqtt":
            entry = CATALOG["MQTT_EXPOSED"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"MQTT broker on port {port.portid}/{port.protocol}"
            ))

        elif s_name == "upnp" and port.protocol == "udp":
            entry = CATALOG["UPNP_EXPOSED"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"UPnP service on UDP port {port.portid}"
            ))

        elif s_name == "snmp" and port.protocol == "udp":
            entry = CATALOG["SNMP_EXPOSED"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"SNMP service on UDP port {port.portid}"
            ))

        elif s_name == "jetdirect":
            entry = CATALOG["PRINTER_RAW_EXPOSED"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"Raw printer jetdirect on port {port.portid}/{port.protocol}"
            ))

        elif s_name == "ssh":
            entry = CATALOG["SSH_OPEN"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"SSH service on port {port.portid}/{port.protocol}"
            ))

        # Check for OUTDATED_SERVICE (in addition to the service's own finding)
        if is_outdated_service(port.service_name, port.product, port.version):
            entry = CATALOG["OUTDATED_SERVICE"]
            findings.append(Finding(
                file=filename, ip=device.ip, port=port.portid,
                finding_code=entry.code, severity=entry.severity, points=entry.points,
                evidence=f"Outdated version: {port.product} {port.version} on port {port.portid}"
            ))

    # SMB_EXPOSED rule: exactly one per device (port 445 if open, else 139)
    if smb_ports:
        port_445 = next((p for p in smb_ports if p.portid == 445), None)
        chosen_smb = port_445 or next((p for p in smb_ports if p.portid == 139), smb_ports[0])
        entry = CATALOG["SMB_EXPOSED"]
        findings.append(Finding(
            file=filename, ip=device.ip, port=chosen_smb.portid,
            finding_code=entry.code, severity=entry.severity, points=entry.points,
            evidence=f"SMB exposed on port {chosen_smb.portid}/{chosen_smb.protocol}"
        ))

    # UNKNOWN_DEVICE rule: no MAC vendor and no hostname and >= 1 open port
    # Port column left empty (None)
    has_vendor = bool(device.vendor and device.vendor.strip())
    has_hostname = bool(device.hostname and device.hostname.strip())
    if not has_vendor and not has_hostname and len(open_ports) >= 1:
        entry = CATALOG["UNKNOWN_DEVICE"]
        findings.append(Finding(
            file=filename, ip=device.ip, port=None,
            finding_code=entry.code, severity=entry.severity, points=entry.points,
            evidence=f"Device at {device.ip} has {len(open_ports)} open port(s) but no vendor or hostname"
        ))

    return findings


def evaluate_devices(filename: str, devices: Sequence[Device]) -> list[Finding]:
    """Evaluate all devices in a scan and return findings sorted according to the catalog spec."""
    all_findings: list[Finding] = []
    for d in devices:
        all_findings.extend(evaluate_device(filename, d))
    return all_findings
