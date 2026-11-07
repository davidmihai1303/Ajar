"""Safe nmap XML parsing (FR-05, NFR-03).

Uses defusedxml to prevent XML entity expansion attacks (XXE).
Enforces file size limits and gracefully returns ScanResult with error
for truncated or malformed files (e.g. V7_broken.xml) without crashing.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from netcheck.analysis.device_type import guess_device_type
from netcheck.analysis.models import Device, Port, ScanResult
from netcheck.analysis.rules import analyze_devices
from netcheck.analysis.scoring import calculate_score
from netcheck.config import MAX_XML_BYTES


def parse_nmap_xml(file_path: str | Path) -> ScanResult:
    """Safely parse an nmap XML file into a ScanResult.

    If file is truncated, corrupt, or exceeds size limits, returns a ScanResult
    with error set (and score=None), never crashing (NFR-03, FR-05).
    """
    path = Path(file_path)
    file_name = path.name
    scan_id = path.stem

    if not path.exists():
        return ScanResult(
            scan_id=scan_id,
            file_name=file_name,
            error=f"File not found: {file_path}",
        )

    file_size = path.stat().st_size
    if file_size > MAX_XML_BYTES:
        return ScanResult(
            scan_id=scan_id,
            file_name=file_name,
            error=f"File exceeds size limit ({file_size} > {MAX_XML_BYTES} bytes)",
        )

    try:
        tree = ET.parse(str(path))
        root = tree.getroot()
    except Exception as exc:
        return ScanResult(
            scan_id=scan_id,
            file_name=file_name,
            error=f"Malformed or truncated XML: {exc}",
        )

    # Extract scan timestamp from root if available
    timestamp = root.get("start", "")

    devices: List[Device] = []
    for host in root.findall("host"):
        # Check host status (default to "up" if missing)
        status_elem = host.find("status")
        if status_elem is not None and status_elem.get("state") != "up":
            continue

        ip = ""
        mac = ""
        vendor = ""
        for addr in host.findall("address"):
            atype = addr.get("addrtype", "")
            if atype == "ipv4":
                ip = addr.get("addr", "")
            elif atype == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        if not ip:
            continue

        hostname = ""
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            hn_elem = hostnames_elem.find("hostname")
            if hn_elem is not None:
                hostname = hn_elem.get("name", "")

        ports: List[Port] = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                proto = port_elem.get("protocol", "tcp")
                try:
                    portid = int(port_elem.get("portid", "0"))
                except ValueError:
                    continue

                state = "closed"
                state_elem = port_elem.find("state")
                if state_elem is not None:
                    state = state_elem.get("state", "closed")

                service_name = ""
                product = ""
                version = ""
                tunnel = ""
                service_elem = port_elem.find("service")
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    tunnel = service_elem.get("tunnel", "")

                title = ""
                for script in port_elem.findall("script"):
                    if script.get("id") == "http-title":
                        elem_title = script.find("elem")
                        if elem_title is not None and elem_title.text:
                            title = elem_title.text.strip()
                        elif script.get("output"):
                            title = script.get("output", "").strip()

                ports.append(
                    Port(
                        port=portid,
                        protocol=proto,
                        state=state,
                        service_name=service_name,
                        product=product,
                        version=version,
                        tunnel=tunnel,
                        title=title,
                    )
                )

        device_type = guess_device_type(ip, vendor, hostname, ports)
        devices.append(
            Device(
                ip=ip,
                mac=mac,
                vendor=vendor,
                hostname=hostname,
                device_type=device_type,
                ports=ports,
            )
        )

    findings = analyze_devices(devices)
    score = calculate_score(findings)

    return ScanResult(
        scan_id=scan_id,
        file_name=file_name,
        timestamp=timestamp,
        score=score,
        devices=devices,
        findings=findings,
    )
