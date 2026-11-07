"""④ Safe nmap XML parsing: defusedxml (no XXE), size limit, truncated file -> error (NFR-03, FR-05)."""
import os
from typing import Optional
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from netcheck.analysis.models import Device, Port, ScanResult
from netcheck.analysis.rules import evaluate_devices
from netcheck.analysis.scoring import compute_score
from netcheck.config import MAX_XML_BYTES


class ParserError(Exception):
    """Raised when scan XML cannot be safely parsed."""
    pass


def parse_xml_file(filepath: str) -> ScanResult:
    """Safely parse an nmap XML file into a ScanResult.
    
    If the file is broken, unreadable or exceeds MAX_XML_BYTES,
    returns a ScanResult with error=True and score=None.
    """
    filename = os.path.basename(filepath)
    
    try:
        if not os.path.exists(filepath):
            return ScanResult(file=filename, error=True)

        size = os.path.getsize(filepath)
        if size > MAX_XML_BYTES:
            return ScanResult(file=filename, error=True)

        with open(filepath, "rb") as f:
            xml_bytes = f.read()

        # Reject any entity declarations (prevent XXE / billion laughs)
        if b"<!ENTITY" in xml_bytes:
            return ScanResult(file=filename, error=True)

        root = ET.fromstring(xml_bytes)
        if root.tag != "nmaprun":
            return ScanResult(file=filename, error=True)
    except Exception:
        # Catch ParseError, XML entity attacks, ExpatError, OS errors -> return error ScanResult
        return ScanResult(file=filename, error=True)

    devices: list[Device] = []

    for host_el in root.findall("host"):
        # Check host status (up/down) - process only if status is up or not specified
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") == "down":
            continue

        ip_addr = ""
        mac_addr = ""
        vendor = ""

        for addr_el in host_el.findall("address"):
            addr_type = addr_el.get("addrtype")
            if addr_type == "ipv4":
                ip_addr = addr_el.get("addr", "")
            elif addr_type == "mac":
                mac_addr = addr_el.get("addr", "")
                vendor = addr_el.get("vendor", "") or ""

        if not ip_addr:
            continue

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            first_hn = hostnames_el.find("hostname")
            if first_hn is not None:
                hostname = first_hn.get("name", "") or ""

        ports: list[Port] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                try:
                    portid = int(port_el.get("portid", "0"))
                except ValueError:
                    continue

                proto = port_el.get("protocol", "tcp").lower()

                state_el = port_el.find("state")
                state = state_el.get("state", "closed").lower() if state_el is not None else "closed"

                service_el = port_el.find("service")
                s_name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                tunnel = service_el.get("tunnel", "") if service_el is not None else ""

                http_title = ""
                for script_el in port_el.findall("script"):
                    if script_el.get("id") == "http-title":
                        output = script_el.get("output", "")
                        elem = script_el.find("elem")
                        if elem is not None and elem.text:
                            http_title = elem.text.strip()
                        elif output:
                            http_title = output.strip()

                ports.append(Port(
                    portid=portid,
                    protocol=proto,
                    state=state,
                    service_name=s_name,
                    product=product,
                    version=version,
                    tunnel=tunnel,
                    http_title=http_title,
                ))

        devices.append(Device(
            ip=ip_addr,
            mac=mac_addr,
            vendor=vendor,
            hostname=hostname,
            ports=ports,
        ))

    findings = evaluate_devices(filename, devices)
    score = compute_score(findings)

    return ScanResult(
        file=filename,
        devices=devices,
        findings=findings,
        score=score,
        error=False,
    )
