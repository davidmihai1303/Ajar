"""④ Safe nmap XML parsing (FR-05, NFR-02, NFR-03).

parse_scan(path) -> ScanResult. It never raises for a bad file: an unreadable, oversized,
unsafe or non-nmap file gives ScanResult(error=...), so a folder export can write ERROR for
that file and continue with the others (V7_broken.xml).

Safety:
* defusedxml: entity declarations and external references are refused (XXE, "billion
  laughs"). A plain <!DOCTYPE nmaprun>, which nmap always writes, is accepted.
* Size limit checked before parsing, and the read itself is bounded.
* Every text value from the scan is untrusted: control characters are removed,
  whitespace is collapsed and the length is limited. The UI must still escape it.
* MAC addresses are masked here, so a full MAC never leaves the parser.

The parser only reads the file. It does not decide what is a finding: that is rules.py.
"""
from __future__ import annotations

import ipaddress
import os
import re
from typing import Optional
from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as SafeET

from .catalog import HTTP_ADMIN_TITLE
from .device_type import guess_device_type
from .models import (ERROR_NOT_NMAP, ERROR_TOO_LARGE, ERROR_UNREADABLE, ERROR_UNSAFE,
                     Device, Port, ScanResult)
from .privacy import mask_mac, mask_macs_in_text, mask_scan_filename

DEFAULT_MAX_XML_BYTES = 20 * 1024 * 1024
MAX_TEXT_CHARS = 512
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _normalized_text(value: Optional[str]) -> str:
    if not value:
        return ""
    text = " ".join(_CONTROL_CHARS.sub(" ", value).split())
    return mask_macs_in_text(text)


def clean_text(value: Optional[str]) -> str:
    """Untrusted text from the scan -> one line, no control characters, bounded length."""
    return _normalized_text(value)[:MAX_TEXT_CHARS]


def _title_excerpt(value: Optional[str]) -> str:
    text = _normalized_text(value)
    if len(text) <= MAX_TEXT_CHARS:
        return text
    match = HTTP_ADMIN_TITLE.search(text)
    if match and match.end() > MAX_TEXT_CHARS:
        # Keep an actual excerpt containing the evidence, including a word crossing the cutoff.
        start = match.start() - MAX_TEXT_CHARS // 2
        return "…" + text[start:start + MAX_TEXT_CHARS - 1]
    return text[:MAX_TEXT_CHARS]


def parse_scan(path: str, max_bytes: int = DEFAULT_MAX_XML_BYTES) -> ScanResult:
    """Read one nmap XML file. Never raises for a bad file; see ScanResult.error."""
    name = os.path.basename(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read(max(0, max_bytes + 1))
    except OSError:
        return ScanResult(file=mask_scan_filename(name), error=ERROR_UNREADABLE)
    return parse_bytes(data, name, max_bytes)


def parse_bytes(data: bytes, file: str, max_bytes: int = DEFAULT_MAX_XML_BYTES) -> ScanResult:
    """Parse a report already in memory using the same size limit as the file reader."""
    name = os.path.basename(file)
    if len(data) > max_bytes:
        return ScanResult(file=mask_scan_filename(name), error=ERROR_TOO_LARGE)
    try:
        root = SafeET.fromstring(data)
    except DefusedXmlException:
        return ScanResult(file=mask_scan_filename(name), error=ERROR_UNSAFE)
    except (ParseError, ValueError, LookupError):
        return ScanResult(file=mask_scan_filename(name), error=ERROR_UNREADABLE)
    if root.tag != "nmaprun":
        return ScanResult(file=mask_scan_filename(name), error=ERROR_NOT_NMAP)
    addresses = root.iterfind("host/address[@addrtype='mac']")
    file = mask_scan_filename(name, (address.get("addr", "") for address in addresses))
    if root.find("runstats/finished[@exit='error']") is not None:
        return ScanResult(file=file, error=ERROR_UNREADABLE)

    devices = [d for d in (_parse_host(h) for h in root.findall("host")) if d is not None]
    devices.sort(key=lambda d: _ip_sort_key(d.ip))
    return ScanResult(file=file, devices=tuple(devices), started=_int_or_none(root.get("start")))


def _parse_host(host: Element) -> Optional[Device]:
    status = host.find("status")
    if status is None or status.get("state") != "up":
        return None

    ipv4 = ipv6 = mac = vendor = ""
    for address in host.findall("address"):
        kind = address.get("addrtype")
        value = address.get("addr", "")
        if kind == "ipv4" and not ipv4:
            ipv4 = _valid_ip(value, 4)
        elif kind == "ipv6" and not ipv6:
            ipv6 = _valid_ip(value, 6)
        elif kind == "mac" and not mac:
            mac = mask_mac(value)
            vendor = clean_text(address.get("vendor"))
    ip = ipv4 or ipv6
    if not ip:
        return None

    hostname = ""
    for entry in host.findall("hostnames/hostname"):
        hostname = clean_text(entry.get("name"))
        if hostname:
            break

    ports = sorted((p for p in (_parse_port(e) for e in host.findall("ports/port")) if p is not None),
                   key=lambda p: (p.protocol, p.port))
    return Device(ip=ip, mac_masked=mac, vendor=vendor, hostname=hostname,
                  device_type=guess_device_type(vendor, hostname, ports), ports=tuple(ports))


def _parse_port(element: Element) -> Optional[Port]:
    number = _int_or_none(element.get("portid"))
    if number is None or not 0 <= number <= 65535:
        return None
    state = element.find("state")
    service = element.find("service")
    attr = service.get if service is not None else (lambda _key, _default=None: None)
    return Port(
        protocol=clean_text(element.get("protocol")).lower(),
        port=number,
        state=clean_text(state.get("state")) if state is not None else "",
        service=clean_text(attr("name")),
        product=clean_text(attr("product")),
        version=clean_text(attr("version")),
        extrainfo=clean_text(attr("extrainfo")),
        tunnel=clean_text(attr("tunnel")),
        scripts=_parse_scripts(element),
    )


def _parse_scripts(port: Element) -> dict:
    """script id -> text. For http-title only the real <elem key="title"> is kept.

    Without a title, nmap writes messages such as "Did not follow redirect to
    http://192.168.1.1/login.html" in the output attribute; the word "login" there must not
    make the page look like an admin page.
    """
    scripts: dict = {}
    for script in port.findall("script"):
        script_id = clean_text(script.get("id"))
        if not script_id or script_id in scripts:
            continue
        if script_id == "http-title":
            title = script.find("elem[@key='title']")
            scripts[script_id] = _title_excerpt(title.text) if title is not None else ""
        else:
            scripts[script_id] = clean_text(script.get("output"))
    return scripts


def _valid_ip(value: str, version: int) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return ""
    if ip.version != version:
        return ""
    # A scoped IPv6 address may include a user-supplied interface label after '%'.
    if version == 6 and ip.scope_id:
        address, _, zone = str(ip).partition("%")
        zone = clean_text(zone)
        return f"{address}%{zone}" if zone else address
    return str(ip)


def _ip_sort_key(ip: str) -> tuple:
    address = ipaddress.ip_address(ip)
    return address.version, int(address)


def _int_or_none(value: Optional[str]) -> Optional[int]:
    digits = (value or "").strip()
    # Nmap writes unsigned decimal fields. Even a 64-bit timestamp fits in 20 digits.
    if not digits.isascii() or not digits.isdecimal():
        return None
    digits = digits.lstrip("0") or "0"
    return int(digits) if len(digits) <= 20 else None
