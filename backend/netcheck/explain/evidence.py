"""Render independently citable statements from the current scan in Romanian or English."""
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class EvidencePort:
    port: int
    protocol: str                 # "tcp" | "udp"
    service: str = ""
    product: str = ""
    version: str = ""
    title: str = ""               # http-title, untrusted


@dataclass(frozen=True)
class EvidenceFinding:
    code: str                     # e.g. "TELNET_OPEN"
    severity: str                 # "high" | "medium" | "low" | "info"
    ip: str
    port: Optional[int] = None    # None for UNKNOWN_DEVICE
    protocol: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    title: str = ""
    device_type: str = ""         # from analysis/device_type.py, e.g. "laptop", "router"
    vendor: str = ""
    hostname: str = ""            # local scan label


@dataclass(frozen=True)
class EvidenceDevice:
    ip: str
    vendor: str = ""
    hostname: str = ""
    device_type: str = ""
    open_ports: tuple = ()        # tuple[EvidencePort, ...]


@dataclass(frozen=True)
class ScanEvidence:
    score: int
    devices: tuple = ()           # tuple[EvidenceDevice, ...]
    findings: tuple = ()          # tuple[EvidenceFinding, ...]


_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-f]*:){2,}[0-9a-f:.]*", re.I)
_ENDPOINT = re.compile(rf"({_IP.pattern}):(\d{{1,5}})\b")
_PORT_LIST = re.compile(
    r"\bport(?:ul|urile|ului|urilor|s)?\s*(?:nr\.?\s*)?"
    r"(\d{1,5}(?:\s*(?:,|/|și|si|and|or|sau)\s*\d{1,5})*)\b", re.I)
_SERVICE_PORT = re.compile(r"\b(\d{1,5})\s*/\s*(?:tcp|udp)\b", re.I)
_MAC = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])", re.I)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def clean(value: str, limit: int = 120) -> str:
    text = _CONTROL.sub(" ", value or "")
    return " ".join(_MAC.sub("[MAC]", text).split())[:limit]


def mentioned_ports(text: str) -> set[int]:
    """Port numbers a text names: "port 80", "porturile 80, 443", "22/tcp", "192.168.1.1:80"."""
    ports = {int(number) for match in _PORT_LIST.finditer(text) for number in re.findall(r"\d+", match.group(1))}
    ports |= {int(number) for number in _SERVICE_PORT.findall(text)}
    return ports | {int(match.group(2)) for match in _ENDPOINT.finditer(text)}


def mentioned_ips(question: str) -> set[str]:
    addresses = set(_IP.findall(question))
    for match in _IPV6.finditer(question):
        try:
            addresses.add(str(ipaddress.IPv6Address(match.group().rstrip("."))))
        except ValueError:
            continue
    return addresses


def _label(value: str) -> str:
    # Quoting keeps a recorded label distinct from a claim about the device.
    return json.dumps(clean(value), ensure_ascii=False)


def _citation(ip: str, port: Optional[int]) -> str:
    return f"[{ip}:{port}]" if port is not None else f"[{ip}]"


def finding_contexts(finding: EvidenceFinding, lang: str) -> dict[str, str]:
    location = _citation(finding.ip, finding.port)
    contexts = {"address": location}
    for key, value, en, ro in (
        ("vendor", finding.vendor, "reported vendor", "producător raportat"),
        ("hostname", finding.hostname, "device name", "nume dispozitiv"),
        ("service", finding.service, "reported service", "serviciu raportat"),
    ):
        if value:
            label = ro if lang == "ro" else en
            contexts[key] = f"{location} ({label}: {_label(value)})"
    return contexts


_FINDINGS = {
    "TELNET_OPEN": ("unencrypted remote login", "conectare la distanță necriptată"),
    "RDP_EXPOSED": ("Windows remote desktop is reachable", "desktopul Windows este accesibil de la distanță"),
    "VNC_EXPOSED": ("screen sharing is reachable", "partajarea ecranului este accesibilă"),
    "DB_EXPOSED": ("a database is reachable", "o bază de date este accesibilă"),
    "CAMERA_STREAM_EXPOSED": ("a media stream is reachable", "un flux audio sau video este accesibil"),
    "OUTDATED_SERVICE": ("an outdated service version", "o versiune veche a unui serviciu"),
    "FTP_CLEARTEXT": ("unencrypted file transfer", "transfer de fișiere necriptat"),
    "HTTP_ADMIN_CLEARTEXT": ("an unencrypted settings page", "o pagină de administrare necriptată"),
    "SMB_EXPOSED": ("file sharing is reachable", "partajarea fișierelor este accesibilă"),
    "MQTT_EXPOSED": ("a smart-device messaging service is reachable", "un serviciu de mesaje pentru dispozitive inteligente este accesibil"),
    "UPNP_EXPOSED": ("automatic router port configuration is reachable", "configurarea automată a porturilor routerului este accesibilă"),
    "SNMP_EXPOSED": ("a network management service is reachable", "un serviciu de administrare a rețelei este accesibil"),
    "PRINTER_RAW_EXPOSED": ("devices on this network can send print jobs directly", "dispozitivele din această rețea pot trimite documente direct la imprimantă"),
    "UNKNOWN_DEVICE": ("the scan could not identify this device", "scanarea nu a putut identifica acest dispozitiv"),
    "SSH_OPEN": ("encrypted remote login is reachable", "conectarea criptată la distanță este accesibilă"),
}
_SEVERITY_RO = {"high": "ridicată", "medium": "medie", "low": "scăzută", "info": "informativă"}


_DEVICE_NAMES_RO = {
    "printer": ("imprimantă", "imprimanta", "imprimantei"),
    "router": ("routerul", "routerului"),
    "camera": ("cameră", "camerei"),
    "laptop": ("laptopul", "laptopului"),
}


def score_text(score: int, lang: str) -> str:
    if lang == "ro":
        return f"Scorul rețelei este {score} din 100."
    return f"The network score is {score} out of 100."


def _recorded_fields(fields: tuple, lang: str) -> str:
    return ", ".join(f"{ro if lang == 'ro' else en}: {_label(value)}"
                     for value, en, ro in fields if value)


def _device_text(device: EvidenceDevice, lang: str) -> str:
    fields = ((device.hostname, "name", "nume"), (device.vendor, "vendor", "producător"),
              (device.device_type, "type", "tip"))
    description = _recorded_fields(fields, lang) or ("dispozitiv detectat" if lang == "ro" else "device detected")
    return f"[{device.ip}] {description}."


def _port_text(ip: str, port: EvidencePort, lang: str) -> str:
    fields = ((port.protocol, "protocol", "protocol"), (port.service, "service", "serviciu"),
              (port.product, "product", "produs"), (port.version, "version", "versiune"))
    details = _recorded_fields(fields, lang)
    label = "Port deschis" if lang == "ro" else "Open port"
    suffix = f" ({details})" if details else ""
    return f"{_citation(ip, port.port)} {label}{suffix}."


def answer_options(evidence: ScanEvidence, question: str, ips: set[str], lang: str) -> dict[str, str]:
    """Scope the selectable records before exposing any IDs to the model."""
    ro = lang == "ro"
    named = set()
    for device in (*evidence.devices, *evidence.findings):
        aliases = _DEVICE_NAMES_RO.get(device.device_type.casefold(), ())
        for name in (device.hostname, device.device_type, device.vendor, *aliases):
            if name and re.search(rf"(?<!\w){re.escape(name)}(?!\w)", question, re.I):
                named.add(device.ip)
    if named and ips and not named.intersection(ips):
        return {}
    subjects = (ips & named) if ips and named else (ips or named)

    pairs = {(ip, int(port)) for ip, port in _ENDPOINT.findall(question)}
    ports = {int(v) for group in _PORT_LIST.findall(question) for v in re.findall(r"\d+", group)}
    ports.update(int(v) for v in _SERVICE_PORT.findall(question))

    protocols = set(re.findall(r"\b(?:tcp|udp)\b", question.casefold()))

    def matches(ip: str, port: Optional[int], protocol: str = "") -> bool:
        if protocols and protocol.casefold() not in protocols:
            return False
        if subjects and ip not in subjects:
            return False
        if pairs or ports:
            return (ip, port) in pairs or port in ports
        return True

    options = {}
    if not subjects and not pairs and not ports and not protocols:
        options["score"] = score_text(evidence.score, lang)
    for i, device in enumerate(evidence.devices):
        if matches(device.ip, None):
            options[f"d{i}"] = _device_text(device, lang)
        for j, port in enumerate(device.open_ports):
            if matches(device.ip, port.port, port.protocol):
                options[f"d{i}p{j}"] = _port_text(device.ip, port, lang)
    for i, finding in enumerate(evidence.findings):
        if matches(finding.ip, finding.port, finding.protocol):
            names = _FINDINGS.get(finding.code)
            if names is None:
                continue
            label = names[1 if ro else 0]
            severity = _SEVERITY_RO.get(finding.severity, "necunoscută") if ro else clean(finding.severity)
            prefix = f"Severitate {severity}" if ro else f"Severity {severity}"
            options[f"f{i}"] = f"{_citation(finding.ip, finding.port)} {prefix} — {label}."
    return options
