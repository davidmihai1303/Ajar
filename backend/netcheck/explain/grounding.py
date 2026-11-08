"""NFR-06: does a model-written answer name evidence the scan does not show?

Checks concrete identifiers only: IPs, ports (and which device has them), versions, device makers,
CVEs and phone numbers. It cannot judge the meaning of other sentences; LLM_FREE_ANSWERS=0 is the
strict mode. When unsure it rejects, because the user then gets the verified answer instead.
"""
import re

from .evidence import _ENDPOINT, _IP, ScanEvidence, mentioned_ips

_LIST_SEP = r"\s*(?:,|/|și|si|and|or|sau)\s*"
_PREFIX = r"\s*(?:(?:number|no\.?|nr\.?|num[aă]r(?:ul)?)\s*)?[#:]?\s*(?:(?:tcp|udp)\s*[/:]?\s*)?"
# One port after a singular word ("port 9100, 2 steps" names only 9100), a list after a plural.
_PORT_ONE = re.compile(rf"\bport(?:ul|ului)?\b{_PREFIX}(\d{{1,5}})\b", re.I)
_PORT_MANY = re.compile(rf"\bport(?:s|uri|urile|urilor)\b{_PREFIX}(\d{{1,5}}(?:{_LIST_SEP}\d{{1,5}}\b)*)", re.I)
_PROTO_FIRST = re.compile(r"\b(?:tcp|udp)\s*[/:]?\s*(\d{1,5})\b", re.I)
_PROTO_LAST = re.compile(r"\b(\d{1,5})\s*/\s*(?:tcp|udp)\b", re.I)

_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
_NEGATION = re.compile(r"\b(?:not|no|none|without|never|nu|niciun|nicio|fără|fara)\b|n't\b", re.I)
_CVE = re.compile(r"\bCVE[-\s]?\d{4}", re.I)
_DATE = re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4})\b")
_PHONE = re.compile(r"(?<![\w.:])\+?\d[\d ().\-/]{5,}\d(?![\w:])")
_VERSION = re.compile(r"(?<![\w.])\d+(?:\.\d+)+[a-z]?\d*(?![\w])", re.I)
# Hardware makers a model is likely to name. Exact case, so "brother" or "canon" as words don't match.
_MAKERS = re.compile(
    r"\b(?:Cisco|TP-Link|Netgear|D-Link|ASUS|Asus|Linksys|Huawei|Xiaomi|Hikvision|Dahua|Samsung|LG|Sony|HP|"
    r"Hewlett[- ]Packard|Canon|Epson|Brother|Synology|QNAP|Apple|Ubiquiti|MikroTik|ZTE|Espressif|Raspberry Pi|"
    r"Dell|Lenovo|Philips|Tuya|Sonos|Roku)\b")
_TYPOGRAPHY = str.maketrans({**dict.fromkeys("‐‑‒–—―−", "-"),
                             **dict.fromkeys("   ", " ")})


def mentioned_ports(text: str) -> set[int]:
    """Port numbers a text names, in the ways people and models write them."""
    ports = {int(n) for pattern in (_PORT_ONE, _PROTO_FIRST, _PROTO_LAST) for n in pattern.findall(text)}
    ports |= {int(n) for match in _PORT_MANY.finditer(text) for n in re.findall(r"\d+", match.group(1))}
    return ports | {int(match.group(2)) for match in _ENDPOINT.finditer(text)}


def _ports_grounded(reply: str, question: str, by_ip: dict[str, set[int]]) -> bool:
    known = set().union(*by_ip.values()) if by_ip else set()
    asked = mentioned_ports(question)
    for sentence in _SENTENCE.split(reply):
        ports = mentioned_ports(sentence)
        denied = _NEGATION.search(sentence) is not None
        # A port the scan does not show may only be repeated to say it is not there.
        if ports - known - (asked if denied else set()):
            return False
        ips = mentioned_ips(sentence)
        if denied:
            continue
        for match in _ENDPOINT.finditer(sentence):
            if int(match.group(2)) not in by_ip.get(match.group(1), set()):
                return False
        # One device named: the ports in that sentence must be that device's.
        if len(ips) == 1 and ports - by_ip.get(next(iter(ips)), set()):
            return False
    return True


def invents_evidence(reply: str, question: str, evidence: ScanEvidence) -> bool:
    """True if the answer names an IP, port, version, maker, CVE or phone number the scan does not show."""
    reply = reply.translate(_TYPOGRAPHY)
    by_ip: dict[str, set[int]] = {d.ip: {p.port for p in d.open_ports} for d in evidence.devices}
    for finding in evidence.findings:
        by_ip.setdefault(finding.ip, set())
        if finding.port is not None:
            by_ip[finding.ip].add(finding.port)
    if mentioned_ips(reply) - set(by_ip) or not _ports_grounded(reply, question, by_ip):
        return True
    if _CVE.search(reply):
        return True  # a scan never contains CVE identifiers

    labels = [text for d in evidence.devices for text in (d.vendor, d.hostname) if text]
    labels += [text for d in evidence.devices for p in d.open_ports for text in (p.product, p.version) if text]
    labels += [text for f in evidence.findings for text in (f.vendor, f.hostname, f.product, f.version) if text]
    known_text = " ".join([*labels, question]).lower()
    if any(maker.lower() not in known_text for maker in _MAKERS.findall(reply)):
        return True

    numbers = _DATE.sub(" ", _IP.sub(" ", reply))
    if any(version.lower() not in known_text for version in _VERSION.findall(numbers)):
        return True
    for match in _PHONE.finditer(numbers):
        digits = sum(ch.isdigit() for ch in match.group())
        if digits >= (9 if "/" in match.group() else 7):  # "9100/631" is two ports, not a phone number
            return True
    return False
