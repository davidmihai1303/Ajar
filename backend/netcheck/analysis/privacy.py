"""MAC masking for every output (NFR-02), e.g. 50:C7:BF:xx:xx:xx.

Only the first three bytes (the manufacturer prefix, OUI) are kept: they say "Apple" or "Intel",
not which exact device it is. The last three bytes identify the device and are hidden.
"""
import ipaddress
import re
from collections.abc import Iterable
from datetime import datetime

_HEX_PAIR = re.compile(r"^[0-9A-F]{2}$")
_MAC_IN_TEXT = re.compile(
    r"(?<![0-9a-z])(?:(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|"
    r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}|[0-9a-f]{12})(?![0-9a-z])", re.I | re.ASCII
)
# Six byte-sized groups can also occur inside an IPv6 literal. Match the whole literal first.
_ADDRESS_IN_TEXT = re.compile(
    r"(?P<ipv6>(?<![0-9a-z])(?:[0-9a-f]{0,4}:){6,8}[0-9a-f]{0,4}(?![0-9a-f:]))|"
    + _MAC_IN_TEXT.pattern, re.I | re.ASCII
)
_MAC_LABEL = re.compile(
    r"(?<![0-9a-z])(?:mac(?:[-_ ]?addr(?:ess)?)?|bssid|eui[-_ ]?48)[ ._:=-]*$", re.I | re.ASCII
)
_MAC_SEPARATORS = str.maketrans("", "", ":.-")


def mask_mac(mac: str) -> str:
    """'d8-43-ae-2e-c3-6d' -> 'D8:43:AE:xx:xx:xx'. Anything that is not a 6-byte MAC -> ''."""
    value = (mac or "").strip().upper()
    if re.fullmatch(r"(?:[0-9A-F]{4}\.){2}[0-9A-F]{4}|[0-9A-F]{12}", value):
        parts = re.findall(r"[0-9A-F]{2}", value.replace(".", ""))
    else:
        parts = re.split(r"[:-]", value)
    if len(parts) != 6 or not all(_HEX_PAIR.match(p) for p in parts):
        return ""
    return ":".join(parts[:3] + ["xx", "xx", "xx"])


def mask_macs_in_text(text: str, *, filename_timestamps: frozenset[str] = frozenset()) -> str:
    """Mask MACs in text. Only the filename formatter supplies verified timestamp exceptions."""
    def replace(match: re.Match) -> str:
        value = match.group()
        if match.lastgroup == "ipv6":
            try:
                ipaddress.IPv6Address(value)
            except ValueError:
                # A label or punctuation can add a colon next to a real MAC.
                return _MAC_IN_TEXT.sub(lambda mac: mask_mac(mac.group()), value)
            return value
        if value in filename_timestamps and not _MAC_LABEL.search(text, 0, match.start()):
            return value
        return mask_mac(value)

    return _ADDRESS_IN_TEXT.sub(replace, text)


def mask_scan_filename(name: str, scan_macs: Iterable[str] = ()) -> str:
    """Keep calendar timestamps in filenames unless the report or filename identifies a MAC."""
    timestamps = set()
    for match in _MAC_IN_TEXT.finditer(name):
        token = match.group()
        if len(token) == 12 and token.isdecimal():
            try:
                datetime.strptime(token, "%Y%m%d%H%M")
            except ValueError:
                continue
            timestamps.add(token)
    if timestamps:
        timestamps.difference_update(mac.strip().translate(_MAC_SEPARATORS) for mac in scan_macs)
    return mask_macs_in_text(name, filename_timestamps=frozenset(timestamps))
