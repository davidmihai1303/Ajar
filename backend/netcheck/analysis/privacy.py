"""MAC masking for every output (NFR-02), e.g. 50:C7:BF:xx:xx:xx."""
import re

_MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})$")


def mask_mac(mac: str) -> str:
    """Mask the last 3 octets of a MAC address (e.g. '50:C7:BF:xx:xx:xx').

    If already masked or invalid, returns as-is or sanitized.
    Preserves the OUI (first 3 octets) for vendor identification while protecting privacy.
    """
    if not mac:
        return ""
    s = mac.strip()
    match = _MAC_PATTERN.match(s)
    if match:
        prefix = match.group(1).replace("-", ":").upper()
        return f"{prefix}:xx:xx:xx"
    # If already masked, e.g. 50:C7:BF:xx:xx:xx
    if ":xx:xx:xx" in s.lower() or ":**:**:**" in s:
        return s
    return s
