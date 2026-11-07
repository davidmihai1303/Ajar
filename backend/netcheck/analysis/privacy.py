"""MAC masking for every output (NFR-02), e.g. 50:C7:BF:xx:xx:xx.

Only the first three bytes (the manufacturer prefix, OUI) are kept: they say "Apple" or "Intel",
not which exact device it is. The last three bytes identify the device and are hidden.
"""
import re

_HEX_PAIR = re.compile(r"^[0-9A-F]{2}$")


def mask_mac(mac: str) -> str:
    """'d8-43-ae-2e-c3-6d' -> 'D8:43:AE:xx:xx:xx'. Anything that is not a 6-byte MAC -> ''."""
    parts = re.split(r"[:\-]", (mac or "").strip().upper())
    if len(parts) != 6 or not all(_HEX_PAIR.match(p) for p in parts):
        return ""
    return ":".join(parts[:3] + ["xx", "xx", "xx"])
