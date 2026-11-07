"""FR-02: refuse anything outside the allowlist, refuse public ranges, require explicit confirmation."""
import ipaddress
from typing import Iterable

MIN_PREFIX = 24


class ScopeError(ValueError):
    """Raised with a bilingual, user-facing reason."""

    def __init__(self, en: str, ro: str) -> None:
        super().__init__(en)
        self.en: str = en
        self.ro: str = ro


def _parse(target: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        raise ScopeError(f"'{target}' is not a valid IP address or network.",
                         f"„{target}” nu este o adresă IP sau o rețea validă.")
    if net.version != 4:
        raise ScopeError("Only IPv4 networks are supported.", "Sunt acceptate doar rețele IPv4.")
    return net


def check_scope(target: str, allowlist: Iterable[str], confirm: bool) -> ipaddress.IPv4Network:
    """Return the validated network, or raise ScopeError. Order matters: cheapest, clearest refusals first."""
    if not confirm:
        raise ScopeError("Live scans need explicit confirmation (--confirm).",
                         "Scanarea live necesită confirmare explicită (--confirm).")

    net = _parse(target)

    if net.is_global or not net.is_private:
        raise ScopeError(f"{net} is not a private local network (public or reserved). Scanning it is not allowed.",
                         f"{net} nu este o rețea locală privată (este publică sau rezervată). Scanarea nu este permisă.")
    if net.is_loopback or net.is_link_local or net.is_multicast:
        raise ScopeError(f"{net} is not a normal local network.",
                         f"{net} nu este o rețea locală obișnuită.")
    if net.prefixlen < MIN_PREFIX:
        raise ScopeError(f"{net} is too large (maximum /{MIN_PREFIX}).",
                         f"{net} este prea mare (maximum /{MIN_PREFIX}).")

    allowed: list = []
    for entry in allowlist:
        a = _parse(entry)
        if a.is_private and not a.is_global:
            allowed.append(a)
    if not any(net.subnet_of(a) for a in allowed):
        shown: str = ", ".join(str(a) for a in allowed) or "(empty)"
        raise ScopeError(f"{net} is outside the allowed networks: {shown}.",
                         f"{net} este în afara rețelelor permise: {shown}.")
    return net
