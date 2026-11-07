"""FR-01: find the active interface, its subnet and gateway without manual input (Linux, iproute2).

Interfaces that are not the user's physical network are ignored, so a VPN or
Docker bridge is never mistaken for "the network this laptop is on".

If more than one physical network is connected (e.g. the hotspot over Wi-Fi AND
the venue network over a cable), detection REFUSES instead of picking one.
Picking the default-route interface would put the venue network in the
allowlist, and the guard would then allow scanning it.
"""
import ipaddress
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass

# loopback, VPNs and virtual bridges: never "the local network the user owns"
EXCLUDED_PREFIXES: tuple = ("lo", "tun", "tap", "wg", "tailscale", "zt", "ppp",
                            "docker", "br-", "veth", "virbr", "vmnet", "vboxnet")


@dataclass(frozen=True)
class NetworkInfo:
    interface: str
    address: str
    subnet: str
    gateway: str
    ssid: str          # Wi-Fi name, "" if unknown or wired

    def to_dict(self) -> dict:
        return asdict(self)


class DetectError(RuntimeError):
    """Raised with a bilingual, user-facing reason (same shape as guard.ScopeError)."""

    def __init__(self, en: str, ro: str = "") -> None:
        super().__init__(en)
        self.en: str = en
        self.ro: str = ro or en


def is_excluded(ifname: str) -> bool:
    return ifname.startswith(EXCLUDED_PREFIXES)


def _run(*args: str) -> str:
    return subprocess.run(list(args), capture_output=True, text=True, check=False).stdout


def _ip_json(*args: str) -> list:
    ip_bin = shutil.which("ip")
    if ip_bin is None:
        raise DetectError("The 'ip' command (iproute2) is not available.",
                          "Comanda „ip” (iproute2) nu este disponibilă.")
    return json.loads(_run(ip_bin, "-j", *args) or "[]")


def physical_networks(addrs: list) -> dict:
    """Pure. ifname -> (local_ip, prefixlen) for every UP, non-virtual interface with a private IPv4."""
    found: dict = {}
    for entry in addrs:
        name: str = entry.get("ifname", "")
        flags: list = entry.get("flags", ["UP"])
        if is_excluded(name) or "UP" not in flags or "NO-CARRIER" in flags:
            continue
        for info in entry.get("addr_info", []):
            if info.get("family") != "inet":
                continue
            ip = ipaddress.ip_address(info["local"])
            if ip.is_private and not ip.is_loopback and not ip.is_link_local:
                found[name] = (info["local"], int(info["prefixlen"]))
                break
    return found


def choose_network(routes: list, addrs: list) -> tuple:
    """Pure function (unit-testable). Returns (ifname, local_ip, prefixlen, gateway).

    Exactly one physical network must be connected. Zero or several -> DetectError.
    """
    candidates: dict = physical_networks(addrs)
    if not candidates:
        raise DetectError("No physical network with a private IPv4 address was found. Connect to the team hotspot.",
                          "Nu am găsit nicio rețea fizică cu adresă IPv4 privată. Conectează-te la hotspotul echipei.")
    if len(candidates) > 1:
        names: str = ", ".join(sorted(candidates))
        raise DetectError(
            f"This laptop is connected to more than one network ({names}). "
            "Disconnect from all of them except the team hotspot, then try again.",
            f"Laptopul este conectat la mai multe rețele ({names}). "
            "Deconectează-te de la toate, în afară de hotspotul echipei, apoi încearcă din nou.")

    name, (local, prefix) = next(iter(candidates.items()))
    gateway: str = next((r.get("gateway", "") for r in routes
                         if r.get("dst") == "default" and r.get("dev") == name), "")
    return name, local, prefix, gateway


def _ssid(ifname: str) -> str:
    iw = shutil.which("iw")
    if iw is None:
        return ""
    for line in _run(iw, "dev", ifname, "link").splitlines():
        line = line.strip()
        if line.startswith("SSID:"):
            return line[len("SSID:"):].strip()
    return ""


def detect_network() -> NetworkInfo:
    routes: list = _ip_json("-4", "route", "show")
    addrs: list = _ip_json("-4", "addr", "show")
    ifname, local, prefix, gateway = choose_network(routes, addrs)
    subnet = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
    return NetworkInfo(interface=ifname, address=local, subnet=str(subnet),
                       gateway=gateway, ssid=_ssid(ifname))
