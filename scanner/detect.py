"""FR-01: find the active interface, its subnet and gateway without manual input (Linux, iproute2).

Interfaces that are not the user's physical network are ignored, so a VPN or
Docker bridge is never mistaken for "the network this laptop is on".
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
    pass


def is_excluded(ifname: str) -> bool:
    return ifname.startswith(EXCLUDED_PREFIXES)


def _run(*args: str) -> str:
    return subprocess.run(list(args), capture_output=True, text=True, check=False).stdout


def _ip_json(*args: str) -> list:
    ip_bin = shutil.which("ip")
    if ip_bin is None:
        raise DetectError("the 'ip' command (iproute2) is not available")
    return json.loads(_run(ip_bin, "-j", *args) or "[]")


def choose_network(routes: list, addrs: list) -> tuple:
    """Pure function (unit-testable). Returns (ifname, local_ip, prefixlen, gateway).

    Preference: the default-route interface if it is a real one; otherwise the first
    UP, non-excluded interface with a private IPv4 address (covers VPN-as-default-route
    and LANs without internet).
    """
    candidates: dict = {}
    order: list = []
    for entry in addrs:
        name: str = entry.get("ifname", "")
        if is_excluded(name) or "UP" not in entry.get("flags", ["UP"]):
            continue
        for info in entry.get("addr_info", []):
            if info.get("family") != "inet":
                continue
            ip = ipaddress.ip_address(info["local"])
            if ip.is_private and not ip.is_loopback and not ip.is_link_local:
                candidates[name] = (info["local"], int(info["prefixlen"]))
                order.append(name)
                break
    if not candidates:
        raise DetectError("no physical network with a private IPv4 address was found")

    gateways: dict = {r["dev"]: r.get("gateway", "") for r in routes if r.get("dst") == "default"}
    chosen: str = next((r["dev"] for r in routes
                        if r.get("dst") == "default" and r.get("dev") in candidates), order[0])
    local, prefix = candidates[chosen]
    return chosen, local, prefix, gateways.get(chosen, "")


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
