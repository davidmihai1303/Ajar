"""Device-type guess for the UI (FR-03): router, camera, printer, iot, computer, phone, tv, nas, server, unknown.

Only a hint shown next to a device. The finding rules never use it, so a wrong guess can never
change findings or scores.
"""
from __future__ import annotations

_CAMERA_VENDORS = ("hikvision", "dahua", "axis", "reolink", "amcrest", "foscam", "uniview")
_PRINTER_VENDORS = ("brother", "epson", "canon", "lexmark", "xerox", "kyocera", "ricoh")
_ROUTER_VENDORS = ("netgear", "tp-link", "tplink", "mikrotik", "ubiquiti", "zyxel", "d-link", "technicolor", "sagemcom")
_IOT_VENDORS = ("espressif", "tuya", "shelly", "sonoff", "itead", "philips lighting", "signify")
_TV_VENDORS = ("roku", "vizio", "tcl", "hisense")
_NAS_VENDORS = ("synology", "qnap", "western digital")


def _has(text: str, needles: tuple) -> bool:
    return any(n in text for n in needles)


def guess_device_type(vendor: str, hostname: str, ports) -> str:
    v = (vendor or "").lower()
    h = (hostname or "").lower()
    services = {p.service for p in ports if p.is_open}

    if "rtsp" in services or _has(v, _CAMERA_VENDORS) or _has(h, ("camera", "cam-", "ipcam", "nvr")):
        return "camera"
    if services & {"jetdirect", "ipp"} or _has(v, _PRINTER_VENDORS) or "printer" in h:
        return "printer"
    if _has(v, _ROUTER_VENDORS) or _has(h, ("router", "gateway", "fritz", "access-point")):
        return "router"
    if _has(v, _NAS_VENDORS) or "nas" in h.split("-"):
        return "nas"
    if "mqtt" in services or _has(v, _IOT_VENDORS) or _has(h, ("plug", "bulb", "hub", "sensor")):
        return "iot"
    if _has(v, _TV_VENDORS) or _has(h, ("tv", "chromecast", "roku")):
        return "tv"
    if _has(h, ("iphone", "android", "galaxy", "pixel", "phone")):
        return "phone"
    if services & {"ms-wbt-server", "microsoft-ds", "netbios-ssn", "vnc"} or _has(h, ("laptop", "desktop", "pc-", "macbook")):
        return "computer"
    if services & {"ssh", "mysql", "postgresql", "redis", "mongodb", "ftp"}:
        return "server"
    return "unknown"
