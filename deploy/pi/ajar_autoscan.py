#!/usr/bin/env python3
"""Ajar on a Raspberry Pi: network-bound consent + scheduled full scans (stage 1).

A live scan needs explicit confirmation (brief FR-02). A scheduled scan has nobody to confirm it,
so the owner confirms ONCE per network ("consent grant"), and every scheduled run scans only while
the Pi is on exactly that network. On any other network (venue Wi-Fi, a friend's house) it refuses.

A network is identified by: Wi-Fi name, subnet, gateway IP and a fingerprint of the gateway's MAC.
SSID + subnet alone are not enough: every iPhone hotspot uses 172.20.10.0/28 and anyone can reuse a
Wi-Fi name. The gateway MAC is never stored: only HMAC-SHA256(local secret key, MAC).

Usage (as the normal user, never as root):
    ajar_autoscan.py consent grant [--days 30]   # interactive, type DA / YES
    ajar_autoscan.py consent show
    ajar_autoscan.py consent revoke [--all]
    ajar_autoscan.py check                       # would a scan run now? (no scan)
    ajar_autoscan.py run                         # full scan, used by the 3-hour timer
    ajar_autoscan.py discover [--no-scan]        # who is connected? used by the 10-minute timer

Stage 2 (discover): host discovery only (nmap -sn through the agent and the root wrapper, no ports).
Devices are remembered by HMAC(local key, MAC), never by the MAC itself. The first run on a network
records a baseline; later runs log every device never seen before and start one full scan (at most
every 30 minutes) to see its open ports. Phones that use a random Wi-Fi address keep it per network,
so they are usually recognised; a phone that changes its random address appears as a new device.

The scan itself goes through the app's existing API (http://127.0.0.1:8001), so it uses the same
agent, scope guard and root wrapper as a manual scan, and lands in the history like any scan.
Standard library only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = os.environ.get("AJAR_API", "http://127.0.0.1:8001")
AGENT = os.environ.get("AJAR_AGENT", "http://127.0.0.1:8765")
STATE_DIR = Path(os.environ.get("AJAR_STATE_DIR", Path.home() / ".config" / "ajar"))
DEFAULT_DAYS = 30
SCAN_TIMEOUT_S = 900          # a full scan takes minutes; the agent itself stops at ~11 min
DISCOVER_TIMEOUT_S = 180
FULL_SCAN_COOLDOWN = dt.timedelta(minutes=30)   # a new device triggers at most one full scan per 30 min
FORGET_AFTER = dt.timedelta(days=30)            # devices not seen for 30 days are forgotten
EXIT_OK, EXIT_SKIPPED, EXIT_ERROR = 0, 0, 1   # a refused/skipped run is not a failure of the timer


class AutoscanError(RuntimeError):
    pass


def say(ro: str, en: str, stream=None) -> None:
    print(f"{ro} / {en}", file=stream or sys.stdout, flush=True)


# ------------------------------------------------------------------ local state (0600, owner only)

def _key_path() -> Path:
    return STATE_DIR / "consent.key"


def _consent_path() -> Path:
    return STATE_DIR / "consent.json"


def _private_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def load_key(create: bool = False) -> bytes | None:
    path = _key_path()
    if path.is_file():
        return path.read_bytes()
    if not create:
        return None
    key = secrets.token_bytes(32)
    _private_write(path, key)
    return key


def load_consents() -> list[dict]:
    try:
        data = json.loads(_consent_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    networks = data.get("networks") if isinstance(data, dict) else None
    return [n for n in networks if isinstance(n, dict)] if isinstance(networks, list) else []


def save_consents(networks: list[dict]) -> None:
    body = json.dumps({"version": 1, "networks": networks}, indent=2, sort_keys=True) + "\n"
    _private_write(_consent_path(), body.encode("utf-8"))


# ------------------------------------------------------------------ network identity

def fingerprint(key: bytes, mac: str) -> str:
    """HMAC of the gateway MAC: identifies the router without storing its address."""
    return hmac.new(key, mac.strip().lower().encode("ascii"), hashlib.sha256).hexdigest()[:32]


def parse_neighbour(entries: list, gateway: str) -> str | None:
    """MAC of `gateway` from `ip -j neigh show` output, or None."""
    for entry in entries:
        if isinstance(entry, dict) and entry.get("dst") == gateway and entry.get("lladdr"):
            state = entry.get("state") or []
            if "FAILED" not in state and "INCOMPLETE" not in state:
                return str(entry["lladdr"]).lower()
    return None


def gateway_mac(gateway: str) -> str | None:
    """Look up the gateway in the neighbour table; ping it once if it is not there yet."""
    try:
        ipaddress.ip_address(gateway)      # never pass anything but an IP address to a command
    except ValueError:
        return None
    ip_bin = shutil.which("ip")
    if ip_bin is None:
        raise AutoscanError("the 'ip' command (iproute2) is not available")
    for attempt in range(2):
        out = subprocess.run([ip_bin, "-j", "neigh", "show", gateway], capture_output=True, text=True).stdout
        mac = parse_neighbour(json.loads(out or "[]"), gateway)
        if mac or attempt:
            return mac
        ping = shutil.which("ping")
        if ping:
            subprocess.run([ping, "-c", "1", "-W", "1", gateway], capture_output=True)
    return None


def identity(network: dict, key: bytes, mac: str | None) -> dict:
    return {"ssid": network.get("ssid") or "", "subnet": network.get("subnet") or "",
            "gateway": network.get("gateway") or "", "gateway_fp": fingerprint(key, mac) if mac else ""}


def matches(consent: dict, current: dict, now: dt.datetime) -> tuple[bool, str]:
    """Pure decision: (allowed, reason)."""
    for field in ("ssid", "subnet", "gateway", "gateway_fp"):
        if not current.get(field) and field != "ssid":
            return False, f"missing {field}"
        if consent.get(field) != current.get(field):
            return False, f"different {field}"
    try:
        expires = dt.datetime.fromisoformat(consent["expires_at"])
    except (KeyError, TypeError, ValueError):
        return False, "invalid expiry"
    if now >= expires:
        return False, "consent expired"
    return True, "ok"


def find_consent(consents: list[dict], current: dict, now: dt.datetime) -> tuple[dict | None, str]:
    """The matching consent, or the most useful reason why none matches.

    A consent for the same Wi-Fi name and subnet that fails only on the router fingerprint is
    reported as such: it is either a different router or a network imitating ours.
    """
    reason = "no consent for this network"
    for consent in consents:
        ok, why = matches(consent, current, now)
        if ok:
            return consent, "ok"
        if (consent.get("ssid"), consent.get("subnet")) == (current.get("ssid"), current.get("subnet")):
            reason = why
    return None, reason


# ------------------------------------------------------------------ app API (loopback only)

def api(method: str, path: str, body: dict | None = None, timeout: float = 10, base: str = "") -> tuple[int, dict]:
    base = base or API
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as err:
        try:
            payload = json.loads(err.read() or b"{}")
        except ValueError:
            payload = {}
        return err.code, payload
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise AutoscanError(f"unreachable at {base}: {err}") from None


def current_network() -> dict:
    status, network = api("GET", "/api/network")
    if status != 200 or not network.get("subnet"):
        raise AutoscanError(f"cannot read the current network (HTTP {status})")
    return network


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ------------------------------------------------------------------ commands

def describe(network: dict) -> str:
    return (f"Wi-Fi: {network.get('ssid') or '-'} | rețea/network: {network.get('subnet')} | "
            f"router: {network.get('gateway') or '-'}")


def cmd_grant(days: int) -> int:
    network = current_network()
    mac = gateway_mac(network.get("gateway") or "") if network.get("gateway") else None
    if not mac:
        say("Nu pot identifica routerul rețelei. Acordul nu a fost salvat.",
            "Cannot identify this network's router. Consent was not saved.", sys.stderr)
        return EXIT_ERROR
    print(describe(network))
    say("Confirmi că această rețea îți aparține sau că ai permisiunea proprietarului, "
        f"și vrei ca Ajar să o scaneze automat timp de {days} zile?",
        f"Do you confirm you own this network or have the owner's permission, "
        f"and want Ajar to scan it automatically for {days} days?")
    if not sys.stdin.isatty():
        say("Acordul trebuie dat interactiv.", "Consent must be given interactively.", sys.stderr)
        return EXIT_ERROR
    answer = input("Scrie DA / Type YES: ").strip().upper()
    if answer not in ("DA", "YES"):
        say("Acord anulat.", "Consent cancelled.")
        return EXIT_SKIPPED
    key = load_key(create=True)
    current = identity(network, key, mac)
    granted = now_utc()
    entry = {**current, "granted_at": granted.isoformat(timespec="seconds"),
             "expires_at": (granted + dt.timedelta(days=days)).isoformat(timespec="seconds")}
    others = [c for c in load_consents()
              if (c.get("ssid"), c.get("subnet"), c.get("gateway"), c.get("gateway_fp"))
              != (current["ssid"], current["subnet"], current["gateway"], current["gateway_fp"])]
    save_consents(others + [entry])
    say(f"Acord salvat până la {entry['expires_at']}.", f"Consent saved until {entry['expires_at']}.")
    return EXIT_OK


def cmd_show() -> int:
    consents = load_consents()
    if not consents:
        say("Niciun acord salvat.", "No consent saved.")
    for c in consents:
        print(f"- Wi-Fi: {c.get('ssid') or '-'} | {c.get('subnet')} | router {c.get('gateway')} | "
              f"expires {c.get('expires_at')}")
    return EXIT_OK


def cmd_revoke(revoke_all: bool) -> int:
    if revoke_all:
        save_consents([])
        say("Toate acordurile au fost retrase.", "All consents revoked.")
        return EXIT_OK
    key = load_key()
    if key is None or not load_consents():
        say("Niciun acord salvat.", "No consent saved.")
        return EXIT_OK
    network = current_network()
    mac = gateway_mac(network["gateway"]) if network.get("gateway") else None
    current = identity(network, key, mac)
    kept = [c for c in load_consents()
            if not (c.get("subnet") == current.get("subnet") and c.get("gateway") == current.get("gateway")
                    and c.get("gateway_fp") == current.get("gateway_fp"))]
    save_consents(kept)
    say("Acordul pentru rețeaua curentă a fost retras.", "Consent for the current network revoked.")
    return EXIT_OK


def decide() -> tuple[dict | None, dict, str]:
    """(consent or None, public network as returned by the API, reason)."""
    network = current_network()
    key = load_key()
    if key is None:
        return None, network, "no consent saved"
    mac = gateway_mac(network["gateway"]) if network.get("gateway") else None
    consent, reason = find_consent(load_consents(), identity(network, key, mac), now_utc())
    return consent, network, reason


def cmd_check() -> int:
    consent, network, reason = decide()
    print(describe(network))
    if consent:
        say("Scanarea automată ar rula.", "A scheduled scan would run.")
    else:
        say(f"Scanarea automată NU ar rula ({reason}).", f"A scheduled scan would NOT run ({reason}).")
    return EXIT_OK


def cmd_run() -> int:
    consent, network, reason = decide()
    if not consent:
        say(f"Scanare sărită: rețeaua nu are acord ({reason}). {describe(network)}",
            f"Scan skipped: no consent for this network ({reason}).")
        return EXIT_SKIPPED
    say(f"Pornesc scanarea programată. {describe(network)}", "Starting the scheduled scan.")
    return full_scan(network, consent)


# ------------------------------------------------------------------ stage 2: new devices (every 10 min)

def _devices_path() -> Path:
    return STATE_DIR / "devices.json"


def load_devices() -> dict:
    try:
        data = json.loads(_devices_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_devices(state: dict) -> None:
    _private_write(_devices_path(), (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def remember(known: dict, seen: dict, now: dt.datetime) -> list:
    """Pure. Update `known` (fingerprint -> record) with `seen`; return the fingerprints that are new.
    Records not seen for FORGET_AFTER are dropped, so an old device coming back is reported again."""
    stamp = now.isoformat(timespec="seconds")
    for fp in [fp for fp, rec in known.items()
               if now - dt.datetime.fromisoformat(rec.get("last_seen", stamp)) > FORGET_AFTER]:
        del known[fp]
    new = [fp for fp in seen if fp not in known]
    for fp, device in seen.items():
        record = known.setdefault(fp, {"first_seen": stamp})
        record.update({"last_seen": stamp, "ip": device["ip"], "vendor": device["vendor"]})
    return sorted(new, key=lambda fp: seen[fp]["ip"])


def full_scan(network: dict, consent: dict) -> int:
    """Full scan through the app API (same path as the UI button). Records when it ran."""
    # Echo the network exactly as the API showed it: the agent re-checks it before scanning.
    status, scan = api("POST", "/api/scans", {"confirm": True, "expected_network": network}, timeout=SCAN_TIMEOUT_S)
    if status == 200:
        state = load_devices()
        state.setdefault(consent["gateway_fp"], {})["last_full_scan"] = now_utc().isoformat(timespec="seconds")
        save_devices(state)
    if status == 409:
        say("Scanare sărită: altă scanare rulează deja.", "Scan skipped: another scan is already running.")
        return EXIT_SKIPPED
    if status == 403:
        say("Scanare refuzată: rețeaua s-a schimbat între timp.", "Scan refused: the network changed meanwhile.")
        return EXIT_SKIPPED
    if status != 200:
        raise AutoscanError(f"scan failed (HTTP {status}): {scan.get('detail', scan)}")
    score = scan.get("score")
    findings = len(scan.get("findings") or [])
    say(f"Scanare terminată: scor {score}, {findings} probleme.", f"Scan finished: score {score}, {findings} findings.")
    return EXIT_OK


def agent_expected_network() -> dict:
    """The agent's own view of the network, in the exact shape it re-checks before discovery."""
    status, raw = api("GET", "/network", base=AGENT)
    if status != 200 or not raw.get("subnet"):
        raise AutoscanError(f"cannot read the network from the scanner agent (HTTP {status})")
    return {"interface": raw.get("interface"), "subnet": raw.get("subnet"),
            "gateway": raw.get("gateway") or None, "ssid": raw.get("ssid") or None}


def cmd_discover(scan_new: bool = True) -> int:
    """Every 10 minutes: who is connected? Log devices never seen on this network before.
    The first run on a network only records what is there (baseline, no alert)."""
    consent, network, reason = decide()
    if not consent:
        say(f"Verificare sărită: rețeaua nu are acord ({reason}).",
            f"Check skipped: no consent for this network ({reason}).")
        return EXIT_SKIPPED
    status, found = api("POST", "/discover", {"confirm": True, "expected_network": agent_expected_network()},
                        timeout=DISCOVER_TIMEOUT_S, base=AGENT)
    if status == 409:
        say("Verificare sărită: o scanare rulează deja.", "Check skipped: a scan is already running.")
        return EXIT_SKIPPED
    if status == 403:
        say("Verificare refuzată: rețeaua s-a schimbat între timp.", "Check refused: the network changed meanwhile.")
        return EXIT_SKIPPED
    if status != 200 or not isinstance(found.get("devices"), list):
        raise AutoscanError(f"discovery failed (HTTP {status})")

    key = load_key()
    seen: dict = {}
    for device in found["devices"]:
        if isinstance(device, dict) and device.get("mac"):
            # Only a keyed hash of the MAC is kept; the address itself is dropped here.
            seen[fingerprint(key, str(device["mac"]))] = {"ip": str(device.get("ip", "")),
                                                            "vendor": str(device.get("vendor", ""))[:80]}
    state = load_devices()
    net_state = state.setdefault(consent["gateway_fp"], {})
    baseline = "devices" not in net_state
    now = now_utc()
    new = remember(net_state.setdefault("devices", {}), seen, now)
    save_devices(state)

    if baseline:
        say(f"Inventar inițial: {len(seen)} dispozitive conectate.", f"Initial inventory: {len(seen)} devices connected.")
        return EXIT_OK
    if not new:
        say(f"Nicio schimbare: {len(seen)} dispozitive conectate, niciunul nou.",
            f"No change: {len(seen)} devices connected, none new.")
        return EXIT_OK
    for fp in new:
        device = seen[fp]
        vendor = device["vendor"] or "producător necunoscut / unknown maker"
        say(f"DISPOZITIV NOU în rețea: {vendor}, IP {device['ip']}.", f"NEW DEVICE on the network: {vendor}, IP {device['ip']}.")

    last = net_state.get("last_full_scan")
    recent = last and now - dt.datetime.fromisoformat(last) < FULL_SCAN_COOLDOWN
    if scan_new and not recent:
        say("Pornesc o scanare completă ca să văd ce porturi are.", "Starting a full scan to see its open ports.")
        return full_scan(network, consent)
    if scan_new:
        say("Scanarea completă a rulat recent; următoarea o va include.",
            "A full scan ran recently; the next one will include it.")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        say("Nu rula ca root.", "Do not run as root.", sys.stderr)
        return EXIT_ERROR
    parser = argparse.ArgumentParser(prog="ajar_autoscan.py")
    sub = parser.add_subparsers(dest="command", required=True)
    consent = sub.add_parser("consent").add_subparsers(dest="action", required=True)
    grant = consent.add_parser("grant")
    grant.add_argument("--days", type=int, default=DEFAULT_DAYS, choices=range(1, 366), metavar="1-365")
    consent.add_parser("show")
    revoke = consent.add_parser("revoke")
    revoke.add_argument("--all", action="store_true")
    sub.add_parser("check")
    sub.add_parser("run")
    discover = sub.add_parser("discover")
    discover.add_argument("--no-scan", action="store_true", help="only log new devices, no follow-up full scan")
    args = parser.parse_args(argv)
    try:
        if args.command == "consent":
            if args.action == "grant":
                return cmd_grant(args.days)
            if args.action == "show":
                return cmd_show()
            return cmd_revoke(args.all)
        if args.command == "check":
            return cmd_check()
        if args.command == "discover":
            return cmd_discover(scan_new=not args.no_scan)
        return cmd_run()
    except AutoscanError as err:
        say(f"Eroare: {err}", f"Error: {err}", sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
