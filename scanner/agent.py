"""
netcheck scanner agent — runs on the HOST as a normal user (never as root).

Two ways to use it:

  CLI (live checks in front of the jury):
      python3 agent.py network                       # FR-01: show detected network
      python3 agent.py scan --confirm                # scan the detected subnet
      python3 agent.py scan --target 8.8.8.8 --confirm      # refused (public)
      python3 agent.py scan                          # refused (no --confirm)

  HTTP server for the Dockerised app (listens on 127.0.0.1 only):
      python3 agent.py serve
      GET  /network                  -> detected network as JSON
      POST /scan  -> requires confirm=true and the network shown for consent
      POST /discover -> same body; who is connected right now (nmap -sn, no ports)

The only privileged step is `sudo -n /usr/local/sbin/netcheck-nmap <cidr>`,
which sudoers allows without a password for members of the `netcheck` group.
Nothing else here needs root.

Configuration (environment variables, no secrets in code):
  NETCHECK_AGENT_PORT   default 8765
  NETCHECK_ALLOWLIST    extra allowed private networks, comma separated
                        (the detected subnet is always the default allowlist)
"""
import argparse
import ipaddress
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.etree import ElementTree

from detect import DetectError, NetworkInfo, detect_network
from guard import ScopeError, check_scope

WRAPPER = "/usr/local/sbin/netcheck-nmap"
MAX_BODY_BYTES = 1024
REFUSAL_DRAIN_TIMEOUT_SECONDS = 0.2
SCAN_TIMEOUT_SECONDS = 660
DISCOVER_TIMEOUT_SECONDS = 150
DISCOVER_MAX_XML = 2 * 1024 * 1024
_scan_lock = threading.Lock()


class ScanError(RuntimeError):
    pass


def allowlist_for(info: NetworkInfo) -> list:
    extra: str = os.environ.get("NETCHECK_ALLOWLIST", "")
    return [info.subnet] + [e.strip() for e in extra.split(",") if e.strip()]


def _check_expected(info: NetworkInfo, expected_network: dict | None) -> None:
    if expected_network is not None and expected_network != {
        "interface": info.interface, "subnet": info.subnet,
        "gateway": info.gateway or None, "ssid": info.ssid or None,
    }:
        raise ScopeError("The network no longer matches your confirmation. Check it and confirm again.",
                         "Rețeaua nu mai corespunde confirmării tale. Verific-o și confirmă din nou.")


def run_scan(confirm: bool, target: str = "", *, expected_network: dict | None = None) -> dict:
    if not _scan_lock.acquire(blocking=False):
        raise ScanError("A scan is already running.")
    try:
        info = detect_network()
        net = check_scope(target or info.subnet, allowlist_for(info), confirm)
        _check_expected(info, expected_network)
        result = subprocess.run(["sudo", "-n", WRAPPER, str(net)],
                                capture_output=True, text=True, timeout=SCAN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise ScanError("The scan took too long and was stopped.")
    finally:
        _scan_lock.release()
    if result.returncode != 0:
        raise ScanError(result.stderr.strip()[:500] or "The scan failed.")
    lines: list = result.stdout.strip().splitlines()
    if not lines:
        raise ScanError("The scan finished but did not report where the results were saved.")
    return {"network": info.to_dict(), "target": str(net), "xml_path": lines[-1]}


def parse_discovery(xml_text: str, own_ip: str = "") -> list:
    """Hosts that are up, from `nmap -sn -oX -` output: [{"ip", "mac", "vendor"}], sorted by IP.

    The XML comes from our own root wrapper, but it is still bounded and parsed defensively.
    The laptop/Pi running the scan reports no MAC for itself and is left out.
    """
    if len(xml_text) > DISCOVER_MAX_XML:
        raise ScanError("The discovery result is too large.")
    # Stdlib only (no defusedxml here): nmap writes a bare <!DOCTYPE nmaprun> and never declares
    # entities, so any entity declaration is refused before parsing (XXE / entity expansion).
    if "<!ENTITY" in xml_text.upper():
        raise ScanError("The discovery result contains unexpected XML entities.")
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        raise ScanError("The discovery result could not be read.")
    devices: dict = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = ""
        for address in host.findall("address"):
            kind = address.get("addrtype")
            if kind == "ipv4" and not ip:
                ip = address.get("addr", "")
            elif kind == "mac" and not mac:
                mac = address.get("addr", "").lower()
                vendor = address.get("vendor", "")
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if ip == own_ip:
            continue
        devices[ip] = {"ip": ip, "mac": mac, "vendor": vendor[:80]}
    return [devices[ip] for ip in sorted(devices, key=lambda a: int(ipaddress.IPv4Address(a)))]


def run_discovery(confirm: bool, *, expected_network: dict | None = None) -> dict:
    """Who is connected right now (no ports). Same scope guard and lock as a full scan.

    Full MAC addresses are returned only to the local client (127.0.0.1, request checks below),
    which must not store them in clear (deploy/pi/ajar_autoscan.py keeps only a keyed hash).
    """
    if not _scan_lock.acquire(blocking=False):
        raise ScanError("A scan is already running.")
    try:
        info = detect_network()
        net = check_scope(info.subnet, allowlist_for(info), confirm)
        _check_expected(info, expected_network)
        result = subprocess.run(["sudo", "-n", WRAPPER, "--discover", str(net)],
                                capture_output=True, text=True, timeout=DISCOVER_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise ScanError("The discovery took too long and was stopped.")
    finally:
        _scan_lock.release()
    if result.returncode != 0:
        raise ScanError(result.stderr.strip()[:500] or "The discovery failed.")
    return {"network": info.to_dict(), "target": str(net), "devices": parse_discovery(result.stdout, info.address)}


CONSENT_TEXT = {
    "ro": "Scanează doar rețele care îți aparțin sau pentru care ai permisiunea proprietarului.",
    "en": "Only scan networks you own or have the owner's permission to scan.",
}


def network_summary() -> dict:
    """What the UI confirmation dialog shows before a live scan."""
    info: NetworkInfo = detect_network()
    return {**info.to_dict(), "allowlist": allowlist_for(info), "consent": CONSENT_TEXT}


# ---------------------------------------------------------------- CLI

def cli(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="agent.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("network")
    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--target", default="", help="defaults to the detected subnet")
    p_scan.add_argument("--confirm", action="store_true", help="required for a live scan")
    p_discover = sub.add_parser("discover", help="who is connected (no ports), detected subnet only")
    p_discover.add_argument("--confirm", action="store_true", help="required for a live discovery")
    sub.add_parser("serve")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "network":
            print(json.dumps(network_summary(), indent=2, ensure_ascii=False))
        elif args.cmd == "scan":
            print(json.dumps(run_scan(args.confirm, args.target), indent=2))
        elif args.cmd == "discover":
            found = run_discovery(args.confirm)
            # The CLI shows masked MACs only; full addresses never reach the terminal or its scrollback.
            for device in found["devices"]:
                device["mac"] = (device["mac"][:8] + ":xx:xx:xx") if device["mac"] else ""
            print(json.dumps(found, indent=2, ensure_ascii=False))
        else:
            serve()
    except ScopeError as e:
        print(f"REFUZAT / REFUSED\n  RO: {e.ro}\n  EN: {e.en}", file=sys.stderr)
        return 2
    except DetectError as e:
        print(f"EROARE / ERROR\n  RO: {e.ro}\n  EN: {e.en}", file=sys.stderr)
        return 1
    except ScanError as e:
        print(f"EROARE / ERROR: {e}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------- HTTP

def is_trusted_request(headers, port: int, method: str) -> tuple:
    """Pure check of who is calling. Returns (ok, reason).

    The agent listens on 127.0.0.1, but a web page open in the user's browser can still send
    requests to 127.0.0.1. Only the app's server-side client should talk to the agent:
      * Host must be 127.0.0.1:<port> or localhost:<port>  (blocks DNS rebinding)
      * no Origin header                                   (browsers always add it to cross-site
                                                            POSTs; the app's HTTP client does not)
      * POST must declare Content-Type: application/json   (a plain HTML form or a text/plain
                                                            "simple request" cannot set it)
    """
    host: str = (headers.get("Host") or "").strip().lower()
    if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
        return False, "unexpected Host header"
    if headers.get("Origin") is not None:
        return False, "browser requests are not accepted"
    if method == "POST":
        ctype: str = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return False, "Content-Type must be application/json"
    return True, ""


class Handler(BaseHTTPRequestHandler):
    server_version = "netcheck-agent"

    def _send(self, status: int, payload: dict) -> None:
        body: bytes = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _drain_body(self) -> None:
        """Discard pending body bytes on close to reduce resets for clients still writing.

        Bounded: one socket read of at most MAX_BODY_BYTES, with a short timeout. An invalid
        Content-Length still gets that one bounded read, because the client did send a body.
        """
        try:
            length: int = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = MAX_BODY_BYTES
        if length <= 0:
            return
        self.connection.settimeout(REFUSAL_DRAIN_TIMEOUT_SECONDS)
        try:
            # read1 makes at most one socket read, even if the body arrives in fragments.
            self.rfile.read1(min(length, MAX_BODY_BYTES))
        except (TimeoutError, ConnectionError):
            pass

    def _trusted(self, method: str) -> bool:
        ok, reason = is_trusted_request(self.headers, self.server.server_address[1], method)
        if not ok:
            self.close_connection = True
            self._send(403, {"error": "forbidden", "reason": reason})
            if method == "POST":
                self._drain_body()
        return ok

    def do_GET(self) -> None:
        if not self._trusted("GET"):
            return
        if self.path != "/network":
            self._send(404, {"error": "not found"})
            return
        try:
            self._send(200, network_summary())
        except DetectError as e:
            self._send(503, {"error": e.en, "en": e.en, "ro": e.ro})

    def do_POST(self) -> None:
        if not self._trusted("POST"):
            return
        if self.path not in ("/scan", "/discover"):
            self._send(404, {"error": "not found"})
            return
        try:
            length: int = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length <= 0 or length > MAX_BODY_BYTES:
            # Same as a 403: answer first, then a bounded drain, so the client is not reset.
            self.close_connection = True
            self._send(400, {"error": "invalid body"})
            self._drain_body()
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid JSON"})
            return
        # Deliberately ignores any target sent by the client: the agent always
        # scans the subnet it detects itself.
        confirm: bool = isinstance(body, dict) and body.get("confirm") is True
        expected = body.get("expected_network") if isinstance(body, dict) else None
        try:
            if not isinstance(expected, dict):
                raise ScopeError("Check the current network and confirm it before scanning.",
                                 "Verifică rețeaua curentă și confirm-o înainte de scanare.")
            if self.path == "/discover":
                self._send(200, run_discovery(confirm, expected_network=expected))
            else:
                self._send(200, run_scan(confirm, expected_network=expected))
        except ScopeError as e:
            self._send(403, {"error": "refused", "en": e.en, "ro": e.ro})
        except ScanError as e:
            self._send(409 if "already running" in str(e) else 500, {"error": str(e)})
        except DetectError as e:
            self._send(503, {"error": e.en, "en": e.en, "ro": e.ro})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[agent] " + fmt % args + "\n")


def serve() -> None:
    port: int = int(os.environ.get("NETCHECK_AGENT_PORT", "8765"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[agent] listening on http://127.0.0.1:{port} (localhost only)")
    httpd.serve_forever()


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))
