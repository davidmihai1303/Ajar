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
      POST /scan  {"confirm": true}  -> runs a scan of the detected subnet

The only privileged step is `sudo -n /usr/local/sbin/netcheck-nmap <cidr>`,
which sudoers allows without a password for members of the `netcheck` group.
Nothing else here needs root.

Configuration (environment variables, no secrets in code):
  NETCHECK_AGENT_PORT   default 8765
  NETCHECK_ALLOWLIST    extra allowed private networks, comma separated
                        (the detected subnet is always the default allowlist)
"""
import argparse
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from detect import DetectError, NetworkInfo, detect_network
from guard import ScopeError, check_scope

WRAPPER = "/usr/local/sbin/netcheck-nmap"
MAX_BODY_BYTES = 1024
REFUSAL_DRAIN_TIMEOUT_SECONDS = 0.2
SCAN_TIMEOUT_SECONDS = 660
_scan_lock = threading.Lock()


class ScanError(RuntimeError):
    pass


def allowlist_for(info: NetworkInfo) -> list:
    extra: str = os.environ.get("NETCHECK_ALLOWLIST", "")
    return [info.subnet] + [e.strip() for e in extra.split(",") if e.strip()]


def run_scan(confirm: bool, target: str = "") -> dict:
    info: NetworkInfo = detect_network()
    net = check_scope(target or info.subnet, allowlist_for(info), confirm)
    if not _scan_lock.acquire(blocking=False):
        raise ScanError("A scan is already running.")
    try:
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
    sub.add_parser("serve")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "network":
            print(json.dumps(network_summary(), indent=2, ensure_ascii=False))
        elif args.cmd == "scan":
            print(json.dumps(run_scan(args.confirm, args.target), indent=2))
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
        if self.path != "/scan":
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
        try:
            self._send(200, run_scan(confirm))
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
