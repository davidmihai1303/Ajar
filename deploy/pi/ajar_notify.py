#!/usr/bin/env python3
"""Ajar events service for the phone app (stage 3). Standard library only.

    ajar_notify.py pair [--open] [--minutes 2]   pairing window: the phone asks, both show a 3-digit
                                                 code, the owner approves HERE (no QR code needed)
    ajar_notify.py pair --qr [--name NAME]       alternative: one phone token as a QR code
    ajar_notify.py devices                       paired phones
    ajar_notify.py unpair <id|name> | --all      revoke one phone or all
    ajar_notify.py serve                         long-running service (systemd: ajar-notify.service)

HTTP API (port 8002 by default):
  GET  /events?since=<id>&wait=<0..60>   Authorization: Bearer <phone token>   (long-poll)
  GET  /events                           -> {"events": [], "last_id": N}       (start "from now")
  POST /pair      {"name": "Pixel 7"}    -> {"request_id", "code", "expires_in"}  only while the window
                                            is open and no other request is pending (403 / 409)
  GET  /pair/<request id>                -> {"status": "pending" | "approved" (+ token, once) |
                                            "rejected" | "expired" | "delivered"}

What this service is NOT allowed to do, by design:
  * start scans or change anything on the network (the only write is a phone's own pairing request);
  * return IP / MAC addresses, host names or device makers (events contain type, severity, counts);
  * accept a pairing without the owner's approval on the Pi;
  * answer more than RATE_LIMIT requests per minute per client, or keep more than MAX_WAITERS
    long-polls open.
It listens on the home network (default 0.0.0.0:8002) over plain HTTP: anyone who can read the Wi-Fi
traffic could read a token, and with it only these minimal events. Revoke a phone with `unpair`.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ajar_events import EventLog  # noqa: E402
from ajar_phones import DEFAULT_WINDOW_MINUTES, PairingError, PairingWindow, PhoneRegistry  # noqa: E402

STATE_DIR = Path(os.environ.get("AJAR_STATE_DIR", Path.home() / ".config" / "ajar"))
BIND = os.environ.get("AJAR_NOTIFY_BIND", "0.0.0.0")
PORT = int(os.environ.get("AJAR_NOTIFY_PORT", "8002"))
AGENT = os.environ.get("AJAR_AGENT", "http://127.0.0.1:8765")
MAX_WAIT_S = 60
POLL_EVERY_S = 1.0
RATE_LIMIT = 120          # requests per minute per client address
MAX_WAITERS = 8           # open long-polls at the same time
MAX_BODY = 1024


class RateLimiter:
    def __init__(self, per_minute: int, clock=time.monotonic):
        self.per_minute, self.clock = per_minute, clock
        self.hits: dict = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = self.clock()
        with self.lock:
            hits = self.hits[client]
            while hits and now - hits[0] > 60:
                hits.popleft()
            if len(hits) >= self.per_minute:
                return False
            hits.append(now)
            return True


def parse_query(query: str) -> tuple[int | None, int]:
    """'since=42&wait=30' -> (42, 30). Invalid or missing values: since=None, wait=0; wait capped at 60."""
    params = urllib.parse.parse_qs(query, keep_blank_values=False)

    def number(name: str) -> int | None:
        values = params.get(name)
        if not values or not values[0].isdigit() or len(values[0]) > 12:
            return None
        return int(values[0])
    wait = number("wait") or 0
    return number("since"), min(wait, MAX_WAIT_S)


class EventsServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, state_dir: Path, poll_every: float = POLL_EVERY_S):
        super().__init__(address, EventsHandler)
        self.log = EventLog(state_dir)
        self.phones = PhoneRegistry(state_dir)
        self.window = PairingWindow(state_dir)
        self.poll_every = poll_every
        self.limiter = RateLimiter(RATE_LIMIT)
        self.waiters = threading.BoundedSemaphore(MAX_WAITERS)
        self.pair_lock = threading.Lock()


class EventsHandler(BaseHTTPRequestHandler):
    server_version = "ajar-notify"
    sys_version = ""

    def _send(self, status: int, payload: dict, extra: dict | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _phone(self) -> str | None:
        header = self.headers.get("Authorization") or ""
        return self.server.phones.verify(header[7:].strip() if header.startswith("Bearer ") else "")

    def _limited(self) -> bool:
        if self.server.limiter.allow(self.client_address[0]):
            return False
        self._send(429, {"error": "too many requests"})
        return True

    def do_GET(self) -> None:
        if self._limited():
            return
        path, _, query = self.path.partition("?")
        if path.startswith("/pair/"):
            self._pair_status(path[len("/pair/"):])
            return
        if path != "/events":
            self._send(404, {"error": "not found"})
            return
        if self._phone() is None:
            self._send(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
            return
        self._events(query)

    def _events(self, query: str) -> None:
        since, wait = parse_query(query)
        if since is None:
            self._send(200, {"events": [], "last_id": self.server.log.last_id()})
            return
        if not self.server.waiters.acquire(blocking=False):
            self._send(503, {"error": "busy"})
            return
        try:
            deadline = time.monotonic() + wait
            while True:
                found = self.server.log.since(since)
                if found or time.monotonic() >= deadline:
                    break
                time.sleep(self.server.poll_every)
        finally:
            self.server.waiters.release()
        last = found[-1]["id"] if found else max(since, 0)
        self._send(200, {"events": found, "last_id": last})

    def _pair_status(self, request_id: str) -> None:
        if not 16 <= len(request_id) <= 64 or not all(c.isalnum() or c in "-_" for c in request_id):
            self._send(404, {"error": "unknown pairing request"})
            return
        try:
            with self.server.pair_lock:            # the token must be handed out exactly once
                self._send(200, self.server.window.poll(request_id, self.server.phones))
        except PairingError as err:
            self._send(err.status, {"error": err.reason})

    def do_POST(self) -> None:
        if self._limited():
            return
        if self.path != "/pair":
            self._send(405, {"error": "read only"})
            return
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if ctype != "application/json" or not 0 < length <= MAX_BODY:
            # Answer first, then one bounded read of the pending body, so the client gets the 400
            # instead of a connection reset (same approach as the scanner agent).
            self.close_connection = True
            self._send(400, {"error": "invalid body"})
            self.connection.settimeout(0.2)
            try:
                self.rfile.read1(min(max(length, MAX_BODY), 64 * 1024))
            except (TimeoutError, ConnectionError, OSError):
                pass
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "invalid JSON"})
            return
        name = body.get("name") if isinstance(body, dict) else None
        try:
            with self.server.pair_lock:
                self._send(200, self.server.window.request(name if isinstance(name, str) else ""))
        except PairingError as err:
            self._send(err.status, {"error": err.reason})

    def do_PUT(self) -> None:
        self._send(405, {"error": "read only"})

    do_DELETE = do_PATCH = do_PUT

    def log_message(self, fmt: str, *args) -> None:
        # Never log query strings or pairing ids: only the client and the path family.
        path = self.path.split("?")[0]
        family = "/pair/…" if path.startswith("/pair/") else path
        sys.stderr.write(f"[notify] {self.client_address[0]} {self.command} {family}\n")


# ------------------------------------------------------------------ owner commands (on the Pi)

def pi_address() -> str:
    """The Pi's address on the scanned network, from the scanner agent (localhost)."""
    try:
        with urllib.request.urlopen(AGENT + "/network", timeout=5) as response:
            return json.loads(response.read()).get("address") or ""
    except (OSError, ValueError):
        return ""


def run_pairing_window(window: PairingWindow, minutes: int, ask=input, sleep=time.sleep,
                       clock=time.monotonic, out=print) -> int:
    """Open the window, wait for one phone, show its code and let the owner approve it here."""
    window.open(minutes)
    deadline = clock() + minutes * 60
    out(f"Fereastră de împerechere deschisă {minutes} min. Deschide aplicația Ajar pe telefon.")
    out(f"Pairing window open for {minutes} min. Open the Ajar app on the phone.")
    try:
        while clock() < deadline:
            request = window.pending()
            if request is None:
                sleep(0.5)
                continue
            out(f"\nCerere de la / Request from: „{request['name']}”")
            out(f"Cod de verificare / Verification code:  {'  '.join(request['code'])}")
            answer = ask("Telefonul tău arată același cod? Scrie DA / Same code on your phone? Type YES: ")
            approved = answer.strip().upper() in ("DA", "YES")
            window.decide(approved)
            if not approved:
                out("Cerere respinsă / Request rejected.")
                return 1
            for _ in range(60):                     # the phone fetches its token within seconds
                if window.status_name() == "delivered":
                    out("Telefon împerecheat / Phone paired.")
                    return 0
                sleep(0.5)
            out("Aprobat, dar telefonul nu și-a luat încă token-ul / Approved, but the phone has not "
                "fetched its token yet. Încearcă din nou / Try again.")
            return 1
        out("Fereastra a expirat fără nicio cerere / The window expired without a request.")
        return 1
    finally:
        window.close()


def cmd_pair_qr(registry: PhoneRegistry, name: str) -> int:
    phone_id, token = registry.add(name)
    host = pi_address() or socket.gethostname() + ".local"
    uri = "ajar://pair?" + urllib.parse.urlencode({"host": host, "port": PORT, "token": token,
                                                    "name": socket.gethostname()})
    print(f"Telefon nou / New phone: {name} ({phone_id})")
    print("Scanează codul din aplicația Ajar. Nu-l arăta altora: conține token-ul.")
    print("Scan this code with the Ajar app. Do not share it: it contains the token.\n")
    qrencode = shutil.which("qrencode")
    if qrencode:
        subprocess.run([qrencode, "-t", "ansiutf8", uri], check=False)
    else:
        print("(pentru cod QR / for a QR code: sudo apt install qrencode)")
    print(uri)
    return 0


def cmd_devices(registry: PhoneRegistry) -> int:
    phones = registry.list()
    if registry.legacy.exists():
        phones.append({"id": "qr-legacy", "name": "token vechi / old QR token", "created_at": "-"})
    if not phones:
        print("Niciun telefon împerecheat / No paired phone.")
    for phone in phones:
        print(f"- {phone['id']}  {phone['name']}  (din / since {phone['created_at']})")
    return 0


def cmd_unpair(registry: PhoneRegistry, ref: str | None, everything: bool) -> int:
    if everything:
        registry.remove_all()
        print("Toate telefoanele au fost scoase / All phones removed.")
        return 0
    removed = registry.remove(ref or "")
    print(f"Scoase / Removed: {removed}")
    return 0 if removed else 1


def cmd_serve() -> int:
    server = EventsServer((BIND, PORT), STATE_DIR)
    print(f"[notify] listening on {BIND}:{PORT} (GET /events with a phone token; POST /pair only while "
          f"a pairing window is open)", flush=True)
    server.serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Nu rula ca root / Do not run as root.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(prog="ajar_notify.py")
    sub = parser.add_subparsers(dest="command", required=True)
    pair = sub.add_parser("pair")
    mode = pair.add_mutually_exclusive_group()
    mode.add_argument("--open", action="store_true", help="pairing window with a 3-digit code (default)")
    mode.add_argument("--qr", action="store_true", help="one phone token as a QR code instead")
    pair.add_argument("--minutes", type=int, default=DEFAULT_WINDOW_MINUTES, choices=range(1, 11), metavar="1-10")
    pair.add_argument("--name", default="Telefon (QR)")
    sub.add_parser("devices")
    unpair = sub.add_parser("unpair")
    unpair.add_argument("ref", nargs="?", help="phone id or name (see `devices`)")
    unpair.add_argument("--all", action="store_true")
    sub.add_parser("serve")
    args = parser.parse_args(argv)

    registry = PhoneRegistry(STATE_DIR)
    if args.command == "pair":
        if args.qr:
            return cmd_pair_qr(registry, args.name)
        if not sys.stdin.isatty():
            print("Împerecherea se aprobă interactiv / Pairing is approved interactively.", file=sys.stderr)
            return 1
        return run_pairing_window(PairingWindow(STATE_DIR), args.minutes)
    if args.command == "devices":
        return cmd_devices(registry)
    if args.command == "unpair":
        if not args.all and not args.ref:
            parser.error("unpair needs a phone id/name or --all")
        return cmd_unpair(registry, args.ref, args.all)
    return cmd_serve()


if __name__ == "__main__":
    sys.exit(main())
