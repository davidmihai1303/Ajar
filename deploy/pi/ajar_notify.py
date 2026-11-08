#!/usr/bin/env python3
"""Ajar events service for the phone app (stage 3). Standard library only.

    ajar_notify.py pair [--new]   create (or rotate) the token and show the pairing QR code
    ajar_notify.py serve          long-running service (systemd: ajar-notify.service)

The phone asks:  GET /events?since=<last id>&wait=<0..60>   with   Authorization: Bearer <token>
and the Pi answers as soon as there is a newer event, or after `wait` seconds with an empty list
(long-poll). Without `since` it answers only {"last_id": N}, so a newly paired phone starts from now.

What this service is NOT allowed to do, by design:
  * start scans or change anything (GET only, one path);
  * return IP / MAC addresses, host names or device makers (events contain type, severity, counts);
  * answer without the token (constant-time comparison), or more than RATE_LIMIT requests per minute
    per client, or more than MAX_WAITERS open long-polls.
It listens on the home network (default 0.0.0.0:8002) over plain HTTP: anyone who can read the Wi-Fi
traffic could read the token, and with it only these minimal events. Rotate it with `pair --new`.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
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

STATE_DIR = Path(os.environ.get("AJAR_STATE_DIR", Path.home() / ".config" / "ajar"))
BIND = os.environ.get("AJAR_NOTIFY_BIND", "0.0.0.0")
PORT = int(os.environ.get("AJAR_NOTIFY_PORT", "8002"))
AGENT = os.environ.get("AJAR_AGENT", "http://127.0.0.1:8765")
MAX_WAIT_S = 60
POLL_EVERY_S = 1.0
RATE_LIMIT = 120          # requests per minute per client address
MAX_WAITERS = 8           # open long-polls at the same time


def token_path() -> Path:
    return STATE_DIR / "notify.token"


def load_token() -> str | None:
    try:
        token = token_path().read_text(encoding="ascii").strip()
    except OSError:
        return None
    return token or None


def new_token() -> str:
    token = secrets.token_urlsafe(32)
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = token_path().with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(token + "\n")
    os.replace(tmp, token_path())
    return token


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

    def __init__(self, address, token: str, log: EventLog, poll_every: float = POLL_EVERY_S):
        super().__init__(address, EventsHandler)
        self.token, self.log, self.poll_every = token, log, poll_every
        self.limiter = RateLimiter(RATE_LIMIT)
        self.waiters = threading.BoundedSemaphore(MAX_WAITERS)


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

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization") or ""
        given = header[7:].strip() if header.startswith("Bearer ") else ""
        return hmac.compare_digest(given.encode("utf-8"), self.server.token.encode("utf-8"))

    def do_GET(self) -> None:
        if not self.server.limiter.allow(self.client_address[0]):
            self._send(429, {"error": "too many requests"})
            return
        path, _, query = self.path.partition("?")
        if path != "/events":
            self._send(404, {"error": "not found"})
            return
        if not self._authorized():
            self._send(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
            return
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

    def do_POST(self) -> None:
        self._send(405, {"error": "read only"})

    do_PUT = do_DELETE = do_PATCH = do_POST

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[notify] %s %s\n" % (self.client_address[0], fmt % args))


def pi_address() -> str:
    """The Pi's address on the scanned network, from the scanner agent (localhost)."""
    try:
        with urllib.request.urlopen(AGENT + "/network", timeout=5) as response:
            return json.loads(response.read()).get("address") or ""
    except (OSError, ValueError):
        return ""


def cmd_pair(rotate: bool) -> int:
    token = load_token()
    if token is None or rotate:
        token = new_token()
        print("Token nou creat / New token created." + (" Telefoanele vechi trebuie împerecheate din nou / "
                                                         "Old phones must pair again." if rotate else ""))
    host = pi_address() or socket.gethostname() + ".local"
    uri = "ajar://pair?" + urllib.parse.urlencode({"host": host, "port": PORT, "token": token,
                                                    "name": socket.gethostname()})
    print("Scanează codul din aplicația Ajar / Scan this code with the Ajar app.")
    print("Nu-l arăta altora: conține token-ul / Do not share it: it contains the token.\n")
    qrencode = shutil.which("qrencode")
    if qrencode:
        subprocess.run([qrencode, "-t", "ansiutf8", uri], check=False)
    else:
        print("(pentru cod QR / for a QR code: sudo apt install qrencode)")
    print(uri)
    return 0


def cmd_serve() -> int:
    token = load_token()
    if token is None:
        print("Nu există token. Rulează mai întâi / No token. First run: ajar_notify.py pair", file=sys.stderr)
        return 1
    server = EventsServer((BIND, PORT), token, EventLog(STATE_DIR))
    print(f"[notify] listening on {BIND}:{PORT} (GET /events, token required)", flush=True)
    server.serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Nu rula ca root / Do not run as root.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(prog="ajar_notify.py")
    sub = parser.add_subparsers(dest="command", required=True)
    pair = sub.add_parser("pair")
    pair.add_argument("--new", action="store_true", help="rotate the token (old phones stop working)")
    sub.add_parser("serve")
    args = parser.parse_args(argv)
    return cmd_pair(args.new) if args.command == "pair" else cmd_serve()


if __name__ == "__main__":
    sys.exit(main())
