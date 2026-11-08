"""Paired phones and the pairing window (stage 3, option B). Standard library only.

Pairing without a QR code, like Bluetooth numeric comparison:
  1. On the Pi the owner opens a short window:  ajar_notify.py pair --open  (default 2 minutes).
  2. The phone (it found the Pi via mDNS) sends  POST /pair {"name": "..."}  and gets back a secret
     request id and a 3-digit verification code. Both screens show the same code.
  3. The owner checks that the phone shows the same code and approves ON THE PI. Approval is never
     possible from the phone: otherwise a stranger on the Wi-Fi could approve its own request.
  4. The phone polls  GET /pair/<request id>  and receives its own token exactly once.
     The window then closes. Only one request can be pending at a time.

Each phone has its own token; only SHA-256 of it is stored (phones.json, 0600), so the file does not
let anyone read the events. A token created by the older QR pairing (notify.token) keeps working.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

DEFAULT_WINDOW_MINUTES = 2
MAX_NAME = 40


class PairingError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(moment: dt.datetime) -> str:
    return moment.isoformat(timespec="seconds")


def _private_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _read(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def clean_name(name) -> str:
    """Phone name as shown on the Pi: printable characters only, bounded."""
    text = "".join(ch for ch in str(name or "") if ch.isprintable()).strip()
    return text[:MAX_NAME] or "Telefon"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class PhoneRegistry:
    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "phones.json"
        self.legacy = Path(state_dir) / "notify.token"

    def _load(self) -> list:
        data = _read(self.path)
        phones = data.get("phones") if isinstance(data, dict) else None
        return [p for p in phones if isinstance(p, dict)] if isinstance(phones, list) else []

    def list(self) -> list:
        return [{k: p.get(k) for k in ("id", "name", "created_at")} for p in self._load()]

    def add(self, name: str) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        phone_id = secrets.token_hex(4)
        phones = self._load() + [{"id": phone_id, "name": clean_name(name), "created_at": _iso(_now()),
                                  "token_sha256": _digest(token)}]
        _private_write(self.path, {"version": 1, "phones": phones})
        return phone_id, token

    def verify(self, token: str) -> str | None:
        """Phone id for a valid token, else None. Constant-time comparison against every phone."""
        if not token:
            return None
        digest, match = _digest(token), None
        for phone in self._load():
            if hmac.compare_digest(digest, str(phone.get("token_sha256", ""))):
                match = phone.get("id")
        try:
            legacy = self.legacy.read_text(encoding="ascii").strip()
        except OSError:
            legacy = ""
        if legacy and hmac.compare_digest(token.encode("utf-8"), legacy.encode("utf-8")):
            match = match or "qr-legacy"
        return match

    def remove(self, ref: str) -> int:
        phones = self._load()
        kept = [p for p in phones if ref not in (p.get("id"), p.get("name"))]
        _private_write(self.path, {"version": 1, "phones": kept})
        removed = len(phones) - len(kept)
        if ref == "qr-legacy" and self.legacy.exists():
            self.legacy.unlink()
            removed += 1
        return removed

    def remove_all(self) -> None:
        _private_write(self.path, {"version": 1, "phones": []})
        self.legacy.unlink(missing_ok=True)


class PairingWindow:
    """State machine in pairing.json: open -> pending -> approved -> delivered (or rejected / expired)."""

    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "pairing.json"

    def _state(self) -> dict | None:
        state = _read(self.path)
        return state if isinstance(state, dict) else None

    def _expired(self, state: dict, now: dt.datetime) -> bool:
        try:
            return now >= dt.datetime.fromisoformat(state["expires_at"])
        except (KeyError, TypeError, ValueError):
            return True

    def open(self, minutes: int = DEFAULT_WINDOW_MINUTES, now: dt.datetime | None = None) -> dt.datetime:
        now = now or _now()
        expires = now + dt.timedelta(minutes=minutes)
        _private_write(self.path, {"status": "open", "expires_at": _iso(expires)})
        return expires

    def close(self) -> None:
        self.path.unlink(missing_ok=True)

    def request(self, name: str, now: dt.datetime | None = None) -> dict:
        """POST /pair. Only while the window is open and nothing else is pending."""
        now = now or _now()
        state = self._state()
        if not state or self._expired(state, now):
            raise PairingError(403, "pairing window closed")
        if state.get("status") != "open":
            raise PairingError(409, "another pairing request is pending")
        request_id = secrets.token_urlsafe(24)
        code = f"{secrets.randbelow(1000):03d}"
        state.update({"status": "pending", "request_id": request_id, "name": clean_name(name),
                      "code": code, "requested_at": _iso(now)})
        _private_write(self.path, state)
        left = int((dt.datetime.fromisoformat(state["expires_at"]) - now).total_seconds())
        return {"request_id": request_id, "code": code, "expires_in": max(left, 0)}

    def pending(self, now: dt.datetime | None = None) -> dict | None:
        """For the owner on the Pi: the request waiting for approval, if any."""
        state = self._state()
        if not state or state.get("status") != "pending" or self._expired(state, now or _now()):
            return None
        return {"name": state["name"], "code": state["code"]}

    def decide(self, approve: bool) -> None:
        state = self._state()
        if state and state.get("status") == "pending":
            state["status"] = "approved" if approve else "rejected"
            _private_write(self.path, state)

    def status_name(self) -> str:
        state = self._state()
        return state.get("status", "") if state else ""

    def poll(self, request_id: str, registry: PhoneRegistry, now: dt.datetime | None = None) -> dict:
        """GET /pair/<request id>. The token is handed out exactly once, then the window closes."""
        now = now or _now()
        state = self._state()
        if not state or not hmac.compare_digest(str(state.get("request_id", "")).encode(), request_id.encode()):
            raise PairingError(404, "unknown pairing request")
        status = state.get("status")
        if status == "approved":
            phone_id, token = registry.add(state.get("name", ""))
            state.update({"status": "delivered", "phone_id": phone_id})
            _private_write(self.path, state)
            return {"status": "approved", "token": token, "phone_id": phone_id}
        if status in ("open", "pending") and self._expired(state, now):
            return {"status": "expired"}
        return {"status": status if status in ("pending", "rejected", "delivered") else "expired"}
