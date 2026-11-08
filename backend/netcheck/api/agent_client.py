"""Server-side client for the existing, consent-gated loopback scanner."""
import hashlib
import hmac
import json
import secrets

import httpx
from fastapi import HTTPException
from pydantic import ValidationError

from netcheck.analysis.privacy import mask_macs_in_text
from .schemas import Network


class AgentClient:
    def __init__(self, url: str, transport: httpx.BaseTransport | None = None):
        base = httpx.URL(url)
        if (base.scheme != "http" or base.host not in ("127.0.0.1", "localhost")
                or base.userinfo or base.query or base.fragment or base.path != "/"):
            raise ValueError("NETCHECK_AGENT_URL must be a local HTTP origin")
        self._key = secrets.token_bytes(32)
        self._http = httpx.Client(base_url=base.copy_with(host="127.0.0.1"), transport=transport,
                                  follow_redirects=False, trust_env=False, timeout=4.0)

    def close(self) -> None:
        self._http.close()

    def _read(self, response: httpx.Response) -> dict:
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code in (403, 503) and isinstance(data, dict):
            if isinstance(data.get("ro"), str) and isinstance(data.get("en"), str):
                raise HTTPException(response.status_code, {"reason_ro": mask_macs_in_text(data["ro"]),
                                                           "reason_en": mask_macs_in_text(data["en"])})
        if response.status_code == 409:
            raise HTTPException(409, "scan_busy")
        if response.status_code != 200 or not isinstance(data, dict):
            raise HTTPException(502, "invalid_agent_response")
        return data

    @staticmethod
    def identity(data: dict) -> Network:
        try:
            return Network(interface=data["interface"], subnet=data["subnet"],
                           gateway=data["gateway"] or None, ssid=data["ssid"] or None)
        except (KeyError, TypeError, ValidationError):
            raise HTTPException(502, "invalid_agent_network") from None

    def detect(self) -> Network:
        try:
            return self.identity(self._read(self._http.get("/network")))
        except httpx.RequestError:
            raise HTTPException(503, "agent_unavailable") from None

    def public(self, raw: Network) -> Network:
        fields = raw.model_dump(exclude={"confirmation_id"})
        masked = {k: mask_macs_in_text(v) if v else v for k, v in fields.items()}
        # Two SSIDs may look identical after masking. Bind consent to the original identity.
        token = hmac.digest(self._key, json.dumps(fields, sort_keys=True).encode(), "sha256").hex() if masked != fields else None
        return Network(**masked, confirmation_id=token)

    @staticmethod
    def history_id(raw: Network) -> str | None:
        if not (raw.ssid and raw.gateway and raw.subnet and raw.interface):
            return None
        identity = json.dumps([raw.interface, raw.subnet, raw.gateway, raw.ssid]).encode()
        return hashlib.sha256(identity).hexdigest()

    def confirmed_scan(self, expected: Network) -> tuple[str, Network]:
        current = self.detect()
        if self.public(current) != expected:
            raise HTTPException(403, {"reason_ro": "Rețeaua s-a schimbat. Confirmă din nou.",
                                      "reason_en": "The network changed. Confirm it again."})
        body = {"confirm": True, "expected_network": current.model_dump(exclude={"confirmation_id"})}
        try:
            result = self._read(self._http.post("/scan", json=body, timeout=httpx.Timeout(675, connect=4)))
        except httpx.TimeoutException:
            raise HTTPException(504, "agent_timeout") from None
        except httpx.RequestError:
            raise HTTPException(503, "agent_unavailable") from None
        if (not isinstance(result.get("network"), dict) or self.identity(result["network"]) != current
                or not isinstance(result.get("xml_path"), str)):
            raise HTTPException(502, "invalid_scan_result")
        return result["xml_path"], current
