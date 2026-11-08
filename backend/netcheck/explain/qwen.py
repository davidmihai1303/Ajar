"""Lifecycle of the bundled llama.cpp router. Only inference can wake its worker."""
from pathlib import Path
import socket
import threading
import time

import httpx

from .llm import LLMClient


class ManagedQwen(LLMClient):
    def __init__(self, directory: str, timeout: float, *, transport: httpx.BaseTransport | None = None):
        super().__init__("http://127.0.0.1:8080/v1", model="local", timeout=timeout)
        self.directory = Path(directory)
        self.socket = self.directory / "router.sock"
        self.transport = transport  # Optional in-process transport for fixture tests.
        self.lifecycle = threading.Lock()
        self.stop_lock = threading.Lock()
        self.stopping = False
        self.generation = 0
        self.waking = False
        self.last_failure: str | None = None

    def _client(self, timeout: float) -> httpx.Client:
        # The URL remains loopback. The shared private socket pins every HTTP request
        # to our container, even if an unrelated process takes over TCP port 8080.
        try:
            key = (self.directory / "router.key").read_text().strip()
        except OSError:
            key = ""
        transport = self.transport or httpx.HTTPTransport(uds=str(self.socket))
        return httpx.Client(base_url=self.base_url, transport=transport, timeout=timeout,
                            headers={"Authorization": f"Bearer {key}"} if key else {},
                            trust_env=False, follow_redirects=False)

    def _reason(self, fallback: str) -> str:
        marker = self.directory / "failure"
        try:
            reason = marker.read_text().strip()
            if fallback == "server" and reason == "starting" and time.time() - marker.stat().st_mtime < 120:
                return "booting"
        except OSError:
            return fallback
        return reason if reason in {"weights", "gpu", "memory", "port"} else fallback

    def _router_state(self) -> tuple[str, str | None]:
        try:
            with self._client(2) as client:
                response = client.get("/models")
                response.raise_for_status()
                models = response.json()["data"]
                model = next((m for m in models if m["id"] == self.model), None)
                if not model:
                    return "failed", "weights"
                status = model["status"]
                if status.get("failed"):
                    return "failed", self._reason("load")
                states = {"loaded": "ready", "sleeping": "idle", "unloaded": "idle", "loading": "starting"}
                return states[status["value"]], None
        except httpx.ConnectError:
            reason = self._reason("server")
            if reason == "booting":
                return "booting", None
            if reason == "server":
                # Diagnose a conflict without sending the listener any HTTP data.
                with socket.socket() as probe:
                    probe.settimeout(0.2)
                    if probe.connect_ex(("127.0.0.1", 8080)) == 0:
                        reason = "port"
            return "failed", reason
        except (httpx.HTTPError, KeyError, TypeError, ValueError, AttributeError):
            return "failed", "server"

    def status(self) -> dict:
        state, reason = self._router_state()
        if state == "booting":
            state = "starting"
        with self._lock:
            if self.waking and state != "ready":
                state, reason = "starting", None
            elif self.last_failure and state != "ready" and reason in (None, "load"):
                state, reason = "failed", self.last_failure
        return {"available": state == "ready", "state": state, "reason": reason}

    def available(self) -> bool:
        return self.status()["available"]

    def can_personalize(self) -> bool:
        return self.available()

    def prepare_inference(self) -> bool:
        deadline = time.monotonic() + 120
        with self._lock:
            if self.stopping:
                return False
            generation = self.generation
        if not self.lifecycle.acquire(timeout=120):
            return False
        try:
            with self._lock:
                if generation != self.generation or self.stopping:
                    return False
                self.last_failure = None
            state, reason = self._router_state()
            while state == "booting":
                with self._lock:
                    if generation != self.generation:
                        return False
                if time.monotonic() >= deadline:
                    raise httpx.ReadTimeout("router startup")
                time.sleep(0.25)
                state, reason = self._router_state()
            if state == "ready":
                return True
            if reason in {"server", "port", "weights", "gpu"}:
                return False
            with self._lock:
                self.waking = True
            # The router coalesces loads. A fixed tokenization request wakes both an
            # unloaded and a sleeping worker before the normal chat timeout begins.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise httpx.ReadTimeout("cold start")
            with self._client(remaining) as client:
                response = client.post("http://127.0.0.1:8080/tokenize?autoload=true",
                                       json={"model": self.model, "content": "."})
                response.raise_for_status()
            with self._lock:
                return generation == self.generation
        except httpx.HTTPError as exc:
            with self._lock:
                self.last_failure = self._reason("timeout" if isinstance(exc, httpx.TimeoutException) else "load")
            return False
        finally:
            with self._lock:
                cancelled = generation != self.generation
                self.waking = False
            if cancelled:
                self._unload_worker()
            self.lifecycle.release()

    def _unload_worker(self) -> bool:
        try:
            with self._client(12) as client:
                response = client.post("http://127.0.0.1:8080/models/unload", json={"model": self.model})
                if not response.is_success:
                    if response.status_code != 400 or "not running" not in response.json()["error"]["message"]:
                        return False
            # The router acknowledges unload before its worker has exited.
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                state, _ = self._router_state()
                if state in {"idle", "failed"}:
                    return True
                time.sleep(0.1)
        except httpx.ConnectError:
            return True  # No managed worker is listening.
        except (httpx.HTTPError, KeyError, ValueError, TypeError):
            pass
        return False

    def unload(self) -> bool:
        with self.stop_lock:
            with self._lock:
                self.stopping = True
                self.generation += 1
                self.last_failure = None
                self._cache.clear()
            try:
                return self._unload_worker()
            finally:
                with self._lock:
                    self.stopping = False
