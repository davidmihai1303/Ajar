import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import httpx
from fastapi.testclient import TestClient

from netcheck.api.app import create_app
from netcheck.explain.llm import ask, personalize
from netcheck.explain.qwen import ManagedQwen
from netcheck.explain.smoke import BASE_RO, EVIDENCE, TELNET


class FixtureRouter:
    def __init__(self):
        self.state = "unloaded"
        self.calls = []
        self.waking = threading.Event()
        self.resume = threading.Event()
        self.resume.set()
        self.fail = False

    def __call__(self, req):
        self.calls.append(req.url.path)
        if req.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "local", "status": {"value": self.state}}]})
        body = json.loads(req.content)
        if req.url.path == "/tokenize":
            assert body == {"model": "local", "content": "."}
            assert req.url.params["autoload"] == "true"
            self.waking.set()
            assert self.resume.wait(2)
            if self.fail:
                raise httpx.ReadTimeout("load timed out")
            self.state = "loaded"
            return httpx.Response(200, json={"tokens": [12]})
        if req.url.path == "/models/unload":
            self.state = "unloaded"
            return httpx.Response(200)
        assert req.url.path == "/v1/chat/completions" and self.state == "loaded"
        options = json.loads(body["messages"][-1]["content"])["options"]
        reply = json.dumps({"refs": [next(iter(options))]})
        return httpx.Response(200, json={"choices": [{"message": {"content": reply}}]})


def test_managed_scope_before_load_and_idle_lifecycle(tmp_path):
    router = FixtureRouter()
    model = ManagedQwen(str(tmp_path), 60, transport=httpx.MockTransport(router))
    assert ask(model, "score", EVIDENCE).source == "scan"
    assert not ask(model, "Is 192.0.2.1 safe?", EVIDENCE).grounded
    assert router.calls == []
    assert personalize(model, TELNET, BASE_RO).source == "static"
    with TestClient(create_app(db=str(tmp_path / "db"), model=model), base_url="http://localhost") as api:
        assert api.get("/api/llm/status").json() == {"state": "idle", "available": False}
        assert set(router.calls) == {"/v1/models"}
        assert ask(model, "Which ports?", EVIDENCE).source == "llm"
        assert api.get("/api/llm/status").json() == {"state": "ready", "available": True}
        router.state = "sleeping"
        assert ask(model, "Ce porturi sunt deschise?", EVIDENCE).source == "llm"
        assert router.calls.count("/tokenize") == 2
        assert api.post("/api/llm/unload").status_code == api.post("/api/llm/unload").status_code == 204
        assert api.get("/api/llm/status").json()["state"] == "idle"


def test_concurrent_questions_share_wake(tmp_path):
    router = FixtureRouter()
    router.resume.clear()
    model = ManagedQwen(str(tmp_path), 60, transport=httpx.MockTransport(router))
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(ask, model, "Which ports?", EVIDENCE)
        assert router.waking.wait(1)
        assert model.status()["state"] == "starting"
        second = pool.submit(ask, model, "What services?", EVIDENCE)
        router.resume.set()
        assert first.result().grounded and second.result().grounded
    assert router.calls.count("/tokenize") == 1


def test_unload_cancels_cold_question(tmp_path):
    router = FixtureRouter()
    router.resume.clear()
    model = ManagedQwen(str(tmp_path), 60, transport=httpx.MockTransport(router))
    with ThreadPoolExecutor(1) as pool:
        pending = pool.submit(ask, model, "Which ports?", EVIDENCE)
        assert router.waking.wait(1)
        assert model.unload()
        router.resume.set()
        assert pending.result().unavailable
    assert "/v1/chat/completions" not in router.calls
    assert model.status()["state"] == "idle"


def test_cold_timeout_and_retry(tmp_path):
    router = FixtureRouter()
    router.fail = True
    model = ManagedQwen(str(tmp_path), 60, transport=httpx.MockTransport(router))
    assert ask(model, "Which ports?", EVIDENCE).unavailable
    assert model.status()["reason"] == "timeout"
    router.fail = False
    assert ask(model, "Which ports?", EVIDENCE).grounded


def test_turn_off_waits_for_router_to_release_worker(tmp_path):
    states = iter(["loaded", "timeout", "sleeping", "unloaded"])
    def acknowledge(req):
        if req.url.path == "/models/unload":
            return httpx.Response(200, json={"success": True})
        state = next(states)
        if state == "timeout":
            raise httpx.ReadTimeout("router busy")
        return httpx.Response(200, json={"data": [{"id": "local", "status": {"value": state}}]})
    model = ManagedQwen(str(tmp_path), 60, transport=httpx.MockTransport(acknowledge))
    assert model.unload()
    assert list(states) == []


def test_turn_off_reports_failure_if_shutdown_cannot_be_confirmed(tmp_path, monkeypatch):
    elapsed = 0.0
    def advance(seconds):
        nonlocal elapsed
        elapsed += seconds
    monkeypatch.setattr("netcheck.explain.qwen.time", SimpleNamespace(monotonic=lambda: elapsed, sleep=advance))

    def router(req):
        if req.url.path == "/models/unload":
            return httpx.Response(200)
        raise httpx.ReadTimeout("worker status unknown")

    model = ManagedQwen(str(tmp_path), 60, transport=httpx.MockTransport(router))
    with TestClient(create_app(db=str(tmp_path / "db"), model=model), base_url="http://localhost") as api:
        response = api.post("/api/llm/unload")
        assert response.status_code == 503 and response.json()["detail"] == "unload_failed"
    assert elapsed >= 12


def test_turn_off_distinguishes_absent_socket_from_connection_failure(tmp_path):
    def unreachable(req):
        raise httpx.ConnectError("cannot reach router")

    model = ManagedQwen(str(tmp_path), 60, transport=httpx.MockTransport(unreachable))
    assert model.unload()
    (tmp_path / "router.sock").touch()
    assert not model.unload()


def test_unreachable_private_socket_never_posts_to_tcp(tmp_path, monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket, "connect_ex", lambda *args: 0)
    model = ManagedQwen(str(tmp_path), 60)
    assert model.status()["reason"] == "port"
    assert ask(model, "Which ports?", EVIDENCE).unavailable
    for reason in ("gpu", "weights", "memory"):
        (tmp_path / "failure").write_text(reason)
        assert model.status()["reason"] == reason
