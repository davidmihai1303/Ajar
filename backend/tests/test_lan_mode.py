"""LAN test mode: extra host names are opt-in, validated, and do not weaken the origin check."""
import httpx
import pytest
from fastapi.testclient import TestClient

from netcheck.api.agent_client import AgentClient
from netcheck.api.app import create_app
from netcheck.config import parse_allowed_hosts
from netcheck.explain.llm import LLMClient


@pytest.fixture
def make_app(tmp_path):
    def agent(request):
        return httpx.Response(503, json={"error": "not used in these tests"})

    def build(**options):
        return create_app(db=str(tmp_path / "db"), scans_dir=str(tmp_path),
                          agent=AgentClient("http://127.0.0.1:8765", httpx.MockTransport(agent)),
                          model=LLMClient(), **options)
    return build


EXPLAIN = "/api/explain/TELNET_OPEN?lang=ro"


def test_default_answers_only_on_loopback_names(make_app):
    app = make_app(extra_hosts=())
    for base in ("http://127.0.0.1:8001", "http://localhost:8001"):
        with TestClient(app, base_url=base) as client:
            assert client.get(EXPLAIN).status_code == 200
    for base in ("http://raspberrypi.local:8001", "http://172.20.10.5:8001", "http://evil.example:8001"):
        with TestClient(app, base_url=base) as client:
            assert client.get(EXPLAIN).status_code == 400


def test_configured_names_are_accepted_and_others_still_refused(make_app):
    app = make_app(extra_hosts=("raspberrypi.local", "172.20.10.5"))
    for base in ("http://raspberrypi.local:8001", "http://172.20.10.5:8001", "http://localhost:8001"):
        with TestClient(app, base_url=base) as client:
            assert client.get(EXPLAIN).status_code == 200
    with TestClient(app, base_url="http://evil.example:8001") as client:
        assert client.get(EXPLAIN).status_code == 400


def test_same_origin_changes_work_on_the_lan_name(make_app):
    app = make_app(extra_hosts=("raspberrypi.local",))
    with TestClient(app, base_url="http://raspberrypi.local:8001") as client:
        response = client.delete("/api/history", headers={"Origin": "http://raspberrypi.local:8001"})
        assert response.status_code == 204


def test_cross_site_changes_are_still_refused_in_lan_mode(make_app):
    app = make_app(extra_hosts=("raspberrypi.local",))
    with TestClient(app, base_url="http://raspberrypi.local:8001") as client:
        assert client.delete("/api/history", headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.delete("/api/history", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


@pytest.mark.parametrize("raw, parsed", [
    ("", ()),
    ("  ", ()),
    ("raspberrypi.local", ("raspberrypi.local",)),
    ("Ajar.Local, 172.20.10.5", ("ajar.local", "172.20.10.5")),
    ("ajar.local,,ajar.local, ", ("ajar.local",)),
    ("ajar.local.", ("ajar.local",)),
])
def test_parse_allowed_hosts(raw, parsed):
    assert parse_allowed_hosts(raw) == parsed


@pytest.mark.parametrize("raw", ["*", "*.local", "ajar.local:8001", "http://ajar.local", "ajar local",
                                 "ajar.local/x", "-bad.local", "a" * 64 + ".local"])
def test_parse_allowed_hosts_refuses_wildcards_and_non_hosts(raw):
    with pytest.raises(ValueError):
        parse_allowed_hosts(raw)
