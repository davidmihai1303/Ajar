import csv
import json
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from netcheck.api.agent_client import AgentClient
from netcheck.api.app import create_app
from netcheck.explain.llm import LLMClient

FIXTURES = Path(__file__).parent / "fixtures" / "validation"
NET = {"interface": "fixture0", "subnet": "192.168.1.0/24", "ssid": "Fixture", "gateway": "192.168.1.1"}


@pytest.fixture
def setup(tmp_path):
    calls = []
    state = {"network": NET.copy(), "path": "/var/lib/netcheck/scans/report.xml"}

    def agent(request):
        if request.url.path == "/network":
            return httpx.Response(200, json=state["network"])
        calls.append(json.loads(request.content))
        return httpx.Response(200, json={"network": state["network"], "xml_path": state["path"]})

    def app(**options):
        return create_app(db=str(tmp_path / "db"), scans_dir=str(tmp_path),
                          agent=AgentClient("http://127.0.0.1:8765", httpx.MockTransport(agent)),
                          model=LLMClient(), **options)
    (tmp_path / "report.xml").write_bytes((FIXTURES / "V6a_before.xml").read_bytes())
    return app, state, calls


def test_public_validation_through_http(setup):
    app, _, calls = setup
    files = sorted(FIXTURES.glob("*.xml"))
    with TestClient(app(), base_url="http://localhost") as client:
        assert client.get("/api/history").json() == []
        rows = client.post("/api/scans/import", files=[("files", (p.name, p.read_bytes())) for p in files]).json()
        assert [r["file"] for r in rows] == [p.name for p in files]
        with (FIXTURES / "expected_scores.csv").open() as f:
            scores = {r["file"]: r["network_score"] for r in csv.DictReader(f)}
        assert {r["file"]: str(r["score"]) if r["error"] is None else "ERROR" for r in rows} == scores
        all_findings = []
        ids = {}
        for row in rows:
            ids[row["file"]] = row["scan_id"]
            scan = client.get("/api/scans/" + row["scan_id"]).json()
            assert scan["source"] == "import" and scan["network_id"] is None and scan["ssid"] is None
            assert scan["findings_available"] == (row["error"] is None)
            for f in scan["findings"]:
                all_findings.append((row["file"], f["ip"], "" if f["port"] is None else str(f["port"]),
                                     f["code"], f["severity"]))
        with (FIXTURES / "expected_findings.csv").open() as f:
            assert sorted(all_findings) == sorted(map(tuple, list(csv.reader(f))[1:]))
        params = {"from": ids["V6a_before.xml"], "to": ids["V6b_after.xml"]}
        diff = client.get("/api/history/diff", params=params).json()
        assert (diff["score_before"], diff["score_after"], len(diff["findings_resolved"])) == (60, 100, 3)
        params["to"] = ids["V7_broken.xml"]
        assert client.get("/api/history/diff", params=params).status_code == 409
        assert not calls
    with TestClient(app(), base_url="http://localhost") as client:
        assert len(client.get("/api/history").json()) == 8
        assert client.delete("/api/history").status_code == 204
        assert client.delete("/api/history").content == b""
        assert client.get("/api/scans/" + params["from"]).status_code == 404


def test_previous_database_preserves_scan_with_only_a_score(setup, tmp_path):
    app, _, _ = setup
    with TestClient(app(), base_url="http://localhost") as client:
        assert client.get("/api/history").json() == []
    with sqlite3.connect(tmp_path / "db") as conn:
        conn.execute("DROP TABLE scan_origin")
        conn.execute("PRAGMA user_version = 4")
        conn.execute("""INSERT INTO scans(scan_id, created_at, score, findings_available)
                        VALUES ('legacy', '2025-01-01T00:00:00+00:00', 85, 0)""")
    with TestClient(app(), base_url="http://localhost") as client:
        for record in [client.get("/api/history").json()[0], client.get("/api/scans/legacy").json()]:
            assert record["file"] == "legacy" and record["score"] == 85
            assert record["source"] == "unknown" and record["network_id"] is None
            assert not record["findings_available"]
        assert client.get("/api/history/diff", params={"from": "legacy", "to": "legacy"}).status_code == 409


def test_scans_require_matching_confirmation(setup):
    app, state, calls = setup
    with TestClient(app(), base_url="http://localhost") as client:
        state["network"]["ssid"] = "wifi-00:11:22:33:44:55"
        expected = client.get("/api/network").json()
        assert "33:44:55" not in str(expected)
        assert client.post("/api/scans", json={"confirm": True}).status_code == 422
        body = {"confirm": False, "expected_network": expected}
        assert client.post("/api/scans", json=body).status_code == 403
        body["confirm"] = True
        state["network"]["ssid"] = "wifi-00:11:22:66:77:88"
        assert client.post("/api/scans", json=body).status_code == 403
        assert not calls
        body["expected_network"] = client.get("/api/network").json()
        scan = client.post("/api/scans", json=body).json()
        assert scan["source"] == "live" and scan["network_id"] and scan["score"] == 60
        assert calls == [{"confirm": True, "expected_network": state["network"]}]
        assert "66:77:88" not in str(scan)
        state["path"] = "/other/report.xml"
        assert client.post("/api/scans", json=body).status_code == 502


def test_upload_limits_privacy_and_origins(setup):
    app, _, _ = setup
    with TestClient(app(max_xml=100), base_url="http://localhost") as client:
        records = client.post("/api/scans/import", files=[("files", ("private-112233445566.xml", b"x"*101)),
                              ("files", ("ok.xml", b"<nmaprun/>"))]).json()
        assert records[0]["error"] == "too_large" and "445566" not in str(records)
        assert records[1]["score"] == 100
        assert client.post("/api/scans/import", files={"files": ("big.xml", b"x"*1100000)}).status_code == 413
        assert client.delete("/api/history", headers={"origin": "https://elsewhere.example"}).status_code == 403
        assert client.get("/api/history", headers={"host": "elsewhere.example"}).status_code == 400
        assert len(client.get("/api/history").json()) == 2
