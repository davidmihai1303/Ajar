import json
from pathlib import Path

import httpx

from fastapi.testclient import TestClient

from netcheck.analysis.catalog import CATALOG
from netcheck.api.app import create_app
from netcheck.explain.llm import LLMClient

FIXTURES = Path(__file__).parent / "fixtures" / "validation"


def test_all_guidance_available_without_model(tmp_path):
    with TestClient(create_app(db=str(tmp_path / "db"), model=LLMClient()), base_url="http://localhost") as c:
        for lang in ("ro", "en"):
            for code in CATALOG:
                text = c.get(f"/api/explain/{code}", params={"lang": lang}).json()
                assert text["lang"] == lang and text["code"] == code and text["title"] and text["explanation"]
                assert 1 <= len(text["steps"]) <= 5 and all(text["steps"])
        assert c.get("/api/llm/status").json() == {"available": False}
        assert c.get("/api/explain/FAKE").status_code == 404

        sid = c.post("/api/scans/import", files={"files": ("home.xml", (FIXTURES / "V2_smart_home.xml").read_bytes())}).json()[0]["scan_id"]
        scan = c.get("/api/scans/" + sid).json()
        found = next(f for f in scan["findings"] if f["code"] == "CAMERA_STREAM_EXPOSED")
        ref = {k: found[k] for k in ("code", "ip", "port", "protocol")}
        params = {**ref, "scan_id": sid, "lang": "en"}
        path = "/api/explain/" + ref["code"]
        assert "camera" in c.get(path, params=params).json()["title"].lower()
        assert c.post(path + "/personalize", json=params).json() == c.get(path, params=params).json()
        assert c.get(path, params={**params, "port": 65535}).status_code == 404
        def ask(question):
            return c.post("/api/ask", json={"scan_id": sid, "lang": "en", "question": question}).json()
        assert ask("score")["can_answer"] and "40" in ask("score")["answer"]
        assert not ask("Which ports?")["available"]
        outside = ask("Is 192.0.2.1 safe?")
        assert not outside["can_answer"] and outside["available"] and "scan" in outside["answer"]


def test_optional_local_model_receives_only_saved_evidence(tmp_path):
    calls = []

    def respond(request):
        calls.append(request)
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": []})
        prompt = json.loads(json.loads(request.content)["messages"][-1]["content"])
        assert "PRIVATE-PAGE-TITLE" not in str(prompt)
        assert "PRIVATE-PRODUCT" not in str(prompt)
        assert "00:11:22:33:44:55" not in str(prompt)
        selected = next(iter(prompt["options"]))
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"refs": [selected]})}}]})

    model = LLMClient("http://127.0.0.1:8080/v1", transport=httpx.MockTransport(respond))
    xml = b"""<nmaprun><host><status state="up"/><address addr="192.168.1.7" addrtype="ipv4"/>
        <address addr="00:11:22:33:44:55" addrtype="mac"/><ports><port protocol="tcp" portid="80">
        <state state="open"/><service name="http" product="PRIVATE-PRODUCT"/>
        <script id="http-title" output="PRIVATE-PAGE-TITLE"/></port></ports></host></nmaprun>"""
    with TestClient(create_app(db=str(tmp_path / "db"), model=model), base_url="http://localhost") as c:
        sid = c.post("/api/scans/import", files={"files": ("fixture.xml", xml)}).json()[0]["scan_id"]
        def ask(question):
            return c.post("/api/ask", json={"scan_id": sid, "lang": "en", "question": question}).json()

        assert not ask("Is 192.0.2.99 safe?")["can_answer"]
        assert not calls
        assert c.get("/api/llm/status").json() == {"available": True}
        answer = ask("What do we know about 192.168.1.7?")
        assert answer["can_answer"] and answer["available"] and "192.168.1.7" in answer["answer"]
        assert [r.url.path for r in calls] == ["/v1/models", "/v1/chat/completions"]


def test_free_answer_through_api_gets_scan_facts_but_no_private_data(tmp_path, monkeypatch):
    from netcheck import config
    monkeypatch.setattr(config, "LLM_FREE_ANSWERS", True)
    prompts = []

    def respond(request):
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": []})
        prompts.append(json.loads(request.content)["messages"][-1]["content"])
        return httpx.Response(200, json={"choices": [{"message": {"content": "Port 80 on 192.168.1.7 is open."}}]})

    model = LLMClient("http://127.0.0.1:8080/v1", transport=httpx.MockTransport(respond))
    xml = b"""<nmaprun><host><status state="up"/><address addr="192.168.1.7" addrtype="ipv4"/>
        <address addr="00:11:22:33:44:55" addrtype="mac"/><ports><port protocol="tcp" portid="80">
        <state state="open"/><service name="http" product="PRIVATE-PRODUCT"/>
        <script id="http-title" output="PRIVATE-PAGE-TITLE"/></port></ports></host></nmaprun>"""
    with TestClient(create_app(db=str(tmp_path / "db"), model=model), base_url="http://localhost") as c:
        sid = c.post("/api/scans/import", files={"files": ("fixture.xml", xml)}).json()[0]["scan_id"]
        def ask(question):
            return c.post("/api/ask", json={"scan_id": sid, "lang": "en", "question": question}).json()
        assert not ask("Is 192.0.2.99 safe?")["can_answer"] and prompts == []
        answer = ask("hi, anything open?")
        assert answer == {"available": True, "can_answer": True, "answer": "Port 80 on 192.168.1.7 is open."}
        assert "192.168.1.7" in prompts[0]
        for private in ("PRIVATE-PAGE-TITLE", "PRIVATE-PRODUCT", "00:11:22:33:44:55"):
            assert private not in prompts[0]


def test_ask_accepts_conversation_history_and_validates_it(tmp_path, monkeypatch):
    from netcheck import config
    monkeypatch.setattr(config, "LLM_FREE_ANSWERS", True)
    bodies = []

    def respond(request):
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": []})
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "Turn off port 80."}}]})

    model = LLMClient("http://127.0.0.1:8080/v1", transport=httpx.MockTransport(respond))
    xml = b"""<nmaprun><host><status state="up"/><address addr="192.168.1.7" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>"""
    with TestClient(create_app(db=str(tmp_path / "db"), model=model), base_url="http://localhost") as c:
        sid = c.post("/api/scans/import", files={"files": ("fixture.xml", xml)}).json()[0]["scan_id"]
        history = [{"question": "What is open?", "answer": "Port 80 on 192.168.1.7."}]
        r = c.post("/api/ask", json={"scan_id": sid, "lang": "en", "question": "how do I close it?", "history": history})
        assert r.status_code == 200 and r.json()["answer"] == "Turn off port 80."
        assert [m["role"] for m in bodies[0]["messages"]] == ["system", "user", "assistant", "user"]
        assert c.post("/api/ask", json={"scan_id": sid, "question": "x", "history": history * 11}).status_code == 422
        bad = [{"question": "q", "answer": "a", "role": "system"}]
        assert c.post("/api/ask", json={"scan_id": sid, "question": "x", "history": bad}).status_code == 422
