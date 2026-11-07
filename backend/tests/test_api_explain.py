from pathlib import Path

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
