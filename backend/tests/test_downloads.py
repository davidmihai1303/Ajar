"""The desktop app download: only Ajar AppImage / .deb files from the configured folder."""
import os

from fastapi.testclient import TestClient

from netcheck.api.app import create_app
from netcheck.explain.llm import LLMClient


def _client(tmp_path, folder):
    app = create_app(db=str(tmp_path / "db"), scans_dir=str(tmp_path), model=LLMClient(), downloads_dir=str(folder))
    return TestClient(app, base_url="http://localhost")


def test_lists_and_serves_only_ajar_packages(tmp_path):
    folder = tmp_path / "downloads"
    folder.mkdir()
    (folder / "Ajar-1.0.0-x86_64.AppImage").write_bytes(b"appimage")
    (folder / "Ajar-1.0.0-arm64.deb").write_bytes(b"debian")
    (folder / "notes.txt").write_text("not offered")
    (folder / "Ajar-evil.sh").write_text("not offered")
    secret = tmp_path / "secret.AppImage"
    secret.write_text("outside")
    os.symlink(secret, folder / "Ajar-link.AppImage")
    with _client(tmp_path, folder) as client:
        assert client.get("/api/downloads").json() == [
            {"name": "Ajar-1.0.0-arm64.deb", "size": 6, "arch": "arm64", "kind": "deb"},
            {"name": "Ajar-1.0.0-x86_64.AppImage", "size": 8, "arch": "x64", "kind": "appimage"},
        ]
        response = client.get("/downloads/Ajar-1.0.0-x86_64.AppImage")
        assert response.status_code == 200 and response.content == b"appimage"
        assert "attachment" in response.headers["content-disposition"]
        for name in ("notes.txt", "Ajar-evil.sh", "Ajar-link.AppImage", "..%2Fsecret.AppImage"):
            assert client.get("/downloads/" + name).status_code == 404


def test_missing_folder_offers_nothing(tmp_path):
    with _client(tmp_path, tmp_path / "absent") as client:
        assert client.get("/api/downloads").json() == []
        assert client.get("/downloads/Ajar-1.0.0-x86_64.AppImage").status_code == 404
