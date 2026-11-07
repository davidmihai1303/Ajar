"""Run the actual application with a temporary DB, a fixture agent and the model off."""
import socket
import sys
from pathlib import Path

import httpx
import uvicorn

from netcheck.api.agent_client import AgentClient
from netcheck.api.app import create_app
from netcheck.explain.llm import LLMClient


def main(directory: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    xml = root / "backend/tests/fixtures/validation/V6a_before.xml"
    (directory / "report.xml").write_bytes(xml.read_bytes())

    def fixture(request: httpx.Request) -> httpx.Response:
        network = {"ssid": (directory / "ssid").read_text(), "subnet": "192.168.1.0/24",
                   "interface": "fixture0", "gateway": "192.168.1.1"}
        if request.url.path == "/network":
            return httpx.Response(200, json=network)
        assert request.url.path == "/scan" and request.method == "POST"
        with (directory / "dispatches").open("ab") as out:
            out.write(request.content + b"\n")
        return httpx.Response(200, json={"network": network, "xml_path": "/var/lib/netcheck/scans/report.xml"})

    app = create_app(db=str(directory / "db"), scans_dir=str(directory), static_dir=root / "frontend/dist",
                     model=LLMClient(), agent=AgentClient("http://127.0.0.1", httpx.MockTransport(fixture)))
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        print(sock.getsockname()[1], flush=True)
        server.run(sockets=[sock])


if __name__ == "__main__":
    main(Path(sys.argv[1]))
