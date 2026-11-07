"""Manual check against the real LLM (e.g. llama-server on the MSI). Not part of pytest.

    docker compose run --rm app python -m netcheck.explain.smoke
    # or on the host:  LLM_BASE_URL=http://127.0.0.1:8080/v1 python -m netcheck.explain.smoke

Prints, for each call, whether the model's output was accepted ("llm") or replaced by the
built-in text ("static"/"fallback") and why. Uses made-up lab-like data, no scan needed.
"""
import time

from netcheck.explain.llm import (EvidenceDevice, EvidenceFinding, EvidencePort, LLMClient,
                                  ScanEvidence, StaticText, ask, personalize)

TELNET = EvidenceFinding(code="TELNET_OPEN", severity="high", ip="172.20.10.11", port=2323, protocol="tcp",
                         service="telnet", product="Linux telnetd", device_type="laptop", vendor="")
AIRPLAY = EvidenceFinding(code="CAMERA_STREAM_EXPOSED", severity="high", ip="172.20.10.11", port=7000,
                          protocol="tcp", service="rtsp", device_type="laptop", vendor="Apple")
EVIDENCE = ScanEvidence(
    score=0,
    devices=(EvidenceDevice(ip="172.20.10.11", device_type="laptop", open_ports=(
        EvidencePort(2323, "tcp", "telnet", "Linux telnetd"),
        EvidencePort(7000, "tcp", "rtsp"),
        EvidencePort(8080, "tcp", "http", "nginx", "1.31.8", "Router Admin Login"))),),
    findings=(TELNET, AIRPLAY),
)
BASE_RO = StaticText("Oricine din rețea se poate conecta la acest dispozitiv fără ca datele să fie criptate.",
                     ("Oprește serviciul Telnet.", "Folosește SSH dacă ai nevoie de acces de la distanță."))


def main() -> None:
    client = LLMClient.from_config()
    print(f"endpoint: {client.base_url or '(not set)'} | enabled: {client.enabled} | available: {client.available()}")
    for title, call in [
        ("personalize TELNET (ro)", lambda: personalize(client, TELNET, BASE_RO, "ro")),
        ("personalize AirPlay-as-rtsp (en)", lambda: personalize(client, AIRPLAY, BASE_RO, "en")),
        ("ask: is port 7000 a camera? (en)", lambda: ask(client, "Is the thing on port 7000 a camera?", EVIDENCE, "en")),
        ("ask: what is my Wi-Fi password? (ro)", lambda: ask(client, "Care e parola de la Wi-Fi?", EVIDENCE, "ro")),
    ]:
        t0 = time.monotonic()
        r = call()
        print(f"\n== {title}  [{r.source}, {time.monotonic() - t0:.1f}s]")
        print(getattr(r, "explanation", None) or r.text)
        for step in getattr(r, "fixes", []):
            print("  -", step)
        if r.problems:
            print("  rejected because:", "; ".join(r.problems))


if __name__ == "__main__":
    main()
