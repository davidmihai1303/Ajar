"""Manual check against the real LLM (e.g. llama-server on the MSI). Not part of pytest.

    docker compose run --rm app python -m netcheck.explain.smoke
    # or on the host:  LLM_BASE_URL=http://127.0.0.1:8080/v1 python -m netcheck.explain.smoke

Prints, for each call, whether the model's output was accepted ("llm") or replaced by the
built-in text ("static"/"fallback") and why. Uses made-up lab-like data, no scan needed.
"""
import time
import argparse

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

BASE_STREAM_EN = StaticText("Other devices on this network can reach this media stream.",
                            ("Open the device's sharing settings.", "Turn off streaming if you do not use it."))


def verify_qwen(client: LLMClient) -> None:
    """A failing process exit makes an accidental static fallback visible at rehearsal."""
    if not client.unload() or client.status().get("state") != "idle":
        raise SystemExit("The managed router must be reachable and idle")
    for lang, question in (("en", "Which ports are open on 172.20.10.11?"),
                           ("ro", "Ce porturi sunt deschise pe 172.20.10.11?")):
        start = time.monotonic()
        answer = ask(client, question, EVIDENCE, lang)
        print(f"{lang} {answer.source} {time.monotonic()-start:.2f}s {answer.text}", flush=True)
        if answer.source != "llm" or not answer.grounded:
            raise SystemExit("The real model did not return accepted evidence")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-qwen", action="store_true")
    args = parser.parse_args()
    client = LLMClient.from_config()
    if args.verify_qwen:
        verify_qwen(client)
        return
    print(f"endpoint: {client.base_url or '(not set)'} | enabled: {client.enabled} | available: {client.available()}")
    for title, call in [
        ("personalize TELNET (ro)", lambda: personalize(client, TELNET, BASE_RO, "ro")),
        ("personalize AirPlay-as-rtsp (en)", lambda: personalize(client, AIRPLAY, BASE_STREAM_EN, "en")),
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
