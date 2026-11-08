"""LLM layer: grounding, fallbacks, privacy and prompt-injection handling. No real model needed."""
import csv
import json
from dataclasses import replace
from pathlib import Path
from xml.etree import ElementTree

import httpx
import pytest

from netcheck.explain import llm
from netcheck.explain.llm import (EvidenceDevice, EvidenceFinding, EvidencePort, LLMClient,
                                  ScanEvidence, StaticText, ask, personalize)

PRINTER = EvidenceFinding(code="PRINTER_RAW_EXPOSED", severity="low", ip="192.168.1.10", port=9100,
                          protocol="tcp", service="jetdirect", device_type="printer", vendor="HP",
                          hostname="office-printer")
BASE = StaticText("Anyone on the network can send print jobs to this printer.",
                  ("Open the printer's settings.", "Turn off raw printing (port 9100) if you don't use it."))
EVIDENCE = ScanEvidence(
    score=45,
    devices=(EvidenceDevice(ip="192.168.1.10", vendor="HP", hostname="office-printer", device_type="printer",
                            open_ports=(EvidencePort(9100, "tcp", "jetdirect"),
                                        EvidencePort(631, "tcp", "ipp", "CUPS", "2.4"))),),
    findings=(PRINTER,),
)


def fake_llm(reply, status: int = 200, seen: list = None, base_url: str = "http://127.0.0.1:8080/v1",
             **kw) -> LLMClient:
    """Client whose server answers with `reply` (str, or callable(request) -> str)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": []})
        body = json.loads(request.content)
        if seen is not None:
            seen.append(body)
        if isinstance(reply, Exception):
            raise reply
        content = reply(body) if callable(reply) else reply
        return httpx.Response(status, json={"choices": [{"message": {"content": content}}]})
    return LLMClient(base_url=base_url, model="test", transport=httpx.MockTransport(handler), **kw)


@pytest.mark.parametrize("endpoint", ["https://example.invalid/v1", "http://192.168.1.5/v1",
                                      "http://host.docker.internal/v1", "file:///tmp/model", "http://["])
def test_only_loopback_models_allowed_even_with_old_opt_in(endpoint, monkeypatch):
    monkeypatch.setenv("LLM_ALLOW_REMOTE", "1")
    seen = []
    client = fake_llm("unused", seen=seen, base_url=endpoint)
    assert not client.enabled and not client.available()
    assert not ask(client, "Is it safe?", EVIDENCE, "en").grounded
    assert seen == []


def test_loopback_ignores_proxy_configuration(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://bad:invalid-port")
    monkeypatch.setenv("ALL_PROXY", "http://bad:invalid-port")
    monkeypatch.delenv("NO_PROXY", raising=False)
    client = LLMClient("http://localhost:8080/v1")
    assert client.base_url == "http://127.0.0.1:8080/v1"
    with client._client(1) as transport:
        assert not transport.trust_env and not transport.follow_redirects
    assert LLMClient("http://[::1]:8080/v1").enabled


def test_remote_endpoint_disabled_by_default() -> None:
    seen: list = []
    client = fake_llm("x", seen=seen, base_url="https://api.example.com/v1")
    assert not client.enabled
    assert ask(client, "Is it safe?", EVIDENCE, "en").source == "fallback" and seen == []


def select(*refs):
    return json.dumps({"refs": list(refs)})


@pytest.fixture
def office():
    """Build evidence from the official V3 XML and answer CSVs."""
    root = Path(__file__).parent / "fixtures" / "validation"
    name = "V3_small_office.xml"
    devices = []
    for host in ElementTree.parse(root / name).findall("host"):
        ports = []
        for port in host.findall("ports/port"):
            if port.find("state").get("state") == "open":
                service = port.find("service")
                ports.append(EvidencePort(int(port.get("portid")), port.get("protocol"),
                                          service.get("name"), service.get("product", ""), service.get("version", "")))
        devices.append(EvidenceDevice(ip=host.find("address[@addrtype='ipv4']").get("addr"),
                                      hostname=host.find("hostnames/hostname").get("name"),
                                      vendor=host.find("address[@addrtype='mac']").get("vendor"),
                                      open_ports=tuple(ports)))
    with (root / "expected_findings.csv").open() as fh:
        findings = tuple(EvidenceFinding(r["finding_code"], r["severity"], r["ip"], int(r["port"]), "tcp")
                         for r in csv.DictReader(fh) if r["file"] == name)
    with (root / "expected_scores.csv").open() as fh:
        score = next(int(r["network_score"]) for r in csv.DictReader(fh) if r["file"] == name)
    return ScanEvidence(score, tuple(devices), findings)


def test_score_is_rendered_from_each_scan(office):
    seen = []
    client = fake_llm("Your network score is 100.", seen=seen)
    answer = ask(client, "What is the network score?", office, "en")
    assert answer.source == "scan" and answer.text == "The network score is 45 out of 100."
    assert ask(client, "Care este scorul?", replace(office, score=0), "ro").text == "Scorul rețelei este 0 din 100."
    assert seen == []
    assert ask(fake_llm(select("score")), "What did the scan show?", office, "en").text == answer.text


@pytest.mark.parametrize("question", ["What about 192.168.1.10:3306?", "Is port 3306 on office-printer open?"])
def test_v3_database_port_is_not_a_printer_fact(office, question):
    seen = []
    assert not ask(fake_llm(select("d3p1"), seen=seen), question, office, "en").grounded
    assert seen == []


def test_same_database_fact_selectable_only_for_its_host(office):
    seen = []
    client = fake_llm(select("d3p1"), seen=seen)
    answer = ask(client, "What runs on [192.168.1.40:3306]?", office, "en")
    assert answer.grounded and "[192.168.1.40:3306]" in answer.text and "mysql" in answer.text
    assert "192.168.1.10" not in seen[0]["messages"][1]["content"]
    wrong = ask(client, "What is open on 192.168.1.10?", office, "en")
    assert not wrong.grounded and "mysql" not in wrong.text


@pytest.mark.parametrize("reply", [
    "Your network score is 100.", "Your printer is a Canon.", "This calls for firmware 9.5.",
    "The printer has a database on [192.168.1.10:3306].", "Call +40 721 123 456.",
    "This is CVE-2020-1234.", "Open https://example.com.", "See [http://192.168.1.10].",
    select("d99p22"), '{"refs":[true]}', '{"refs":[{}]}', '[]', 'null', "CANNOT_ANSWER",
])
def test_invalid_or_free_text_answer_fails_closed(reply):
    answer = ask(fake_llm(reply), "Tell me about my network.", EVIDENCE, "en")
    assert answer.source == "fallback" and not answer.grounded
    assert reply not in answer.text


@pytest.mark.parametrize("reply", [
    select("score", "oops"), '{"refs":["score"],"answer":"100"}', '{"refs":"score"}',
    select("score", "score", "score", "score", "score", "score", "score"),
])
def test_imperfect_reply_keeps_valid_ids_and_never_shows_model_text(reply):
    answer = ask(fake_llm(reply), "Tell me about my network.", EVIDENCE, "en")
    assert answer.source == "llm" and answer.grounded
    assert answer.text == "The network score is 45 out of 100."
    assert "oops" not in answer.text and '"answer"' not in answer.text


def _many():
    """Seven findings on seven devices: more than one answer may show."""
    sev = ["low", "medium", "high", "info", "medium", "high", "low"]
    findings = tuple(EvidenceFinding("TELNET_OPEN", s, f"192.168.1.{i + 2}", 23) for i, s in enumerate(sev))
    return ScanEvidence(40, findings=findings)


def test_too_many_selected_ids_keep_the_most_severe():
    evidence = _many()
    answer = ask(fake_llm(select(*[f"f{i}" for i in range(7)])), "Should I worry?", evidence, "en")
    assert answer.grounded and answer.source == "llm"
    assert answer.text.count("Severity") == llm.MAX_SELECTED
    assert answer.text.index("Severity high") < answer.text.index("Severity medium") < answer.text.index("Severity low")
    assert "Severity info" not in answer.text


@pytest.mark.parametrize("question,lang", [
    ("What vulnerabilities do I have?", "en"), ("what problems are on my network", "en"),
    ("What did the scan find?", "en"), ("Ce vulnerabilități am?", "ro"), ("Ce probleme am?", "ro"),
])
def test_overview_lists_every_finding_from_the_scan_without_the_model(question, lang):
    seen = []
    evidence = _many()
    answer = ask(fake_llm(select("score"), seen=seen), question, evidence, lang)
    assert answer.source == "scan" and answer.grounded and seen == []
    assert all(f"[192.168.1.{i + 2}:23]" in answer.text for i in range(7))
    high, low = ("ridicată", "scăzută") if lang == "ro" else ("high", "low")
    assert answer.text.index(high) < answer.text.index(low)
    assert ("40 din 100" if lang == "ro" else "40 out of 100") in answer.text


def test_overview_works_with_ai_off_and_caps_long_lists():
    findings = tuple(EvidenceFinding("TELNET_OPEN", "medium", f"10.0.0.{i}", 23) for i in range(1, 14))
    answer = ask(LLMClient(), "What problems do I have?", ScanEvidence(0, findings=findings), "en")
    assert answer.grounded and "13 problems" in answer.text and "3 more" in answer.text
    assert answer.text.count("Severity") == llm.MAX_OVERVIEW
    clean = ask(LLMClient(), "Ce probleme am?", ScanEvidence(100), "ro")
    assert clean.grounded and "nicio problemă" in clean.text


def test_question_about_one_device_still_goes_to_the_model():
    seen = []
    answer = ask(fake_llm(select("f0"), seen=seen), "What problems does 192.168.1.10 have?", EVIDENCE, "en")
    assert answer.source == "llm" and "[192.168.1.10:9100]" in answer.text and len(seen) == 1


@pytest.mark.parametrize("question,lang,expected", [
    ("hi", "en", "Ask me"), ("Hello!", "en", "Ask me"), ("Salut", "ro", "Întreabă-mă"), ("bună ziua", "ro", "Întreabă-mă"),
])
def test_greeting_gets_a_hint_without_the_model(question, lang, expected):
    seen = []
    answer = ask(fake_llm(select("score"), seen=seen), question, EVIDENCE, lang)
    assert expected in answer.text and not answer.grounded and seen == []


@pytest.mark.parametrize("question", ["Is 213.43.4.3 safe?", "Compare 192.168.1.10 with 192.168.1.99.",
                                      "Is [2001:db8::1] present?", "Dar 192.168.1.99:80?"])
def test_unknown_ip_rejected_before_transport(question):
    seen = []
    answer = ask(fake_llm(select("d0"), seen=seen), question, EVIDENCE, "ro")
    assert answer.source == "fallback" and not answer.grounded
    assert "adresele IP" in answer.text and seen == []


@pytest.mark.parametrize("question", ["Is port 9100 on my printer safe?",
                                      "Ce spune scanarea despre imprimantă pe portul 9100?"])
def test_valid_finding_is_localized_and_cited(question):
    lang = "ro" if question.startswith("Ce") else "en"
    answer = ask(fake_llm(select("f0")), question, EVIDENCE, lang)
    assert answer.grounded and "[192.168.1.10:9100]" in answer.text
    assert ("scăzută" if lang == "ro" else "low") in answer.text


def test_protocol_version_and_product_stay_with_the_endpoint():
    udp = EvidencePort(631, "udp", "other-service", "Other product", "7.3")
    device = replace(EVIDENCE.devices[0], open_ports=(*EVIDENCE.devices[0].open_ports, udp))
    evidence = replace(EVIDENCE, devices=(device,))
    q = "What is running on 192.168.1.10 port 631/TCP?"
    assert not ask(fake_llm(select("d0p2")), q, evidence, "en").grounded
    answer = ask(fake_llm(select("d0p1")), q, evidence, "en")
    assert answer.grounded and '"ipp"' in answer.text and '"2.4"' in answer.text
    assert '"7.3"' not in answer.text


def test_only_named_device_is_offered_even_when_another_has_same_port():
    other = replace(EVIDENCE.devices[0], ip="192.168.1.11", hostname="hall", vendor="Other",
                    device_type="server")
    evidence = replace(EVIDENCE, devices=(*EVIDENCE.devices, other))
    assert not ask(fake_llm(select("d1p1")), "Imprimanta, portul 631?", evidence, "ro").grounded
    reply = ask(fake_llm(select("d0p1")), "Is port 631 open on office-printer?", evidence, "en")
    assert reply.grounded and "[192.168.1.10:631]" in reply.text


def test_host_level_finding_has_no_invented_port():
    finding = EvidenceFinding("UNKNOWN_DEVICE", "low", "192.168.1.5")
    answer = ask(fake_llm(select("f0")), "What is 192.168.1.5?", ScanEvidence(95, findings=(finding,)), "en")
    assert answer.grounded and "[192.168.1.5]" in answer.text


def test_vendor_hostname_and_version_are_copied_from_correct_records():
    reply = ask(fake_llm(select("d0", "d0p1")), "Tell me about my printer.", EVIDENCE, "en")
    assert reply.grounded
    for label in ('"HP"', '"office-printer"', '"CUPS"', '"2.4"'):
        assert label in reply.text


def test_personalization_uses_exact_base_steps_and_verified_context():
    result = personalize(fake_llm("<think>ignored</think>" + select("vendor")), PRINTER, BASE, "en")
    assert result.source == "llm" and '"HP"' in result.explanation
    assert result.explanation.endswith(BASE.explanation) and result.fixes == list(BASE.fixes)


@pytest.mark.parametrize("bad", [
    "Your score is 100.", select("other-host"), select(),
    '{"explanation":"Your Canon printer is fine.","fixes":"OFF"}', None, [{"type":"text","text":"oops"}],
])
def test_personalization_keeps_static_guidance_on_bad_reply(bad):
    result = personalize(fake_llm(bad), PRINTER, BASE, "en")
    assert result.source == "static" and result.explanation == BASE.explanation
    assert result.fixes == list(BASE.fixes)


@pytest.mark.parametrize("reply", [select("vendor", "address"), '{"refs":["vendor"],"fixes":["Disable encryption"]}'])
def test_personalization_uses_first_valid_label_and_keeps_base_steps(reply):
    result = personalize(fake_llm(reply), PRINTER, BASE, "en")
    assert result.source == "llm" and '"HP"' in result.explanation
    assert result.explanation.endswith(BASE.explanation) and result.fixes == list(BASE.fixes)
    assert "Disable encryption" not in result.explanation + " ".join(result.fixes)


@pytest.mark.parametrize("error", [httpx.ConnectError("down"), httpx.ReadTimeout("slow")])
def test_transport_failure_uses_local_fallbacks(error):
    client = fake_llm(error)
    assert personalize(client, PRINTER, BASE, "en").source == "static"
    assert "not available" in ask(client, "Tell me about my network.", EVIDENCE, "en").text


def test_unknown_answer_and_disabled_client():
    assert not ask(fake_llm(select()), "What is my password?", EVIDENCE, "ro").grounded
    client = LLMClient()
    assert not ask(client, "Tell me about my network.", EVIDENCE, "en").grounded
    assert personalize(client, PRINTER, BASE, "en").explanation == BASE.explanation


def test_untrusted_title_and_mac_do_not_enter_model_message():
    mac = "02:00:00:00:00:01"
    port = replace(EVIDENCE.devices[0].open_ports[0], title="Raw untrusted web title", product="Printer " + mac)
    evidence = replace(EVIDENCE, devices=(replace(EVIDENCE.devices[0], open_ports=(port,)),))
    seen = []
    ask(fake_llm(select("d0p0"), seen=seen), "Is " + mac + " safe?", evidence, "en")
    prompt = seen[0]["messages"][1]["content"]
    assert mac not in prompt and "Raw untrusted web title" not in prompt
    assert "office-printer" in prompt and "[MAC]" in prompt


def test_same_request_is_cached():
    seen = []
    client = fake_llm(select("vendor"), seen=seen)
    a = personalize(client, PRINTER, BASE, "en")
    b = personalize(client, PRINTER, BASE, "en")
    assert a.source == "llm" and a == b and len(seen) == 1
    assert seen[0]["temperature"] == 0 and seen[0]["response_format"] == {"type": "json_object"}
