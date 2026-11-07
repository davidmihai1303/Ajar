"""Answers drawn only from stored, published scan evidence."""
from fastapi import APIRouter, HTTPException, Request

from netcheck.analysis.catalog import CATALOG
from netcheck.explain import llm
from netcheck.explain.evidence import EvidenceDevice, EvidenceFinding, EvidencePort, ScanEvidence
from netcheck.explain.static import guidance
from . import schemas as api
from .routes_history import saved, scan_view

router = APIRouter(prefix="/api")


def evidence(scan: api.Scan) -> ScanEvidence:
    if scan.score is None or not scan.findings_available:
        raise HTTPException(409, "incomplete_scan")
    devices = {d.ip: d for d in scan.devices}
    endpoints = {(d.ip, p.port, p.protocol): p for d in scan.devices for p in d.ports}
    findings = []
    for f in scan.findings:
        d = devices.get(f.ip)
        p = endpoints.get((f.ip, f.port, f.protocol))
        findings.append(EvidenceFinding(f.code, f.severity, f.ip, f.port, f.protocol or "",
            service=p.service or "" if p else "", device_type=d.device_type if d else "",
            vendor=d.vendor or "" if d else "", hostname=d.hostname or "" if d else ""))
    # Product banners, titles, MACs and script outputs are not model inputs.
    inventory = tuple(EvidenceDevice(d.ip, d.vendor or "", d.hostname or "", d.device_type,
                      tuple(EvidencePort(p.port, p.protocol, p.service or "") for p in d.ports))
                      for d in scan.devices)
    return ScanEvidence(scan.score, inventory, tuple(findings))


def selected(scan: api.Scan, ref: api.FindingRef) -> EvidenceFinding:
    key = (ref.code, ref.ip, ref.port, ref.protocol or "")
    for f in evidence(scan).findings:
        if (f.code, f.ip, f.port, f.protocol) == key:
            return f
    raise HTTPException(404, "finding_not_in_scan")


def explain(code: str, lang: api.Lang, device_type: str = "") -> api.Explanation:
    if code not in CATALOG:
        raise HTTPException(404, "unknown_finding")
    text = guidance(code, lang, device_type)
    return api.Explanation(code=code, lang=lang, title=text["title"], explanation=text["explanation"],
                           steps=text["fixes"])


@router.get("/explain/{code}")
def explanation(code: str, request: Request, lang: api.Lang = "ro", scan_id: str | None = None,
                ip: str | None = None, port: int | None = None, protocol: str | None = None) -> api.Explanation:
    if scan_id is None and ip is None and port is None and protocol is None:
        return explain(code, lang)
    if not scan_id or not ip:
        raise HTTPException(422, "finding_context_required")
    scan = scan_view(saved(request.app.state.db, scan_id))
    f = selected(scan, api.FindingRef(code=code, ip=ip, port=port, protocol=protocol))
    return explain(code, lang, f.device_type)


@router.post("/explain/{code}/personalize")
def personalize(code: str, body: api.PersonalizeRequest, request: Request) -> api.Explanation:
    if code != body.code:
        raise HTTPException(422, "finding_mismatch")
    f = selected(scan_view(saved(request.app.state.db, body.scan_id)), body)
    base = explain(code, body.lang, f.device_type)
    result = llm.personalize(request.app.state.model, f, llm.StaticText(base.explanation, tuple(base.steps)), body.lang)
    return base.model_copy(update={"explanation": result.explanation})


@router.get("/llm/status")
def model_status(request: Request) -> api.ModelStatus:
    return api.ModelStatus(available=request.app.state.model.available())


@router.post("/ask")
def ask(body: api.AskRequest, request: Request) -> api.Answer:
    scan = scan_view(saved(request.app.state.db, body.scan_id))
    result = llm.ask(request.app.state.model, body.question, evidence(scan), body.lang)
    return api.Answer(available=not result.unavailable, can_answer=result.grounded, answer=result.text)
