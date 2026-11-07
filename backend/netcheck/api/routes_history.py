"""Translate persisted observations into the public UI contract."""
from fastapi import APIRouter, HTTPException, Query, Request, Response

from netcheck.analysis import models
from netcheck.analysis.privacy import mask_macs_in_text, mask_scan_filename
from netcheck.history import ScanRecord, compute_diff, delete_all_history, get_scan, list_scans

from . import schemas as api

router = APIRouter(prefix="/api")


def clean(value: str | None) -> str | None:
    return mask_macs_in_text(value) if value else None


def saved(db: str, scan_id: str) -> ScanRecord:
    record = get_scan(scan_id, db)
    if record is None:
        raise HTTPException(404, "scan_not_found")
    return record


def finding_view(f: models.Finding) -> api.Finding:
    return api.Finding(ip=f.ip, port=f.port, protocol=clean(f.protocol), code=f.code,
                       severity=f.severity, points=f.points, evidence=clean(f.evidence) or "")


def scan_view(record: ScanRecord) -> api.Scan:
    # Older reports may have multiple observations for one IP. Present each device once
    # with its last known labels and the union of observed open endpoints.
    devices = {}
    endpoints = {}
    for device in record.devices:
        by_port = endpoints.setdefault(device.ip, {})
        for p in device.open_ports:
            by_port[p.protocol, p.port] = api.Port(port=p.port, protocol=clean(p.protocol) or "",
                service=clean(p.service), product=clean(p.product), version=clean(p.version),
                http_title=clean(p.http_title), tunnel=clean(p.tunnel))
        devices[device.ip] = device
    inventory = [api.Device(ip=d.ip, mac_masked=clean(d.mac_masked), vendor=clean(d.vendor),
                            hostname=clean(d.hostname), device_type=clean(d.device_type) or "unknown",
                            ports=list(endpoints[d.ip].values())) for d in devices.values()]
    return api.Scan(id=record.scan_id, file=mask_scan_filename(record.file), created_at=record.created_at,
                    score=record.score, error=record.error, source=record.source or "unknown",
                    ssid=clean(record.ssid), subnet=record.subnet, network_id=record.network_id,
                    findings_available=record.ok and record.findings_available, devices=inventory,
                    findings=[finding_view(f) for f in record.findings or []])


@router.get("/scans/{scan_id}")
def detail(scan_id: str, request: Request) -> api.Scan:
    return scan_view(saved(request.app.state.db, scan_id))


@router.get("/history")
def history(request: Request) -> list[api.HistoryItem]:
    return [api.HistoryItem(**{**row, "id": row["scan_id"], "file": mask_scan_filename(row["file_name"]),
                               "source": row["source"] or "unknown", "ssid": clean(row["ssid"]),
                               "findings_available": row["findings_available"] and not row["error"]})
            for row in list_scans(request.app.state.db)]


@router.get("/history/diff")
def diff(request: Request, from_id: str = Query(alias="from"), to_id: str = Query(alias="to")) -> api.Diff:
    db = request.app.state.db
    before, after = saved(db, from_id), saved(db, to_id)
    if not before.findings_available or not after.findings_available:
        raise HTTPException(409, "incomplete_scan")
    change = compute_diff(before, after)
    if change is None:
        raise HTTPException(409, "unreadable_scan")

    def ports(items: list[dict]) -> list[api.PortRef]:
        return [api.PortRef(**{**p, "service": clean(p["service"])}) for p in items]

    return api.Diff(from_id=from_id, to_id=to_id, score_before=change.score_before,
                    score_after=change.score_after, devices_added=[d.ip for d in change.new_devices],
                    devices_removed=[d.ip for d in change.removed_devices],
                    ports_opened=ports(change.newly_opened_ports), ports_closed=ports(change.closed_ports),
                    findings_resolved=[finding_view(f) for f in change.resolved_findings],
                    findings_new=[finding_view(f) for f in change.new_findings])


@router.delete("/history", status_code=204)
def clear(request: Request) -> Response:
    state = request.app.state
    with state.history_lock:
        delete_all_history(state.db)
        state.history_generation += 1
    return Response(status_code=204)
