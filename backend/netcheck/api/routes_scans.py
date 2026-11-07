"""Ingest local reports through the deterministic parser, rules and history store."""
import os
import stat
from pathlib import Path, PurePosixPath

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from netcheck.analysis.parser import parse_bytes
from netcheck.history import ScanRecord, save_scan

from .routes_history import saved, scan_view
from .schemas import ImportResult, Network, Scan, ScanRequest

router = APIRouter(prefix="/api")
HOST_SCAN_DIR = PurePosixPath("/var/lib/netcheck/scans")


def persist(request: Request, record: ScanRecord, generation: int) -> ScanRecord:
    state = request.app.state
    with state.history_lock:
        if generation != state.history_generation:
            raise HTTPException(409, "history_cleared")
        sid = save_scan(record, db_path=state.db)
        return saved(state.db, sid)


@router.get("/network", response_model_exclude_none=False)
def network(request: Request) -> Network:
    agent = request.app.state.agent
    return agent.public(agent.detect())


@router.post("/scans")
def start_scan(body: ScanRequest, request: Request) -> Scan:
    if not body.confirm:
        raise HTTPException(403, {"reason_ro": "Confirmă rețeaua înainte de scanare.",
                                  "reason_en": "Confirm the network before scanning."})
    state = request.app.state
    generation = state.history_generation
    path, raw = state.agent.confirmed_scan(body.expected_network)
    host_path = PurePosixPath(path)
    if host_path.parent != HOST_SCAN_DIR or host_path.suffix.lower() != ".xml":
        raise HTTPException(502, "invalid_report_path")
    try:
        fd = os.open(Path(state.scans_dir) / host_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as report:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise HTTPException(502, "invalid_report_path")
            data = report.read(state.max_xml + 1)
    except (OSError, ValueError):
        raise HTTPException(502, "report_unavailable") from None
    public = state.agent.public(raw)
    record = ScanRecord(parse_bytes(data, host_path.name, state.max_xml), source="live", ssid=public.ssid,
                        subnet=public.subnet, network_id=state.agent.history_id(raw))
    return scan_view(persist(request, record, generation))


class BatchTooLarge(MultiPartException):
    pass


@router.post("/scans/import", openapi_extra={"requestBody": {"required": True, "content": {
    "multipart/form-data": {"schema": {"type": "object", "required": ["files"], "properties": {
        "files": {"type": "array", "items": {"type": "string", "format": "binary"}}}}}}}})
async def import_scans(request: Request) -> list[ImportResult]:
    state = request.app.state
    generation = state.history_generation
    if request.headers.get("content-type", "").split(";")[0].lower() != "multipart/form-data":
        raise HTTPException(415, "multipart_required")

    async def limited_stream():
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > state.max_batch:
                raise BatchTooLarge("upload_limit")
            yield chunk

    try:
        form = await MultiPartParser(request.headers, limited_stream(), max_files=64, max_fields=0).parse()
    except BatchTooLarge:
        raise HTTPException(413, "upload_limit") from None
    except MultiPartException:
        raise HTTPException(400, "invalid_multipart") from None

    try:
        items = form.multi_items()
        if not items or any(key != "files" or not isinstance(f, UploadFile) for key, f in items):
            raise HTTPException(422, "files_required")
        results = []
        for _, upload in items:
            name = (upload.filename or "report.xml").replace("\\", "/").rsplit("/", 1)[-1] or "report.xml"
            data = await upload.read(state.max_xml + 1)
            scan = await run_in_threadpool(parse_bytes, data, name, state.max_xml)
            record = await run_in_threadpool(persist, request, ScanRecord(scan, source="import"), generation)
            results.append(ImportResult(file=record.file, scan_id=record.scan_id, score=record.score, error=record.error))
        return results
    finally:
        await form.close()
