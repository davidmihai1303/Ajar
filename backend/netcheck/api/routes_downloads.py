"""The Ajar desktop app for Ubuntu, offered for download by the running app.

Files come from a read-only folder (NETCHECK_DOWNLOADS_DIR). Only names like
`Ajar-<version>-<arch>.AppImage` / `.deb` are listed or served: no directory browsing,
no paths, no symlinks.
"""
import re
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse

router = APIRouter()
_NAME = re.compile(r"^Ajar-[0-9A-Za-z._-]+\.(AppImage|deb)$")


def _files(folder: str) -> list[Path]:
    root = Path(folder)
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if _NAME.match(p.name) and p.is_file() and not p.is_symlink())


def _describe(path: Path) -> dict:
    name = path.name.lower()
    return {
        "name": path.name,
        "size": path.stat().st_size,
        "arch": "arm64" if ("arm64" in name or "aarch64" in name) else "x64",
        "kind": "deb" if name.endswith(".deb") else "appimage",
    }


@router.get("/api/downloads")
def list_downloads(request: Request) -> list[dict]:
    return [_describe(p) for p in _files(request.app.state.downloads_dir)]


@router.get("/downloads/{name}", include_in_schema=False)
def download(name: str, request: Request):
    for path in _files(request.app.state.downloads_dir):
        if path.name == name:
            return FileResponse(path, filename=path.name, media_type="application/octet-stream")
    return JSONResponse({"detail": "not_found"}, status_code=404)
