"""Loopback-only application serving the React build and its local API."""
import sqlite3
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.staticfiles import StaticFiles

from netcheck import config
from netcheck.explain.llm import LLMClient
from .agent_client import AgentClient
from . import routes_history, routes_scans


def create_app(*, db: str = config.DB_PATH, scans_dir: str = config.SCANS_DIR,
               static_dir: Path | None = None, agent: AgentClient | None = None,
               model: LLMClient | None = None, max_xml: int = config.MAX_XML_BYTES) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.agent = agent or AgentClient(config.AGENT_URL)
        app.state.model = model or LLMClient.from_config()
        try:
            yield
        finally:
            app.state.agent.close()

    app = FastAPI(title="Ajar local API", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.db = db
    app.state.scans_dir = scans_dir
    app.state.max_xml = max_xml
    app.state.max_batch = 4 * max_xml + 1024 * 1024
    app.state.history_lock = threading.Lock()
    app.state.history_generation = 0

    @app.middleware("http")
    async def local_mutations(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            allowed = f"{request.url.scheme}://{request.headers.get('host', '')}"
            if request.headers.get("sec-fetch-site") == "cross-site" or (origin and origin != allowed):
                return JSONResponse({"detail": "foreign_origin"}, status_code=403)
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"], www_redirect=False)

    @app.exception_handler(RequestValidationError)
    async def bad_input(request, exc):
        # Validation errors may contain user questions, filenames or entire request bodies.
        return JSONResponse({"detail": "invalid_request"}, status_code=422)

    @app.exception_handler(sqlite3.Error)
    async def storage_error(request, exc):
        return JSONResponse({"detail": "history_unavailable"}, status_code=503)

    app.include_router(routes_scans.router)
    app.include_router(routes_history.router)

    @app.get("/api/{missing:path}", include_in_schema=False)
    def missing_api(missing: str):
        return JSONResponse({"detail": "not_found"}, status_code=404)

    app.mount("/", StaticFiles(directory=static_dir or Path(__file__).with_name("static"), html=True))
    return app


app = create_app()
