"""Local-only SENTINEL X API. No network activity at import/startup."""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException, Request, Query, Path as ApiPath
from typing import Literal
from datetime import date
from starlette.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from .service import Service, SyncBusy

ORIGINS = ("http://127.0.0.1:5177", "http://127.0.0.1:8007")


async def authorize_sync(request: Request):
    if (request.headers.getlist("origin") not in [[origin] for origin in ORIGINS]
            or request.headers.getlist("x-sentinel-request") != ["sync"]):
        raise HTTPException(403, "Allowed Origin and X-Sentinel-Request: sync required")
    if request.query_params:
        raise HTTPException(422, "Sync does not accept query parameters")
    async for chunk in request.stream():
        if chunk:
            raise HTTPException(422, "Sync does not accept a body")


def create_app(db_path=None):
    service = Service(db_path or Path(__file__).resolve().parents[2] / "data" / "sentinel.db")

    @asynccontextmanager
    async def lifespan(app):
        service.initialize()
        yield

    app = FastAPI(title="SENTINEL X", lifespan=lifespan)
    app.state.service = service
    app.add_middleware(CORSMiddleware, allow_origins=list(ORIGINS), allow_methods=["GET", "POST"],
                       allow_headers=["X-Sentinel-Request"], allow_credentials=False)

    @app.middleware("http")
    async def host_guard(request: Request, call_next):
        if request.headers.getlist("host") not in [["127.0.0.1:8007"], ["127.0.0.1:5177"]]:
            return JSONResponse({"detail": "Invalid Host"}, status_code=400)
        return await call_next(request)

    @app.get("/api/health")
    def health():
        return service.health()

    @app.get("/api/summary")
    def summary():
        return service.summary()

    @app.get("/api/vulnerabilities")
    def vulnerabilities(q: str = Query('', max_length=200), vendor: str = Query('', max_length=200),
                        ransomware: Literal['Known', 'Unknown'] | None = None,
                        added_since: str | None = Query(None, pattern=r'^\d{4}-\d{2}-\d{2}$'),
                        sort: Literal['asc', 'desc'] = 'desc', page: int = Query(1, ge=1),
                        page_size: int = Query(20, ge=1, le=100)):
        if added_since is not None:
            try:
                date.fromisoformat(added_since)
            except ValueError as error:
                raise HTTPException(422, 'Invalid added_since date') from error
        return service.listing(q, vendor, ransomware, added_since, sort, page, page_size)

    @app.get("/api/vulnerabilities/{cve_id}")
    def detail(cve_id: str = ApiPath(pattern=r'^CVE-[0-9]{4}-[0-9]{4,19}$')):
        result = service.detail(cve_id)
        if result is None:
            raise HTTPException(404, "Unknown CVE")
        return result

    @app.get("/api/sync/status")
    def status():
        return service.status()

    @app.post("/api/sync", dependencies=[Depends(authorize_sync)])
    def sync():
        try:
            result = service.sync()
        except SyncBusy as error:
            raise HTTPException(409, str(error)) from error
        if result["status"] == "failed":
            raise HTTPException(502, result)
        return result

    return app


app = create_app()
