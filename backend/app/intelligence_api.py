"""P1-only routes and guards, without changing P0 request or response shapes."""
from fastapi import Depends, HTTPException, Query, Request
from .intelligence import IntelligenceBusy, IntelligenceFailure


def install_routes(app, intelligence, origins):
    async def authorize(request: Request):
        if (request.headers.getlist("origin") not in [[origin] for origin in origins]
                or request.headers.getlist("x-sentinel-request") != ["sync"]):
            raise HTTPException(403, "Allowed Origin and X-Sentinel-Request: sync required")
        allowed = {"refresh"} if request.url.path.startswith("/api/intelligence/nvd/") else set()
        if any(key not in allowed for key in request.query_params):
            raise HTTPException(422, "Unknown query parameter")
        refresh = request.query_params.getlist("refresh")
        if refresh and (len(refresh) != 1 or refresh[0] not in ("true", "false")):
            raise HTTPException(422, "refresh must be exactly true or false, once")
        async for chunk in request.stream():
            if chunk:
                raise HTTPException(422, "Intelligence sync does not accept a body")

    def invoke(function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except KeyError as error:
            raise HTTPException(404, "Unknown local CISA CVE") from error
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        except IntelligenceBusy as error:
            raise HTTPException(409, str(error)) from error
        except IntelligenceFailure as error:
            detail = {"error": str(error), "attempt": error.attempt}
            if args:
                detail["cached"] = intelligence.get(args[0])["nvd"]
            raise HTTPException(502, detail) from error

    @app.get("/api/intelligence/status")
    def status():
        return intelligence.status()

    @app.get("/api/intelligence/summary")
    def summary():
        return intelligence.summary()

    @app.get("/api/intelligence")
    def many(request: Request, cve: str = Query(..., min_length=1, max_length=3000)):
        values = cve.split(",")
        if len(request.query_params.getlist("cve")) != 1 or not 1 <= len(values) <= 100 or len(set(values)) != len(values):
            raise HTTPException(422, "Expected 1..100 unique exact CVE identifiers")
        return invoke(intelligence.get_many, values)

    @app.get("/api/intelligence/{cve_id}")
    def single(cve_id: str):
        return invoke(intelligence.get, cve_id)

    @app.post("/api/intelligence/nvd/{cve_id}", dependencies=[Depends(authorize)])
    def nvd(cve_id: str, refresh: bool = False):
        return invoke(intelligence.fetch_nvd, cve_id, refresh=refresh)

    @app.post("/api/intelligence/epss", dependencies=[Depends(authorize)])
    def epss():
        return invoke(intelligence.fetch_epss)
