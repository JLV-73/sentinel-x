"""Isolated GHSA routes; stable intelligence endpoints are unchanged."""
from fastapi import Depends, HTTPException, Request
from .intelligence import IntelligenceBusy, IntelligenceFailure


def install_ghsa_routes(app, ghsa, origins):
    async def authorize(request: Request):
        if (request.headers.getlist("origin") not in [[origin] for origin in origins]
                or request.headers.getlist("x-sentinel-request") != ["sync"]):
            raise HTTPException(403, "Allowed Origin and X-Sentinel-Request: sync required")
        if any(key != "refresh" for key in request.query_params):
            raise HTTPException(422, "Unknown query parameter")
        refresh = request.query_params.getlist("refresh")
        if refresh and (len(refresh) != 1 or refresh[0] not in ("true", "false")):
            raise HTTPException(422, "refresh must be exactly true or false, once")
        async for chunk in request.stream():
            if chunk:
                raise HTTPException(422, "GHSA sync does not accept a body")

    def invoke(function, value, **kwargs):
        try:
            return function(value, **kwargs)
        except KeyError as error:
            raise HTTPException(404, "Unknown local CISA CVE") from error
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        except IntelligenceBusy as error:
            raise HTTPException(409, str(error)) from error
        except IntelligenceFailure as error:
            raise HTTPException(502, {"error": str(error), "attempt": error.attempt, "cached": ghsa.get(value)}) from error

    @app.get("/api/intelligence/ghsa/{cve_id}")
    def get(cve_id: str):
        return invoke(ghsa.get, cve_id)

    @app.post("/api/intelligence/ghsa/{cve_id}", dependencies=[Depends(authorize)])
    def post(cve_id: str, refresh: bool = False):
        return invoke(ghsa.fetch, cve_id, refresh=refresh)
