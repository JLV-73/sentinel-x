"""Disabled P2 endpoint: no request body is read and no transport is constructed.

Do not enable until independent production-boundary and audit-safety review.
"""
from fastapi import HTTPException, Request


def install_fortress_route(app, origins):
    @app.post('/api/fortress/audit')
    async def fortress_unavailable(request: Request):
        if (request.headers.getlist('origin') not in [[origin] for origin in origins]
                or request.headers.getlist('x-sentinel-request') != ['sync']):
            raise HTTPException(403, 'Audit request forbidden')
        if request.query_params:
            raise HTTPException(422, 'Query parameters not accepted')
        raise HTTPException(503, 'Audit unavailable')
