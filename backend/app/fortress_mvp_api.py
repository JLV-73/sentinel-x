"""Local demo boundary; Internet audit is disabled before body parsing."""
import json
import secrets
import threading
from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from .fortress_mvp import run_demo

_CAPABILITY = secrets.token_urlsafe(32)
_DEMO_LOCK = threading.Lock()
_BODY_LIMIT = 512


def _guard(request, origins):
    if (request.headers.getlist('origin') not in [[origin] for origin in origins]
            or request.headers.getlist('host') not in [['127.0.0.1:8007'], ['127.0.0.1:5177']]
            or request.headers.getlist('x-sentinel-request') != ['sync']):
        raise HTTPException(403, 'Request forbidden')
    if request.url.query:
        raise HTTPException(422, 'Query parameters not accepted')


def install_disabled_route(app, origins):
    @app.post('/api/fortress/audit')
    async def unavailable(request: Request):
        _guard(request, origins)
        raise HTTPException(503, 'Audit unavailable')

    @app.get('/api/fortress/mvp/capability')
    async def capability(request: Request):
        _guard(request, origins)
        return JSONResponse({'capability': _CAPABILITY}, headers={'Cache-Control': 'no-store'})

    @app.post('/api/fortress/mvp/demo')
    async def demo(request: Request):
        _guard(request, origins)
        tokens = request.headers.getlist('x-sentinel-capability')
        if len(tokens) != 1 or not tokens[0].isascii() or not secrets.compare_digest(tokens[0], _CAPABILITY):
            raise HTTPException(403, 'Request forbidden')
        if request.headers.getlist('content-type') != ['application/json']:
            raise HTTPException(415, 'JSON required')
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > _BODY_LIMIT:
                raise HTTPException(413, 'Body too large')
            body.extend(chunk)
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError('duplicate key')
                result[key] = value
            return result
        try:
            data = json.loads(body, object_pairs_hook=pairs)
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(422, 'Invalid body') from None
        if (not isinstance(data, dict) or set(data) != {'scenario', 'consent'}
                or data['consent'] is not True or data['scenario'] not in ('ok', 'forbidden', 'tls-error')):
            raise HTTPException(422, 'Invalid scenario or consent')
        if not _DEMO_LOCK.acquire(blocking=False):
            raise HTTPException(409, 'Demo busy')
        def work():
            try:
                return run_demo(data['scenario'])
            finally:
                _DEMO_LOCK.release()
        result = await run_in_threadpool(work)
        return JSONResponse(result, headers={'Cache-Control': 'no-store'})
