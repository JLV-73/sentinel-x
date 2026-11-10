import json
import asyncio
import traceback
import ssl
import time
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from app.fortress_live import validate_url, exchange_connected

import pytest

from app import fortress_mvp_api as api
from app.fortress_live import result


@pytest.mark.parametrize('nested', [False, True])
def test_duplicate_worker_keys_are_rejected(nested):
    target = 'https://example.invalid/'
    raw = json.dumps(result(target)).encode()
    raw = raw.replace(b'"mode": "live"', b'"mode": "fixture", "mode": "live"') if not nested else raw.replace(b'"certificate": "indeterminate"', b'"certificate": "verified", "certificate": "indeterminate"')
    with patch.object(api, 'run_gated', return_value=raw):
        with pytest.raises(ValueError):
            api._run_live(target, target)


def app_trace(exc):
    trace = traceback.TracebackException.from_exception(exc, capture_locals=True)
    chunks = []
    while trace:
        for frame in trace.stack:
            if frame.filename.replace('\\', '/').endswith(('/app/fortress_live.py', '/app/fortress_mvp_api.py')):
                chunks.append(repr(frame.locals))
        chunks.append(str(trace))
        trace = trace.__cause__ or trace.__context__
    return ''.join(chunks)


def test_timeout_after_response_does_not_propagate_processing_frames():
    class TLS:
        def __enter__(self): return self
        def __exit__(self, *args): raise TimeoutError('PRIVATE_COOKIE_MARKER')
        def settimeout(self, value): pass
        def do_handshake(self): pass
        def getpeercert(self): return {}
        def version(self): return 'TLSv1.3'
        def sendall(self, value): pass
        def recv(self, size): return b'HTTP/1.1 200 OK\r\nSet-Cookie: PRIVATE_COOKIE_MARKER=secret\r\n\r\n'
    class Context:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True
        def wrap_socket(self, *args, **kwargs): return TLS()
    class Sock:
        def settimeout(self, value): pass
    with pytest.raises(TimeoutError) as caught:
        exchange_connected(Sock(), 'example.invalid', 'example.invalid', '/', Context(), time.monotonic()+5, result('https://example.invalid/'))
    assert 'PRIVATE_COOKIE_MARKER' not in app_trace(caught.value)


def test_invalid_url_trace_does_not_retain_url():
    with pytest.raises(ValueError) as caught:
        validate_url('https://example.invalid/PRIVATE_URL_MARKER#invalid')
    assert 'PRIVATE_URL_MARKER' not in app_trace(caught.value)


def test_demo_unexpected_exception_does_not_retain_body():
    app = FastAPI()
    api.install_disabled_route(app, ('http://127.0.0.1:5177',))
    endpoint = next(r.endpoint for r in app.routes if getattr(r, 'path', None) == '/api/fortress/mvp/demo')
    async def receive():
        return {'type': 'http.request', 'body': b'{"scenario":"ok","consent":true,"PRIVATE_DEMO_MARKER":1}', 'more_body': False}
    # Inject a fault after reception, before validation finishes.
    request = Request({'type': 'http', 'method': 'POST', 'path': '/api/fortress/mvp/demo', 'query_string': b'',
        'headers': [(b'origin', b'http://127.0.0.1:5177'), (b'host', b'127.0.0.1:8007'),
                    (b'x-sentinel-request', b'sync'), (b'x-sentinel-capability', api._CAPABILITY.encode()),
                    (b'content-type', b'application/json')], 'server': ('127.0.0.1', 8007), 'scheme': 'http'}, receive)
    with patch.object(api.json, 'loads', side_effect=RuntimeError('PRIVATE_DEMO_MARKER')):
        with pytest.raises(RuntimeError) as caught:
            asyncio.run(endpoint(request))
    assert 'PRIVATE_DEMO_MARKER' not in app_trace(caught.value)


@pytest.mark.parametrize('route,body', [
    ('/api/fortress/audit', b'{"url":"PRIVATE_BODY_MARKER", "consent":true}'),
    ('/api/fortress/mvp/demo', b'{"scenario":"PRIVATE_BODY_MARKER", "consent":true}'),
])
def test_api_error_trace_does_not_retain_body(route, body):
    app = FastAPI()
    api.install_disabled_route(app, ('http://127.0.0.1:5177',))
    endpoint = next(r.endpoint for r in app.routes if getattr(r, 'path', None) == route)
    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}
    request = Request({'type': 'http', 'method': 'POST', 'path': route, 'query_string': b'',
        'headers': [(b'origin', b'http://127.0.0.1:5177'), (b'host', b'127.0.0.1:8007'),
                    (b'x-sentinel-request', b'sync'), (b'x-sentinel-capability', api._CAPABILITY.encode()),
                    (b'content-type', b'application/json')], 'server': ('127.0.0.1', 8007), 'scheme': 'http'}, receive)
    with pytest.raises(HTTPException) as caught:
        asyncio.run(endpoint(request))
    assert caught.value.status_code == 422
    assert 'PRIVATE_BODY_MARKER' not in app_trace(caught.value)
