"""Fortress demo and guarded, supervised Windows live audit routes."""
import json
import secrets
import threading
import ctypes
import os
import sys
import asyncio
from functools import wraps
from pathlib import Path
from datetime import datetime
from .fortress_live import validate_url, result, _OUTPUT_LIMIT
from .fortress_job import run_gated
from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from starlette.requests import ClientDisconnect
from .fortress_mvp import run_demo

_CAPABILITY = secrets.token_urlsafe(32)
_DEMO_LOCK = threading.Lock()
_BODY_LIMIT = 8192
_BODY_TIMEOUT = 5
_LIVE_LOCK = threading.Lock()


def _valid_observation(value, target):
    """Reject any worker data outside the deliberately small public schema."""
    template = result(target)
    if not isinstance(value, dict) or set(value) != set(template) or value['mode'] != 'live' or value['target'] != target:
        return False
    try:
        if not isinstance(value['observed_at'], str) or len(value['observed_at']) > 35:
            return False
        stamp = datetime.fromisoformat(value['observed_at'])
        if stamp.utcoffset() is None or stamp.utcoffset().total_seconds() != 0:
            return False
    except (TypeError, ValueError, OverflowError):
        return False
    status = value['http_status']
    if status is not None and (type(status) is not int or not 200 <= status <= 599):
        return False
    if value['failure_code'] not in ('none', 'http_refused', 'timeout', 'tls_or_transport', 'blocked', 'incomplete', 'unknown'):
        return False
    tls, headers = value['tls'], value['headers']
    if not isinstance(tls, dict) or set(tls) != set(template['tls']) or not isinstance(headers, dict) or set(headers) != set(template['headers']):
        return False
    if any(headers[k] not in ('present', 'absent', 'indeterminate') for k in headers):
        return False
    if tls['certificate'] not in ('verified', 'indeterminate') or tls['hostname'] not in ('verified', 'indeterminate'):
        return False
    if tls['protocol'] not in (None, 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'):
        return False
    for k in ('not_before', 'not_after'):
        if tls[k] is not None:
            if not isinstance(tls[k], str) or len(tls[k]) > 40:
                return False
            try:
                import ssl
                ssl.cert_time_to_seconds(tls[k])
            except (ValueError, TypeError, OverflowError):
                return False
    verified = tls['certificate'] == tls['hostname'] == 'verified'
    if tls['certificate'] != tls['hostname']:
        return False
    if verified:
        if tls['protocol'] is None or tls['not_before'] is None or tls['not_after'] is None:
            return False
    elif any(tls[k] is not None for k in ('protocol', 'not_before', 'not_after')):
        return False
    if status is not None:
        if not verified or any(v == 'indeterminate' for v in headers.values()):
            return False
        if value['failure_code'] != ('http_refused' if status >= 400 else 'none'):
            return False
    elif any(v != 'indeterminate' for v in headers.values()) or value['failure_code'] in ('none', 'http_refused'):
        return False
    advanced = value['advanced']
    if status is not None:
        from .fortress_advanced_core import validate_head_facts
        if not validate_head_facts(advanced):
            return False
        obs = advanced['observations']
        if obs['http_status'] != status:
            return False
        for key in headers:
            fact = obs[key]
            expected = 'absent' if fact == 'absent' else 'present'
            if headers[key] != expected:
                return False
    elif advanced is not None:
        return False
    return True


def _unique_pairs(items):
    obj = {}
    for key, value in items:
        if key in obj:
            raise ValueError('duplicate key')
        obj[key] = value
    return obj


def _run_live(url, target):
    # Named mutex serializes cooperating API processes across Windows sessions.
    # Exclusion spans the cleanup attempt, not necessarily confirmed child death:
    # a native termination/query/close failure can leave death unconfirmed while
    # the finally block still releases the mutex. Native-fault qualification is
    # NO GO; do not treat cleanup failure as proof of process termination.
    # Client/UI cancellation does not propagate to this worker; the job deadline
    # bounds acceptance of output, subject to the supervisor's cleanup limits.
    if os.name != 'nt':
        raise RuntimeError('Supervisor unavailable')
    if not _LIVE_LOCK.acquire(blocking=False):
        raise BlockingIOError('Busy')
    handle = None
    acquired = False
    try:
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        kernel.CreateMutexW.restype = ctypes.c_void_p
        kernel.ReleaseMutex.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        ctypes.set_last_error(0)
        handle = kernel.CreateMutexW(None, True, 'Global\\SentinelXFortressAuditV022')
        error = ctypes.get_last_error()
        if not handle:
            raise RuntimeError('Mutex unavailable')
        if error == 183:
            raise BlockingIOError('Busy')
        acquired = True
        backend = str(Path(__file__).resolve().parents[1])
        code = "import sys;sys.path.insert(0,sys.argv[1]);from app.fortress_live_worker import main;raise SystemExit(main())"
        try:
            raw = run_gated([sys.executable, '-c', code, backend], 10, json.dumps(url).encode('ascii'))
            # Defense in depth for substituted supervisors; real reads are bounded.
            value = None
            rejected = False
            try:
                if len(raw) > _OUTPUT_LIMIT:
                    raise ValueError('Invalid result')
                value = json.loads(raw, object_pairs_hook=_unique_pairs)
                if not _valid_observation(value, target):
                    raise ValueError('Invalid result')
            except Exception:
                # Drop the parser/validator exception and its potentially sensitive
                # frames before raising a fresh, unchained error below.
                value = None
                rejected = True
            finally:
                raw = None
            if rejected:
                raise ValueError('Invalid result')
            return value
        except TimeoutError:
            value = result(target)
            value['failure_code'] = 'timeout'
            return value
    finally:
        original = sys.exception()
        failed = []
        try:
            if handle:
                if acquired and not kernel.ReleaseMutex(handle):
                    failed.append('release')
                if not kernel.CloseHandle(handle):
                    failed.append('close')
        finally:
            _LIVE_LOCK.release()
        if failed:
            message = 'Mutex cleanup failed: ' + ', '.join(failed)
            if original is not None and not isinstance(original, BlockingIOError):
                original.add_note(message)
            else:
                raise RuntimeError(message) from original


async def _read_body(request, limit):
    body = bytearray()
    try:
        async with asyncio.timeout(_BODY_TIMEOUT):
            async for chunk in request.stream():
                if len(body) + len(chunk) > limit:
                    raise HTTPException(413, 'Body too large')
                body.extend(chunk)
    except TimeoutError:
        raise HTTPException(408, 'Request body timeout') from None
    except ClientDisconnect:
        raise HTTPException(400, 'Client disconnected') from None
    return body


def _guard(request, origins):
    if (request.headers.getlist('origin') not in [[origin] for origin in origins]
            or request.headers.getlist('host') not in [['127.0.0.1:8007'], ['127.0.0.1:5177']]
            or request.headers.getlist('x-sentinel-request') != ['sync']):
        raise HTTPException(403, 'Request forbidden')
    if request.url.query:
        raise HTTPException(422, 'Query parameters not accepted')


def _private_errors(handler):
    @wraps(handler)
    async def boundary(request: Request):
        try:
            return await handler(request)
        except HTTPException as exc:
            error = HTTPException(exc.status_code, exc.detail, headers=exc.headers)
        except Exception:
            error = RuntimeError('Request failed')
        # Raise outside the handler's except block: neither its traceback nor
        # its implicit context should retain the parsed request body.
        raise error
    return boundary


def install_disabled_route(app, origins):
    @app.post('/api/fortress/audit')
    @_private_errors
    async def audit(request: Request):
        _guard(request, origins)
        tokens = request.headers.getlist('x-sentinel-capability')
        if len(tokens) != 1 or not tokens[0].isascii() or not secrets.compare_digest(tokens[0], _CAPABILITY):
            raise HTTPException(403, 'Request forbidden')
        if request.headers.getlist('content-type') != ['application/json']:
            raise HTTPException(415, 'JSON required')
        body = await _read_body(request, _BODY_LIMIT)
        def pairs(items):
            obj = {}
            for key, value in items:
                if key in obj:
                    raise ValueError('duplicate')
                obj[key] = value
            return obj
        try:
            data = json.loads(body, object_pairs_hook=pairs)
            if not isinstance(data, dict) or set(data) != {'url', 'consent'} or data['consent'] is not True:
                raise ValueError('invalid')
            _, _, _, target = validate_url(data['url'])
        except (ValueError, UnicodeDecodeError, TypeError, RecursionError):
            raise HTTPException(422, 'Invalid body') from None
        try:
            observation = await run_in_threadpool(_run_live, data['url'], target)
        except BlockingIOError:
            raise HTTPException(409, 'Audit busy') from None
        except Exception:
            raise HTTPException(503, 'Audit unavailable') from None
        return JSONResponse(observation, headers={'Cache-Control': 'no-store'})

    @app.get('/api/fortress/mvp/capability')
    async def capability(request: Request):
        _guard(request, origins)
        return JSONResponse({'capability': _CAPABILITY}, headers={'Cache-Control': 'no-store'})

    @app.post('/api/fortress/mvp/demo')
    @_private_errors
    async def demo(request: Request):
        _guard(request, origins)
        tokens = request.headers.getlist('x-sentinel-capability')
        if len(tokens) != 1 or not tokens[0].isascii() or not secrets.compare_digest(tokens[0], _CAPABILITY):
            raise HTTPException(403, 'Request forbidden')
        if request.headers.getlist('content-type') != ['application/json']:
            raise HTTPException(415, 'JSON required')
        body = await _read_body(request, 512)
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError('duplicate key')
                result[key] = value
            return result
        try:
            data = json.loads(body, object_pairs_hook=pairs)
        except (ValueError, UnicodeDecodeError, RecursionError):
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
