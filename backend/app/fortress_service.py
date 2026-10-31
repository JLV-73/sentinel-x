"""Internal-only, incomplete prototype. Production activation is prohibited.

The HTTP endpoint remains disabled and must never call this module. Deep mode is
rejected before transport/DNS. The Windows mutex covers only one logon session,
not other sessions, machines or deployments; it is not a global safety proof.
No Python naming convention is a security boundary against trusted in-process code.
"""
from datetime import datetime, timezone
import re
import threading
import os
import ctypes
from ctypes import wintypes
from uuid import uuid4

from .fortress_checks import evaluate_findings
from .fortress_transport import SafeTransport as _SafeTransport, _parse, validate_scope

__all__ = ()


class AuditError(ValueError):
    """A redacted validation or concurrency failure."""


_AUDIT_LOCK = threading.Lock()
_FIELDS = frozenset(('level', 'authorized', 'routes'))
_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_.-]{0,63}\Z')
_SENSITIVE = re.compile(r'pass|token|secret|auth|session|cookie|credential|api.?key', re.I)


def _mutex_api():
    if os.name != 'nt':
        raise AuditError('audit unavailable') from None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.ReleaseMutex.argtypes = (wintypes.HANDLE,)
    kernel.ReleaseMutex.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def _acquire_process_mutex():
    # Local namespace is only one Windows session, NOT deployment-wide.
    try:
        kernel = _mutex_api()
        handle = kernel.CreateMutexW(None, False, r'Local\SentinelX-P2-DigitalFortress-Audit')
        if not handle:
            raise AuditError('audit unavailable')
        result = kernel.WaitForSingleObject(handle, 0)
        if result not in (0, 0x80):  # normal or abandoned ownership
            kernel.CloseHandle(handle)
            raise AuditError('audit unavailable')
        return handle
    except Exception:
        raise AuditError('audit unavailable') from None


def _release_process_mutex(handle):
    kernel = _mutex_api()
    try:
        kernel.ReleaseMutex(handle)
    finally:
        kernel.CloseHandle(handle)


def _validate(payload, language):
    try:
        if type(payload) is not dict or set(payload) != _FIELDS or payload['authorized'] is not True:
            raise ValueError()
        if language not in ('en', 'fr') or type(language) is not str:
            raise ValueError()
        if type(payload['level']) is not str or payload['level'] != 'standard':
            raise ValueError()
        entries = payload['routes']
        if type(entries) is not list or not 1 <= len(entries) <= 4:
            raise ValueError()
        routes = []
        for entry in entries:
            if type(entry) is not dict or set(entry) != {'url', 'safe_use_confirmed', 'methods', 'cors_get', 'parameters'}:
                raise ValueError()
            if (type(entry['url']) is not str or '?' in entry['url'] or
                entry['safe_use_confirmed'] is not True or type(entry['methods']) is not list or
                entry['methods'] != ['GET'] or entry['cors_get'] is not False or
                type(entry['parameters']) is not list or entry['parameters'] != []):
                raise ValueError()
            routes.append(entry['url'])
        scope = validate_scope(routes[0], routes[1:])
        canonical = [_parse(url)[1] for url in routes]
        if len(set(canonical)) != len(canonical):
            raise ValueError()
        return scope, tuple(routes), payload['level']
    except Exception:
        raise AuditError('invalid audit request') from None


def _cookie_fact(observation):
    if (type(observation) is not dict or observation.get('outcome') != 'ok' or
        observation.get('redirected', False) is not False):
        return {}
    cookies = observation.get('cookies')
    keys = ('count', 'missing_secure', 'missing_httponly', 'missing_samesite', 'indeterminate')
    if type(cookies) is not dict or any(type(cookies.get(k)) is not int for k in keys):
        return {}
    count = cookies['count']
    if not 1 <= count <= 10000 or cookies['indeterminate'] != 0:
        return {}
    values = [cookies[k] for k in keys[1:4]]
    if any(v < 0 or v > count for v in values) or not any(values):
        return {}
    return {'cookie_attributes': {'complete': True, 'observed': True, 'cookie_count': count}}


def _audit(payload, *, language='en'):
    """Internal prototype only; not authorized for HTTP or production use."""
    scope, routes, level = _validate(payload, language)
    if level == 'deep':
        raise AuditError('deep mode unavailable') from None
    if not _AUDIT_LOCK.acquire(blocking=False):
        raise AuditError('audit unavailable') from None
    mutex = None
    try:
        mutex = _acquire_process_mutex()
        started = datetime.now(timezone.utc)
        findings = []
        used = 0
        stopped = False
        try:
            transport = _SafeTransport(scope, max_requests=30,
                                       allowed_methods=frozenset((_parse(route)[1], 'GET') for route in routes))
        except Exception:
            transport = None
            stopped = True
        for route in routes:
            facts = {}
            if not stopped:
                try:
                    before = transport.count
                    if type(before) is not int or before != used or not 0 <= before < 30 or transport.blocked is not False:
                        raise ValueError()
                    observation = transport.observe_headers('GET', route)
                    after = transport.count
                    if type(after) is not int or not before < after <= 30:
                        raise ValueError()
                    used = after
                    if type(observation) is not dict or observation.get('outcome') != 'ok' or transport.blocked is not False:
                        stopped = True
                    elif after - before == 1:
                        facts = _cookie_fact(observation)
                        # The observer emits 'absent' only for complete direct headers;
                        # recognized presence is not evidence of effective protection.
                        headers = observation.get('security_headers')
                        if observation.get('redirected', False) is False and type(headers) is dict:
                            for name in ('hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy'):
                                if type(headers.get(name)) is str and headers[name] == 'absent':
                                    facts[name] = {'complete': True, 'observed': False}
                except Exception:
                    # No exception text, raw observation, or target data may escape.
                    try:
                        count = transport.count
                        if type(count) is int and used <= count <= 30:
                            used = count
                    except Exception:
                        pass
                    stopped = True
            findings.extend(evaluate_findings(facts, route='[redacted route]', method='GET', date=started.date().isoformat(), language=language))
        finished = datetime.now(timezone.utc)
        return {'audit_id': str(uuid4()), 'mode': level, 'started_at': started.isoformat(),
                'finished_at': finished.isoformat(), 'scope': {'origin': '[redacted]', 'paths': ['[redacted route]'] * len(routes)},
                'requests_used': used, 'complete': False, 'findings': findings,
                'limitations': (['Prototype incomplet : contrôles CORS et sondes non effectués ; aucune évaluation des avis.'] if language == 'fr' else
                                ['Incomplete prototype: CORS and probes not performed; advisory assessment unavailable.'])}
    finally:
        try:
            if mutex is not None:
                _release_process_mutex(mutex)
        finally:
            _AUDIT_LOCK.release()
