"""Internal-only, incomplete prototype. Production activation is prohibited.

The HTTP endpoint remains disabled and must never call this module. Deep mode is
rejected before transport/DNS. The Windows global mutex is fail-closed on access
failure, but its ACL and cross-session behavior are not independently verified.
It does not coordinate other machines or deployments.
No Python naming convention is a security boundary against trusted in-process code.
"""
from datetime import datetime, timezone
import re
import threading
import os
import ctypes
import sys
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
    # No fallback if the global namespace cannot be opened or acquired.
    handle = None
    kernel = None
    try:
        kernel = _mutex_api()
        ctypes.set_last_error(0)
        handle = kernel.CreateMutexW(None, False, r'Global\SentinelX-P2-DigitalFortress-Audit')
        # An existing object, including an unowned one, has an untrusted origin.
        # Never rely on the creator's default DACL as an identity guarantee.
        if not handle or ctypes.get_last_error() != 0:
            raise AuditError('audit unavailable')
        if kernel.WaitForSingleObject(handle, 0) != 0:
            raise AuditError('audit unavailable')
        acquired, handle = (kernel, handle), None
        return acquired
    except Exception:
        raise AuditError('audit unavailable') from None
    finally:
        if handle and kernel:
            try:
                closed = kernel.CloseHandle(handle)
            except Exception:
                closed = False
            if not closed:
                error = sys.exception()
                if error is not None:
                    error.add_note('mutex cleanup failed; handle may remain open')
                else:
                    raise AuditError('mutex cleanup failed; handle may remain open') from None


def _release_process_mutex(mutex):
    # Reuse the initialized API: rebuilding WinDLL here could strand the handle.
    kernel, handle = mutex
    failed = False
    try:
        if not kernel.ReleaseMutex(handle):
            failed = True
    except Exception:
        failed = True
    finally:
        try:
            if not kernel.CloseHandle(handle):
                failed = True
        except Exception:
            failed = True
    if failed:
        raise AuditError('mutex cleanup failed; handle may remain open or mutex owned') from None


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
    if any(v < 0 or v > count for v in values):
        return {}
    return {'cookie_attributes': {'complete': True, 'observed': any(values), 'cookie_count': count}}


def _audit(payload, *, language='en'):
    """Internal prototype only; not authorized for HTTP or production use."""
    return _audit_with_factory(payload, language=language, factory=_SafeTransport)


def _audit_single_with_factory(raw_json, *, factory, language='en'):
    """Experimental trusted-Python seam only, never mount or accept a factory over HTTP.

    Injectable network dependencies are exclusively for owned tests. The default
    production API remains disabled. Synchronous timeouts are cooperative and do
    not cancel blocked DNS/native calls: this is not qualified for Internet use.
    """
    from .fortress_single_scope import prepare_single_scope
    payload = prepare_single_scope(raw_json)
    return _audit_with_factory(payload, factory=factory, language=language, _strict_single=True)


def _audit_with_factory(payload, *, factory, language='en', _strict_single=False):
    """Trusted in-process lab seam; factory must never come from a request."""
    scope, routes, level = _validate(payload, language)
    if _strict_single and len(routes) != 1:
        raise AuditError('invalid audit request') from None
    if level == 'deep':
        raise AuditError('deep mode unavailable') from None
    if not _AUDIT_LOCK.acquire(blocking=False):
        raise AuditError('audit unavailable') from None
    mutex = None
    try:
        mutex = _acquire_process_mutex()
        started = datetime.now(timezone.utc)
        findings = []
        route_execution = []
        used = 0
        stopped = False
        http_status = None
        failure_code = 'unknown'
        try:
            transport = factory(scope, max_requests=1 if _strict_single else 30,
                                       **({'strict_standard': True} if _strict_single else {}),
                                       allowed_methods=frozenset((_parse(route)[1], 'GET') for route in routes))
        except Exception:
            transport = None
            stopped = True
        for route_index, route in enumerate(routes, 1):
            facts = {}
            x_content_code = None
            header_codes = {}
            state = 'not_started'
            if not stopped:
                try:
                    before = transport.count
                    if type(before) is not int or before != used or not 0 <= before < 30 or transport.blocked is not False:
                        raise ValueError()
                    state = 'indeterminate'
                    observation = transport.observe_headers('GET', route)
                    after = transport.count
                    if type(after) is not int or not before < after <= (1 if _strict_single else 30):
                        raise ValueError()
                    used = after
                    if _strict_single:
                        if (type(observation) is dict and set(observation) == {'outcome', 'failure_code'} and observation.get('outcome') == 'error'
                                and transport.blocked is True and after - before == 1):
                            candidate = observation.get('failure_code')
                            if type(candidate) is str and candidate in ('security_refused', 'incomplete', 'timeout', 'tls_or_transport'):
                                failure_code = candidate
                            raise ValueError()
                        # Accept facts only from a consistent, complete direct response.
                        # Redirects have their own non-conformant, no-facts path.
                        status = observation.get('status') if type(observation) is dict else None
                        direct = (type(status) is int and 200 <= status < 300 and status != 206 and
                                  observation.get('redirected') is False and observation.get('outcome') == 'ok' and
                                  transport.blocked is False)
                        redirect = (type(status) is int and status in (301, 302, 303, 307, 308) and
                                    observation.get('redirected') is True and observation.get('outcome') == 'indeterminate' and
                                    type(transport.blocked) is bool)
                        refused = (type(status) is int and status == 403 and
                                   observation.get('redirected') is False and observation.get('outcome') == 'http_refused' and
                                   transport.blocked is True and after - before == 1)
                        if not (direct or redirect or refused):
                            raise ValueError()
                        failure_code = 'http_refused' if refused else 'none'
                        if refused:
                            http_status = status
                    if (_strict_single and type(observation) is dict and after - before == 1 and
                            observation.get('outcome') in ('ok', 'indeterminate') and
                            (transport.blocked is False or (observation.get('outcome') == 'indeterminate' and
                             observation.get('redirected') is True and observation.get('status') in (301, 302, 303, 307, 308))) and
                            type(observation.get('status')) is int and 100 <= observation['status'] <= 599):
                        http_status = observation['status']
                    if _strict_single and http_status in (301, 302, 303, 307, 308) and observation.get('redirected') is True:
                        state = 'redirected'
                    elif _strict_single and refused:
                        state = 'indeterminate'
                    elif transport.blocked is True:
                        state = 'blocked'
                    elif type(observation) is dict and observation.get('redirected') is True:
                        state = 'redirected'
                    elif (type(observation) is dict and observation.get('outcome') == 'ok' and
                          transport.blocked is False and after - before == 1 and
                          observation.get('redirected', False) is False):
                        state = 'completed'
                    if type(observation) is not dict or observation.get('outcome') != 'ok' or transport.blocked is not False:
                        stopped = True
                    elif after - before == 1:
                        facts = _cookie_fact(observation)
                        tls = observation.get('tls')
                        if (scope.origin[0] == 'https' and observation.get('redirected', False) is False and
                            type(tls) is dict and set(tls) == {'certificate', 'protocol'} and
                            tls['certificate'] == 'verified' and tls['protocol'] in ('TLSv1.2', 'TLSv1.3')):
                            facts['https_tls'] = {'complete': True, 'observed': True}
                        # The observer emits 'absent' only for complete direct headers;
                        # recognized presence is not evidence of effective protection.
                        headers = observation.get('security_headers')
                        if observation.get('redirected', False) is False and type(headers) is dict:
                            for name in ('hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy'):
                                if (name != 'hsts' or scope.origin[0] == 'https') and type(headers.get(name)) is str and headers[name] == 'absent':
                                    facts[name] = {'complete': True, 'observed': False}
                                elif _strict_single and (name != 'hsts' or scope.origin[0] == 'https') and type(headers.get(name)) is str:
                                    if headers[name] == 'invalid':
                                        facts[name] = {'complete': True, 'observed': False}
                                        header_codes[name] = 'header_invalid'
                                    elif headers[name] == 'present':
                                        header_codes[name] = 'header_syntax_recognized'
                        if _strict_single and observation.get('redirected', False) is False:
                            derived = observation.get('header_value_facts')
                            # Both classifiers describe the same header. A missing,
                            # malformed or incompatible pair cannot establish either
                            # presence or absence, even if one looks convincing.
                            presence = headers.get('x_content_type_options') if type(headers) is dict else None
                            value = derived.get('x_content_type_options') if type(derived) is dict else None
                            facts.pop('x_content_type_options', None)
                            header_codes.pop('x_content_type_options', None)
                            if type(presence) is str and type(value) is str:
                                if (presence, value) in (('present', 'recognized_nosniff'),
                                                         ('unknown', 'other_token'),
                                                         ('invalid', 'invalid'), ('absent', 'absent')):
                                    facts['x_content_type_options'] = {'complete': True, 'observed': value == 'recognized_nosniff'}
                                    x_content_code = ('header_valid' if value == 'recognized_nosniff' else
                                                      'header_absent' if value == 'absent' else 'header_invalid')
                except Exception:
                    # No exception text, raw observation, or target data may escape.
                    try:
                        if transport.blocked is True:
                            state = 'blocked'
                        count = transport.count
                        if type(count) is int and used <= count <= 30:
                            used = count
                    except Exception:
                        pass
                    stopped = True
            route_execution.append({'route_index': route_index, 'state': state})
            route_findings = evaluate_findings(facts, route='[redacted route]', method='GET', date=started.date().isoformat(), language=language)
            for finding in route_findings:
                finding['route_index'] = route_index
                if finding['id'] == 'cookie_attributes' and finding['status'] == 'conformant':
                    finding['evidence'] = ('Attributs recommandés observés sur les cookies examinés.' if language == 'fr' else
                                           'Observed recommended attributes on examined cookies.')
                    finding['reason'] = ('Observation limitée ; pertinence indéterminée, sans certification.' if language == 'fr' else
                                         'Limited observation; applicability is indeterminate, not a certification.')
                finding['evidence_code'] = ('cookie_attributes_present' if finding['id'] == 'cookie_attributes' and finding['status'] == 'conformant'
                                            else 'tls_verified' if finding['id'] == 'https_tls' and finding['status'] == 'conformant'
                                            else 'cookie_attributes_missing' if finding['id'] == 'cookie_attributes' and finding['status'] == 'attention'
                                            else 'header_absent' if finding['id'] in facts and finding['status'] == 'attention'
                                            else 'indeterminate')
                if finding['id'] == 'x_content_type_options' and x_content_code is not None:
                    finding['evidence_code'] = x_content_code
                elif _strict_single and finding['id'] in header_codes:
                    finding['evidence_code'] = header_codes[finding['id']]
                if _strict_single and finding['evidence_code'] in ('header_syntax_recognized', 'header_invalid'):
                    if finding['evidence_code'] == 'header_syntax_recognized':
                        finding['evidence'] = ('Syntaxe limitée reconnue ; efficacité non établie.' if language == 'fr' else
                                               'Limited syntax recognized; effectiveness not established.')
                        finding['reason'] = ('La protection reste indéterminée.' if language == 'fr' else
                                             'Protection remains indeterminate.')
                    else:
                        finding['evidence'] = ('Valeur vide ou catégorie invalide observée.' if language == 'fr' else
                                               'Empty value or invalid category observed.')
            findings.extend(route_findings)
        finished = datetime.now(timezone.utc)
        result = {'audit_id': str(uuid4()), 'mode': level, 'started_at': started.isoformat(),
                'finished_at': finished.isoformat(), 'scope': {'origin': '[redacted]', 'paths': ['[redacted route]'] * len(routes)},
                'requests_used': used, 'complete': False, 'findings': findings, 'route_execution': route_execution,
                'limitations': (['Prototype incomplet : contrôles CORS et sondes non effectués ; aucune évaluation des avis.'] if language == 'fr' else
                                ['Incomplete prototype: CORS and probes not performed; advisory assessment unavailable.'])}
        if _strict_single:
            result['http_status'] = http_status
            result['failure_code'] = failure_code
            result['limitations'].append(
                'Analyse des valeurs limitée à des catégories syntaxiques ; les valeurs brutes et l’efficacité des politiques ne sont pas établies.'
                if language == 'fr' else
                'Value analysis is limited to syntax categories; raw values and policy effectiveness are not established.')
        return result
    finally:
        previous = sys.exception()
        try:
            if mutex is not None:
                try:
                    _release_process_mutex(mutex)
                except AuditError:
                    if previous is None:
                        raise
                    previous.add_note('mutex cleanup failed; handle may remain open or mutex owned')
        finally:
            _AUDIT_LOCK.release()
