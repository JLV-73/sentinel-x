"""DRAFT experimental test-only ASGI adapter. Never mount in an application.

The consumer is trusted Python test code, never selectable over HTTP. This is
not a deployment boundary, a real endpoint, or proof of production safety.
The receive timeout is cooperative, not a hard wall-clock deadline; it cannot
preempt synchronous code or a consumer. The fragment bound is independent.
"""
import json
import re
from datetime import datetime
import anyio
from app.fortress_service import _validate, AuditError
from app.fortress_checks import evaluate_findings

LIMIT = 16 * 1024
MAX_FRAGMENTS = 1024
NAMES = ('https_tls', 'hsts', 'csp', 'x_content_type_options', 'referrer_policy',
         'permissions_policy', 'cookie_attributes', 'third_party_scripts', 'version',
         'debug_info', 'directory_index', 'cors', 'redirect', 'reflection')
HEADERS_CHECKS = frozenset(('hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy'))


def _project(result, payload):
    """Fail closed; emit only fixed text and validated finite service categories.

    Templates validate the current prototype's supported outcomes, not arbitrary
    consumer text. Metadata and evidence are discarded, not sanitized. Numeric
    request count and route count remain bounded service facts.
    """
    if type(result) is dict and result == {'ok': True} and type(result['ok']) is bool:
        return {'ok': True}  # fixed test sentinel
    keys = {'audit_id', 'mode', 'started_at', 'finished_at', 'scope', 'requests_used', 'complete', 'findings', 'limitations', 'route_execution'}
    if type(result) is not dict or set(result) != keys:
        raise ValueError()
    if (type(result['audit_id']) is not str or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', result['audit_id']) or
        result['mode'] != 'standard' or type(result['mode']) is not str or result['complete'] is not False or
        type(result['requests_used']) is not int or not 0 <= result['requests_used'] <= 30 or
        result['scope'] != {'origin': '[redacted]', 'paths': ['[redacted route]'] * len(payload['routes'])} or
        result['limitations'] != ['Incomplete prototype: CORS and probes not performed; advisory assessment unavailable.']):
        raise ValueError()
    for key in ('started_at', 'finished_at'):
        if type(result[key]) is not str:
            raise ValueError()
        datetime.fromisoformat(result[key])
    execution = result['route_execution']
    states = ('not_started', 'completed', 'indeterminate', 'redirected', 'blocked')
    if type(execution) is not list or len(execution) != len(payload['routes']):
        raise ValueError()
    for index, item in enumerate(execution, 1):
        if (type(item) is not dict or set(item) != {'route_index', 'state'} or
            type(item['route_index']) is not int or item['route_index'] != index or
            type(item['state']) is not str or item['state'] not in states):
            raise ValueError()
    if sum(item['state'] in ('completed', 'redirected') for item in execution) > result['requests_used']:
        raise ValueError()
    findings = result['findings']
    if type(findings) is not list or len(findings) != len(NAMES) * len(payload['routes']):
        raise ValueError()
    projected = []
    for index, item in enumerate(findings):
        name = NAMES[index % len(NAMES)]
        if type(item) is not dict or type(item.get('date')) is not str:
            raise ValueError()
        # Regenerate exact known service text for the admitted finite outcomes.
        date = item['date']
        if type(item.get('route_index')) is not int or item['route_index'] != index // len(NAMES) + 1:
            raise ValueError()
        code = item.get('evidence_code')
        base = {k: v for k, v in item.items() if k not in ('route_index', 'evidence_code')}
        candidates = [evaluate_findings({}, route='[redacted route]', method='GET', date=date)[index % len(NAMES)]]
        if name in HEADERS_CHECKS:
            candidates.append(evaluate_findings({name: {'complete': True, 'observed': False}}, route='[redacted route]', method='GET', date=date)[index % len(NAMES)])
        elif name == 'https_tls':
            candidates.append(evaluate_findings({name: {'complete': True, 'observed': True}}, route='[redacted route]', method='GET', date=date)[index % len(NAMES)])
        elif name == 'cookie_attributes' and type(item.get('evidence')) is str:
            positive = evaluate_findings({name: {'complete': True, 'observed': False, 'cookie_count': 1}}, route='[redacted route]', method='GET', date=date)[index % len(NAMES)]
            positive['evidence'] = 'Observed recommended attributes on examined cookies.'
            positive['reason'] = 'Limited observation; applicability is indeterminate, not a certification.'
            candidates.append(positive)
            match = re.search(r' Cookie count: ([1-9][0-9]{0,4})\.', item['evidence'])
            if match and int(match.group(1)) <= 10000:
                facts = {name: {'complete': True, 'observed': True, 'cookie_count': int(match.group(1))}}
                candidates.append(evaluate_findings(facts, route='[redacted route]', method='GET', date=date)[index % len(NAMES)])
        expected_code = ('cookie_attributes_present' if name == 'cookie_attributes' and item.get('status') == 'conformant'
                         else 'tls_verified' if name == 'https_tls' and item.get('status') == 'conformant'
                         else 'cookie_attributes_missing' if name == 'cookie_attributes' and item.get('status') == 'attention'
                         else 'header_absent' if name in HEADERS_CHECKS and item.get('status') == 'attention'
                         else 'indeterminate')
        if type(code) is not str or code != expected_code or base not in candidates:
            raise ValueError()
        status = item['status']
        projected.append({'id': name, 'status': status, 'severity': 'low' if status == 'attention' else 'info' if status == 'conformant' else 'unknown',
                          'reason': 'See status.', 'evidence': 'Details withheld.',
                          'limitations': 'Incomplete prototype.', 'preconditions': 'Authorized observation required.',
                          'recommendation': 'Review within authorized scope.', 'reference': 'Not provided.',
                          'method': 'GET', 'route': '[redacted route]', 'date': 'unknown',
                          'route_index': item['route_index'], 'evidence_code': code})
    return {'audit_id': 'withheld', 'mode': 'standard', 'started_at': 'withheld', 'finished_at': 'withheld',
            'scope': {'origin': '[redacted]', 'paths': ['[redacted route]'] * len(payload['routes'])},
            'requests_used': result['requests_used'], 'complete': False, 'findings': projected,
            'route_execution': [{'route_index': item['route_index'], 'state': item['state']} for item in execution],
            'limitations': ['Incomplete prototype.']}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def _constant(_):
    raise ValueError('invalid constant')


class DraftFortressAdapter:
    def __init__(self, consumer, *, host='test.local', origin='http://test.local', timeout=0.2):
        self.consumer, self.host, self.origin, self.timeout = consumer, host, origin, timeout

    async def __call__(self, scope, receive, send):
        status, result = await self._handle(scope, receive)
        data = json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('ascii')
        await send({'type': 'http.response.start', 'status': status, 'headers': [(b'content-type', b'application/json'), (b'content-length', str(len(data)).encode())]})
        await send({'type': 'http.response.body', 'body': data})

    async def _handle(self, scope, receive):
        try:
            if scope.get('type') != 'http' or scope.get('path') != '/api/fortress/audit' or scope.get('method') != 'POST':
                return 404, {'error': 'not found'}
            headers = {}
            for key, value in scope.get('headers', []):
                headers.setdefault(key.lower(), []).append(value)
            if (headers.get(b'host') != [self.host.encode('ascii')] or
                headers.get(b'origin') != [self.origin.encode('ascii')] or
                headers.get(b'x-sentinel-request') != [b'sync']):
                return 403, {'error': 'forbidden'}
            if scope.get('query_string', b''):
                return 422, {'error': 'invalid request'}
            if headers.get(b'content-type') != [b'application/json']:
                return 415, {'error': 'unsupported media type'}
            if headers.get(b'content-encoding', []) not in ([], [b'identity']):
                return 415, {'error': 'unsupported media type'}
            length = headers.get(b'content-length', [])
            if len(length) > 1 or (length and not re.fullmatch(rb'[0-9]+', length[0])):
                return 400, {'error': 'invalid request'}
            declared = int(length[0]) if length else None
            if declared is not None and declared > LIMIT:
                return 413, {'error': 'request too large'}
            chunks, size, fragments = [], 0, 0
            try:
                with anyio.fail_after(self.timeout):
                    while True:
                        msg = await receive()
                        fragments += 1
                        if fragments > MAX_FRAGMENTS:
                            return 413, {'error': 'request too large'}
                        if msg.get('type') != 'http.request' or type(msg.get('body', b'')) is not bytes:
                            return 400, {'error': 'invalid request'}
                        chunk = msg.get('body', b'')
                        size += len(chunk)
                        if size > LIMIT:
                            return 413, {'error': 'request too large'}
                        chunks.append(chunk)
                        if not msg.get('more_body', False):
                            break
            except TimeoutError:
                return 408, {'error': 'request timeout'}
            if declared is not None and declared != size:
                return 400, {'error': 'invalid request'}
            try:
                payload = json.loads(b''.join(chunks).decode('utf-8', errors='strict'), object_pairs_hook=_object, parse_constant=_constant)
                if type(payload) is not dict:
                    raise ValueError()
                _validate(payload, 'en')
            except (ValueError, UnicodeError, RecursionError):
                return 422, {'error': 'invalid request'}
            try:
                result = _project(self.consumer(payload), payload)
                return 200, result
            except Exception:
                return 503, {'error': 'unavailable'}
        except Exception:
            return 400, {'error': 'invalid request'}
