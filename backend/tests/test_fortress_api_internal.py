"""DRAFT: isolated ASGI contract tests, not production activation."""
import asyncio
import json
import socket
import pytest


def test_adapter_exists():
    from support_fortress_api import DraftFortressAdapter
    assert callable(DraftFortressAdapter)

import app.fortress_service as service
from support_fortress_api import DraftFortressAdapter

SENTINEL = 'PRIVATE_SENTINEL_123'
HEADERS = [(b'host', b'test.local'), (b'origin', b'http://test.local'), (b'x-sentinel-request', b'sync'), (b'content-type', b'application/json')]


def payload():
    return {'level':'standard', 'authorized':True, 'routes':[{'url':'https://example.invalid/'+SENTINEL, 'safe_use_confirmed':True, 'methods':['GET'], 'cors_get':False, 'parameters':[]}]}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    # Windows creates its private asyncio wakeup socketpair before the guard.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    def denied(*a, **kw):
        raise AssertionError('network prohibited')
    monkeypatch.setattr(socket, 'getaddrinfo', denied)
    monkeypatch.setattr(socket.socket, 'connect', denied)
    monkeypatch.setattr(socket.socket, 'connect_ex', denied)
    yield
    loop.close()
    asyncio.set_event_loop(None)


def run(body=None, headers=None, query=b'', chunks=None, consumer=None, stall=False):
    if body is None:
        body = json.dumps(payload()).encode()
    scope = {'type':'http', 'method':'POST', 'path':'/api/fortress/audit', 'query_string':query, 'headers':list(HEADERS if headers is None else headers)}
    messages = list(chunks if chunks is not None else [{'type':'http.request', 'body':body}])
    sent = []
    async def receive():
        if messages:
            return messages.pop(0)
        if stall:
            await asyncio.sleep(10)
        return {'type':'http.disconnect'}
    async def send(m):
        sent.append(m)
    async def go():
        await DraftFortressAdapter(consumer or (lambda p: {'ok':True}), timeout=0.02)(scope, receive, send)
    asyncio.get_event_loop().run_until_complete(go())
    assert [m['type'] for m in sent] == ['http.response.start', 'http.response.body']
    return sent[0]['status'], json.loads(sent[1]['body'])


def test_valid():
    assert run() == (200, {'ok':True})


@pytest.mark.parametrize('key', [b'host', b'origin', b'x-sentinel-request'])
@pytest.mark.parametrize('case', ['missing', 'duplicate', 'wrong'])
def test_boundary_singletons(key, case):
    headers = [h for h in HEADERS if h[0] != key]
    original = next(v for k,v in HEADERS if k == key)
    headers += [] if case == 'missing' else ([(key, original), (key, original)] if case == 'duplicate' else [(key, b'wrong')])
    calls = []
    assert run(headers=headers, consumer=lambda p: calls.append(p))[0] == 403
    assert not calls


@pytest.mark.parametrize('query', [b'x=1', b'?', b'x=', b'SECRET'])
def test_query_rejected(query):
    assert run(query=query)[0] == 422


@pytest.mark.parametrize('extra,expected', [([(b'content-length', b'-1')],400), ([(b'content-length', b'1'),(b'content-length', b'1')],400), ([(b'content-length', b'1')],400), ([(b'content-length', b'16385')],413), ([(b'content-length', b'+1')],400), ([(b'content-length', b'1,1')],400)])
def test_length(extra, expected):
    assert run(headers=HEADERS + extra)[0] == expected


def test_valid_length():
    body = json.dumps(payload()).encode()
    assert run(body=body, headers=HEADERS + [(b'content-length', str(len(body)).encode())])[0] == 200


def test_stream_over_limit_and_timeout():
    chunks = [{'type':'http.request','body':b' '*10000,'more_body':True}, {'type':'http.request','body':b' '*6385}]
    assert run(chunks=chunks)[0] == 413
    assert run(chunks=[{'type':'http.request','body':b'{','more_body':True}], stall=True)[0] == 408


def test_stream_exact_limit():
    body = json.dumps(payload()).encode()
    body += b' '*(16384-len(body))
    assert run(chunks=[{'type':'http.request','body':body[:8000],'more_body':True}, {'type':'http.request','body':body[8000:]}])[0] == 200


@pytest.mark.parametrize('headers', [[], [(b'content-type',b'text/plain')], [(b'content-type',b'application/json'),(b'content-type',b'application/json')]])
def test_content_type(headers):
    assert run(headers=[h for h in HEADERS if h[0] != b'content-type']+headers)[0] == 415


@pytest.mark.parametrize('body', [b'\xff', b'[]', b'null', b'NaN', b'{"x":1,"x":2}', b'{"x":{"a":1,"a":2}}', b'{', b'{"authorized":true,"authorized":true}'])
def test_json_rejected(body):
    calls = []
    status, result = run(body=body, consumer=lambda p: calls.append(p))
    assert status == 422 and result == {'error':'invalid request'} and not calls


@pytest.mark.parametrize('mutate', [lambda p:p.pop('authorized'), lambda p:p.update(authorized=False), lambda p:p.update(level='deep'), lambda p:p.update(secret=SENTINEL), lambda p:p['routes'][0].update(url='https://example.invalid/?token='+SENTINEL), lambda p:p['routes'][0].update(url='http://127.0.0.1/')])
def test_dto_before_consumer(mutate):
    p = payload(); mutate(p); calls = []
    status, result = run(body=json.dumps(p).encode(), consumer=lambda p: calls.append(p))
    assert status == 422 and not calls and SENTINEL not in json.dumps(result)


def test_consumer_error_redacted():
    def fail(p):
        raise RuntimeError(SENTINEL)
    status, result = run(consumer=fail)
    assert status == 503 and result == {'error':'unavailable'} and SENTINEL not in json.dumps(result)


@pytest.mark.parametrize('encodings', [[(b'content-encoding', b'gzip')], [(b'content-encoding', b'identity'), (b'content-encoding', b'identity')], [(b'content-encoding', b'identity,gzip')], [(b'content-encoding', b'')]])
def test_content_encoding_rejected_before_consumer(encodings):
    calls = []
    assert run(headers=HEADERS + encodings, consumer=lambda p: calls.append(p))[0] == 415
    assert not calls


def test_empty_fragment_flood_rejected():
    calls = []
    chunks = [{'type': 'http.request', 'body': b'', 'more_body': True}] * 1025
    assert run(chunks=chunks, consumer=lambda p: calls.append(p))[0] == 413
    assert not calls


def test_fragment_limit_includes_last_message():
    body = json.dumps(payload()).encode()
    chunks = [{'type': 'http.request', 'body': b'', 'more_body': True}] * 1023
    assert run(chunks=chunks + [{'type': 'http.request', 'body': body}])[0] == 200


def test_consumer_secret_result_fails_closed():
    status, result = run(consumer=lambda p: {'ok': True, 'leak': SENTINEL})
    assert status == 503 and result == {'error': 'unavailable'}


@pytest.mark.parametrize('field', ['reason', 'evidence', 'id', 'status', 'severity', 'limitations', 'preconditions', 'recommendation', 'reference', 'method', 'route', 'date', 'extra', 'route_index', 'evidence_code'])
def test_real_shape_with_secret_field_fails_closed(monkeypatch, field):
    class Transport:
        count = 0
        blocked = False
        def __init__(self, *args, **kwargs): pass
        def observe_headers(self, method, url):
            self.count += 1
            return {'outcome':'ok', 'redirected':False, 'security_headers':{'hsts':'absent'}}
    monkeypatch.setattr(service, '_SafeTransport', Transport)
    monkeypatch.setattr(service, '_acquire_process_mutex', lambda: 1)
    monkeypatch.setattr(service, '_release_process_mutex', lambda handle: None)
    def corrupt(p):
        result = service._audit(p)
        result['findings'][0][field] = SENTINEL
        return result
    assert run(consumer=corrupt) == (503, {'error':'unavailable'})


def test_identity_encoding_is_allowed():
    assert run(headers=HEADERS + [(b'content-encoding', b'identity')])[0] == 200


@pytest.mark.parametrize('field,value', [('route_index', True), ('route_index', 0),
    ('route_index', 2), ('route_index', 5), ('evidence_code', 'header_absent'),
    ('evidence_code', 'unknown')])
def test_typed_finding_cross_product_rejects_invalid(monkeypatch, field, value):
    class Transport:
        def __init__(self, *args, **kwargs):
            self.count = 0
            self.blocked = False
        def observe_headers(self, method, url):
            self.count += 1
            return {'outcome': 'ok', 'redirected': False, 'security_headers': {}}
    monkeypatch.setattr(service, '_SafeTransport', Transport)
    monkeypatch.setattr(service, '_acquire_process_mutex', lambda: 1)
    monkeypatch.setattr(service, '_release_process_mutex', lambda handle: None)
    def corrupt(p):
        result = service._audit(p)
        result['findings'][0][field] = value
        return result
    assert run(consumer=corrupt) == (503, {'error': 'unavailable'})


def test_real_service_with_test_only_mock_transport(monkeypatch):
    instances = []
    class Transport:
        def __init__(self, *args, **kwargs):
            self.count = 0; self.blocked = False; instances.append(self)
        def observe_headers(self, method, url):
            self.count += 1
            return {'outcome':'ok', 'redirected':False, 'security_headers':{'hsts':'absent'}}
    monkeypatch.setattr(service, '_SafeTransport', Transport)
    monkeypatch.setattr(service, '_acquire_process_mutex', lambda: 1)
    monkeypatch.setattr(service, '_release_process_mutex', lambda handle: None)
    status, result = run(consumer=service._audit)
    assert status == 200 and len(instances) == 1 and instances[0].count == 1
    assert set(result) == {'audit_id','mode','started_at','finished_at','scope','requests_used','complete','findings','limitations','route_execution'}
    assert result['complete'] is False and result['requests_used'] == 1
    assert result['scope'] == {'origin':'[redacted]','paths':['[redacted route]']}
    assert all(set(f) == {'id','status','severity','reason','evidence','limitations','preconditions','recommendation','reference','method','route','date','route_index','evidence_code'} for f in result['findings'])
    assert all(f['route_index'] == 1 for f in result['findings'])
    assert next(f for f in result['findings'] if f['id'] == 'hsts')['evidence_code'] == 'header_absent'
    encoded = json.dumps(result)
    assert SENTINEL not in encoded and 'example.invalid' not in encoded
