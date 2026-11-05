"""FastAPI qualification in a Python-only isolated test assembly, never production."""
import asyncio
import json

import copy
import socket

import httpx
import pytest
import app.fortress_service as service
import support_fortress_api as support


SECRET = 'PRIVATE_qualification_123'
GOOD_HEADERS = [('host', 'test.local'), ('origin', 'http://test.local'),
                ('x-sentinel-request', 'sync'), ('content-type', 'application/json')]


def request_payload():
    return {'level': 'standard', 'authorized': True, 'routes': [
        {'url': 'https://example.invalid/' + SECRET, 'safe_use_confirmed': True,
         'methods': ['GET'], 'cors_get': False, 'parameters': []}]}


def run_request(app, *, headers=None, body=None, method='POST', path='/api/fortress/audit', monkeypatch=None):
    async def request():
        # The event loop is already created; block DNS and outbound connections.
        if monkeypatch:
            def denied(*args, **kwargs):
                raise AssertionError('network forbidden')
            monkeypatch.setattr(socket, 'getaddrinfo', denied)
            monkeypatch.setattr(socket.socket, 'connect', denied)
            monkeypatch.setattr(socket.socket, 'connect_ex', denied)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test.local') as client:
            return await client.request(method, path, content=json.dumps(request_payload()).encode() if body is None else body,
                                        headers=GOOD_HEADERS if headers is None else headers)
    return asyncio.run(request())


def test_application_contract_exists_and_rejects_before_consumer(monkeypatch):
    import importlib.util
    assert importlib.util.find_spec('app.fortress_standard_contract') is not None, 'application contract missing'
    from app.fortress_standard_contract import DraftFortressAdapter
    calls = []
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    app = FastAPI()
    adapter = DraftFortressAdapter(lambda p: calls.append(p))
    @app.post('/api/fortress/audit')
    async def route(request: Request):
        status, result = await adapter._handle(request.scope, request.receive)
        return JSONResponse(status_code=status, content=result)
    payload = request_payload()
    payload['authorized'] = False
    response = run_request(app, body=json.dumps(payload).encode(), monkeypatch=monkeypatch)
    assert response.status_code == 422 and not calls


def test_isolated_fastapi_accepts_valid_standard_request():
    factory = getattr(support, 'make_qualification_app', None)
    assert factory is not None, 'test-only FastAPI assembly missing'
    app = factory(support.fake_audit_result)
    payload = {'level': 'standard', 'authorized': True, 'routes': [
        {'url': 'https://example.invalid/PRIVATE', 'safe_use_confirmed': True,
         'methods': ['GET'], 'cors_get': False, 'parameters': []}]}
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test.local') as client:
            return await client.post('/api/fortress/audit', json=payload,
                                     headers={'origin': 'http://test.local', 'x-sentinel-request': 'sync'})
    response = asyncio.run(request())
    assert response.status_code == 200
    result = response.json()
    assert set(result) == {'audit_id', 'mode', 'started_at', 'finished_at', 'scope', 'requests_used', 'complete', 'findings', 'limitations', 'route_execution'}
    assert result['mode'] == 'standard' and result['complete'] is False
    assert result['scope'] == {'origin': '[redacted]', 'paths': ['[redacted route]']}
    assert len(result['findings']) == 14 and 'PRIVATE' not in response.text


@pytest.mark.parametrize('key', ['host', 'origin', 'x-sentinel-request'])
@pytest.mark.parametrize('case', ['wrong', 'duplicate'])
def test_fastapi_singletons_block_before_consumer(key, case, monkeypatch):
    calls = []
    original = next(v for k, v in GOOD_HEADERS if k == key)
    headers = [(k, v) for k, v in GOOD_HEADERS if k != key]
    headers.extend([(key, 'wrong')] if case == 'wrong' else [(key, original), (key, original)])
    response = run_request(support.make_qualification_app(lambda p: calls.append(p)),
                           headers=headers, monkeypatch=monkeypatch)
    assert response.status_code == 403 and not calls
    assert SECRET not in response.text


@pytest.mark.parametrize('mutation', [
    lambda p: p.update(authorized=False),
    lambda p: p.update(level='deep'),
    lambda p: p['routes'][0].update(safe_use_confirmed=False),
    lambda p: p['routes'][0].update(methods=['POST']),
    lambda p: p['routes'][0].update(cors_get=True),
    lambda p: p['routes'][0].update(parameters=['token']),
    lambda p: p['routes'][0].update(url='http://127.0.0.1/'),
    lambda p: p['routes'][0].update(url='https://example.invalid/?secret=' + SECRET),
    lambda p: p.update(extra=SECRET),
    lambda p: p['routes'].append({**p['routes'][0], 'url':'https://other.invalid/'}),
])
def test_fastapi_invalid_dto_refused_before_consumer(mutation, monkeypatch):
    calls = []
    payload = request_payload()
    mutation(payload)
    response = run_request(support.make_qualification_app(lambda p: calls.append(p)),
                           body=json.dumps(payload).encode(), monkeypatch=monkeypatch)
    assert response.status_code == 422 and not calls
    assert SECRET not in response.text


@pytest.mark.parametrize('body,expected', [(b'{"a":1,"a":2}', 422), (b'\xff', 422),
                                            (b'x' * 16385, 413)])
def test_fastapi_bad_body_refused(body, expected, monkeypatch):
    calls = []
    response = run_request(support.make_qualification_app(lambda p: calls.append(p)), body=body, monkeypatch=monkeypatch)
    assert response.status_code == expected and not calls


def test_fastapi_other_method_and_query_refused(monkeypatch):
    calls = []
    app = support.make_qualification_app(lambda p: calls.append(p))
    assert run_request(app, method='GET', monkeypatch=monkeypatch).status_code == 405
    monkeypatch.undo()
    assert run_request(app, path='/api/fortress/audit?private=1', monkeypatch=monkeypatch).status_code == 422
    assert not calls


def test_fastapi_consumer_exception_is_sanitized(monkeypatch):
    def consumer(_):
        raise RuntimeError(SECRET)
    response = run_request(support.make_qualification_app(consumer), monkeypatch=monkeypatch)
    assert response.status_code == 503 and response.json() == {'error': 'unavailable'}
    assert SECRET not in response.text


def test_disabled_production_route_never_receives_body(monkeypatch):
    from fastapi import FastAPI
    from app.fortress_api import install_fortress_route
    from app.fortress_transport import SafeTransport
    app = FastAPI()
    install_fortress_route(app, ('http://test.local',))
    received = []
    sent = []
    async def run():
        def denied(*args, **kwargs):
            raise AssertionError('DNS or transport forbidden')
        monkeypatch.setattr(socket, 'getaddrinfo', denied)
        monkeypatch.setattr(SafeTransport, '__init__', denied)
        async def receive():
            received.append(True)
            raise AssertionError('body must not be read')
        async def send(message):
            sent.append(message)
        await app({'type':'http', 'asgi':{'version':'3.0'}, 'http_version':'1.1',
                   'method':'POST', 'scheme':'http', 'path':'/api/fortress/audit',
                   'raw_path':b'/api/fortress/audit', 'query_string':b'',
                   'headers':[(k.encode(), v.encode()) for k,v in GOOD_HEADERS],
                   'server':('test.local',80), 'client':('127.0.0.1',1234), 'root_path':''}, receive, send)
    asyncio.run(run())
    assert not received
    assert sent[0]['status'] == 503
    assert json.loads(sent[1]['body']) == {'detail': 'Audit unavailable'}


def test_contract_refuses_missing_consent_before_fake_transport(monkeypatch):
    events = []
    class FakeTransport:
        def __init__(self, scope, **kwargs):
            events.append('constructed')
    monkeypatch.setattr(service, '_acquire_process_mutex', lambda: 1)
    monkeypatch.setattr(service, '_release_process_mutex', lambda _: None)
    consumer = lambda p: service._audit_with_factory(p, factory=FakeTransport)
    payload = request_payload()
    payload['routes'][0]['safe_use_confirmed'] = False
    response = run_request(support.make_qualification_app(consumer),
                           body=json.dumps(payload).encode(), monkeypatch=monkeypatch)
    assert response.status_code == 422 and events == []
    assert SECRET not in response.text


def test_fastapi_service_route_attribution_without_network(monkeypatch):
    events = []
    class FakeTransport:
        def __init__(self, scope, **kwargs):
            self.count = 0
            self.blocked = False
        def observe_headers(self, method, url):
            self.count += 1
            events.append((method, url))
            return {'outcome': 'ok', 'redirected': False,
                    'security_headers': {'hsts': 'absent'} if self.count == 1 else {}}
    monkeypatch.setattr(service, '_acquire_process_mutex', lambda: 1)
    monkeypatch.setattr(service, '_release_process_mutex', lambda _: None)
    consumer = lambda p: service._audit_with_factory(p, factory=FakeTransport)
    payload = request_payload()
    payload['routes'].append({**copy.deepcopy(payload['routes'][0]), 'url':'https://example.invalid/SECOND_PRIVATE'})
    response = run_request(support.make_qualification_app(consumer), body=json.dumps(payload).encode(), monkeypatch=monkeypatch)
    assert response.status_code == 200
    result = response.json()
    assert events == [('GET', payload['routes'][0]['url']), ('GET', payload['routes'][1]['url'])]
    assert result['route_execution'] == [{'route_index': 1, 'state': 'completed'}, {'route_index': 2, 'state': 'completed'}]
    hsts = [f for f in result['findings'] if f['id'] == 'hsts']
    assert [(f['route_index'], f['status']) for f in hsts] == [(1, 'attention'), (2, 'indeterminate')]
    assert result['requests_used'] == 2 and result['complete'] is False
    assert SECRET not in response.text and 'SECOND_PRIVATE' not in response.text and 'example.invalid' not in response.text
