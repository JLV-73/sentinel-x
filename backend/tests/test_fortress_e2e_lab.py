"""ASGI simulation through real service/transport to an owned loopback fixture.

Test-only peer identity is simulated; this is not a deployed HTTP endpoint, TLS,
production readiness, or a frontend integration test.
"""
import asyncio
import json
import socket

import pytest
from fastapi.testclient import TestClient

import app.fortress_service as service
from app.fortress_transport import SafeTransport
from app.main import create_app
from owned_lab_helpers import HOST, SIMULATED_IP, SENTINELS, OwnedHTTP, SimulatedPublicPeerAdapter
from support_fortress_api import DraftFortressAdapter

HEADERS = [(b'host', b'test.local'), (b'origin', b'http://test.local'),
           (b'x-sentinel-request', b'sync'), (b'content-type', b'application/json')]


def payload(*paths):
    return {'level': 'standard', 'authorized': True, 'routes': [
        {'url': f'http://{HOST}{path}', 'safe_use_confirmed': True,
         'methods': ['GET'], 'cors_get': False, 'parameters': []} for path in paths]}


@pytest.fixture
def lab(monkeypatch):
    loop = asyncio.new_event_loop()  # Windows asyncio creates its own socketpair.
    owned = OwnedHTTP()
    adapters, resolutions, transports = [], [], []
    original_connect = socket.socket.connect

    def connect(sock, address):
        assert address == owned.address, 'only the owned fixture may be contacted'
        return original_connect(sock, address)

    def forbidden_dns(*args, **kwargs):
        raise AssertionError('real DNS forbidden')

    def resolver(host, port, *, type):
        assert (host, port, type) == (HOST, 80, socket.SOCK_STREAM)
        resolutions.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (SIMULATED_IP, 80))]

    def socket_factory(family, kind, proto):
        assert (family, kind, proto) == (socket.AF_INET, socket.SOCK_STREAM, 0)
        adapter = SimulatedPublicPeerAdapter(owned)
        adapters.append(adapter)
        return adapter

    budget = [30]
    def factory(scope, **kwargs):
        kwargs['max_requests'] = budget[0]  # trusted test-only cap, never HTTP input
        transport = SafeTransport(scope, resolver=resolver, socket_factory=socket_factory,
                                  timeout=2, deadline=8, **kwargs)
        transports.append(transport)
        return transport

    monkeypatch.setattr(socket.socket, 'connect', connect)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden_dns)
    try:
        yield owned, loop, resolutions, adapters, transports, budget, factory
    finally:
        owned.close()  # asserts listener closed and worker terminated
        loop.close()


def request(lab, data=None, *, body=None, headers=HEADERS):
    if body is None:
        body = json.dumps(data).encode()
    scope = {'type': 'http', 'method': 'POST', 'path': '/api/fortress/audit',
             'query_string': b'', 'headers': list(headers)}
    sent = []
    async def receive():
        return {'type': 'http.request', 'body': body}
    async def send(message):
        sent.append(message)
    lab[1].run_until_complete(DraftFortressAdapter(lambda p: service._audit_with_factory(p, factory=lab[6]))(scope, receive, send))
    assert [m['type'] for m in sent] == ['http.response.start', 'http.response.body']
    return sent[0]['status'], json.loads(sent[1]['body'])


def assert_traffic(lab, paths):
    owned, _, resolutions, adapters, transports, _, _ = lab
    assert len(owned.requests) == len(owned.peers) == len(resolutions) == len(adapters) == len(paths)
    assert all(a.actual_peer == owned.address and a.getpeername() == (SIMULATED_IP, 80) for a in adapters)
    assert all(peer[0] == '127.0.0.1' for peer in owned.peers)
    assert not owned.errors
    for raw, path in zip(owned.requests, paths):
        lines = raw.split(b'\r\n')
        assert lines[0] == f'GET {path} HTTP/1.1'.encode()
        assert lines[1] == f'Host: {HOST}'.encode()
        assert not any(line.lower().startswith((b'authorization:', b'cookie:')) for line in lines)
    return transports


def assert_redacted(result, paths):
    assert set(result) == {'audit_id', 'mode', 'started_at', 'finished_at', 'scope',
                           'requests_used', 'complete', 'findings', 'limitations', 'route_execution'}
    assert type(result['audit_id']) is str and type(result['requests_used']) is int
    assert result['mode'] == 'standard' and result['complete'] is False
    assert result['scope'] == {'origin': '[redacted]', 'paths': ['[redacted route]'] * len(paths)}
    assert type(result['findings']) is list and result['findings']
    for finding in result['findings']:
        assert set(finding) == {'id', 'status', 'severity', 'reason', 'evidence', 'limitations',
                                'preconditions', 'recommendation', 'reference', 'method', 'route', 'date', 'route_index', 'evidence_code'}
        assert finding['status'] in ('attention', 'indeterminate', 'conformant')
        assert type(finding['route_index']) is int and 1 <= finding['route_index'] <= len(paths)
        assert finding['route'] == '[redacted route]' and finding['method'] == 'GET'
    encoded = json.dumps(result)
    for secret in (*SENTINELS, HOST, *paths):
        assert secret not in encoded


def test_asgi_to_owned_fixture_produces_redacted_real_findings(lab):
    paths = ('/private-path-sentinel',)
    status, result = request(lab, payload(*paths))
    assert status == 200
    assert assert_traffic(lab, paths)[0].count == result['requests_used'] == 1
    findings = {f['id']: f for f in result['findings']}
    assert findings['hsts']['status'] == 'indeterminate'
    for name in ('csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy'):
        assert findings[name]['status'] == 'attention'
    assert findings['cookie_attributes']['status'] == 'attention'
    assert_redacted(result, paths)


@pytest.mark.parametrize('mutation', ['no_authorization', 'false_authorization', 'numeric_authorization',
                                      'no_safe_use', 'post', 'cors', 'parameters', 'private', 'five_routes'])
def test_strict_dto_rejected_before_any_transport(lab, mutation):
    data = payload('/secret-path')
    route = data['routes'][0]
    if mutation == 'no_authorization': del data['authorized']
    elif mutation == 'false_authorization': data['authorized'] = False
    elif mutation == 'numeric_authorization': data['authorized'] = 1
    elif mutation == 'no_safe_use': route['safe_use_confirmed'] = False
    elif mutation == 'post': route['methods'] = ['POST']
    elif mutation == 'cors': route['cors_get'] = True
    elif mutation == 'parameters': route['parameters'] = ['x']
    elif mutation == 'private': route['url'] = 'http://127.0.0.1/'
    else: data = payload('/1', '/2', '/3', '/4', '/5')
    status, result = request(lab, data)
    assert status == 422 and result == {'error': 'invalid request'}
    assert assert_traffic(lab, ()) == []


@pytest.mark.parametrize('body', [b'{"authorized":true,"authorized":true}',
                                  b'{"routes":[{"url":"a","url":"b"}]}'])
def test_duplicate_json_keys_rejected_without_traffic(lab, body):
    status, result = request(lab, body=body)
    assert status == 422 and result == {'error': 'invalid request'}
    assert assert_traffic(lab, ()) == []


@pytest.mark.parametrize('key', [b'host', b'origin', b'x-sentinel-request'])
def test_missing_asgi_guard_stops_before_traffic(lab, key):
    status, result = request(lab, payload('/private-path'), headers=[h for h in HEADERS if h[0] != key])
    assert status == 403 and result == {'error': 'forbidden'}
    assert assert_traffic(lab, ()) == []


def test_maximum_four_routes(lab):
    paths = ('/one', '/two', '/three', '/four')
    status, result = request(lab, payload(*paths))
    assert status == 200 and result['requests_used'] == 4
    assert result['route_execution'] == [{'route_index': i, 'state': 'completed'} for i in range(1, 5)]
    assert assert_traffic(lab, paths)[0].count == 4
    assert_redacted(result, paths)


@pytest.mark.parametrize('first', ['/blocked', '/redirect'])
def test_block_or_unapproved_redirect_stops_followup(lab, first):
    paths = (first, '/next')
    status, result = request(lab, payload(*paths))
    assert status == 200 and result['requests_used'] == 1
    transport = assert_traffic(lab, (first,))[0]
    assert result['route_execution'] == [{'route_index': 1, 'state': 'blocked'}, {'route_index': 2, 'state': 'not_started'}]
    assert transport.blocked and transport.count == 1
    assert all(f['status'] == 'indeterminate' for f in result['findings'])
    assert_redacted(result, paths)


def test_trusted_lower_budget_stops_second_request(lab):
    lab[5][0] = 1
    paths = ('/one', '/two')
    status, result = request(lab, payload(*paths))
    assert status == 200 and result['requests_used'] == 1
    transport = assert_traffic(lab, paths[:1])[0]
    assert transport.count == 1 and transport.blocked
    assert_redacted(result, paths)


def test_main_endpoint_remains_disabled(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('production transport or DNS must not run')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(service, '_SafeTransport', forbidden)
    client = TestClient(create_app(), base_url='http://127.0.0.1:8007')
    response = client.post('/api/fortress/audit', headers={'Origin': 'http://127.0.0.1:5177',
                           'X-Sentinel-Request': 'sync'}, json=payload('/private-path'))
    assert response.status_code == 503 and response.json() == {'detail': 'Audit unavailable'}
