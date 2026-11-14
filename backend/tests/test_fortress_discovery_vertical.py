import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import fortress_mvp_api as api

BASE = {'Origin': 'http://127.0.0.1:5177', 'X-Sentinel-Request': 'sync'}

def client_and_auth():
    app = FastAPI()
    api.install_disabled_route(app, ('http://127.0.0.1:5177', 'http://127.0.0.1:8007'))
    client = TestClient(app, base_url='http://127.0.0.1:8007')
    capability = client.get('/api/fortress/mvp/capability', headers=BASE).json()['capability']
    return client, {**BASE, 'X-Sentinel-Capability': capability}

def test_lab_real_worker_tls_crawl_and_guard():
    client, auth = client_and_auth()
    assert client.post('/api/fortress/discovery/lab', headers=BASE, json={'authorized': True}).status_code == 403
    response = client.post('/api/fortress/discovery/lab', headers=auth, json={'authorized': True})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['schema'] == 'fortress.discovery/1'
    assert result['provenance'] == 'lab'
    assert result['requests'] >= 3
    assert any(page['status'] == 302 for page in result['pages'])
    assert sum(page['status'] == 200 for page in result['pages']) >= 2
    assert 'SECRET_EXAMPLE' not in response.text
    assert all(page['route'].startswith('page-') for page in result['pages'])

def test_live_rejects_private_scope_before_dns(monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: (_ for _ in ()).throw(AssertionError('DNS forbidden')))
    client, auth = client_and_auth()
    response = client.post('/api/fortress/discovery/live', headers=auth, json={'authorized': True, 'target': 'https://127.0.0.1/', 'routes': ['/']})
    assert response.status_code == 422
    assert client.post('/api/fortress/discovery/lab', headers=auth, json={'authorized': True, 'provenance': 'live'}).status_code == 422


def test_real_tls_header_change_changes_analysis(monkeypatch):
    from app import fortress_discovery_lab as lab
    from app.fortress_discovery_contract import project_lab
    monkeypatch.setattr(lab, '_ROUTES', {'/': (200, b'<p>fixture</p>', '/', [('Strict-Transport-Security', 'max-age=0')])})
    before = project_lab(lab.run_lab())
    monkeypatch.setattr(lab, '_ROUTES', {'/': (200, b'<p>fixture</p>', '/', [('Strict-Transport-Security', 'max-age=31536000')])})
    after = project_lab(lab.run_lab())
    assert before['pages'][0]['observations']['hsts'] == 'disabled'
    assert after['pages'][0]['observations']['hsts'] == 'positive'
    assert before['pages'][0]['findings'] != after['pages'][0]['findings']


@pytest.mark.parametrize('outcome', ['visited', 'unreached', 'refused', 'partial'])
def test_depth_target_pending_then_visited_is_complete(monkeypatch, outcome):
    from app import fortress_discovery_lab as lab
    routes = {
        '/': (200, b'<a href="/a">a</a><a href="/d">d</a>'),
        '/a': (200, b'<a href="/b">b</a>'),
        '/d': (200, b'<a href="/pending">p</a>'),
        '/b': (302, b'', '/deep'),
        '/deep': (200, b'<a href="/pending">p</a>'),
        '/pending': (200, b''),
    }
    if outcome == 'unreached':
        routes['/d'] = (200, b'')
    elif outcome == 'refused':
        routes['/pending'] = (403, b'')
    visited = []
    def exchange(path):
        visited.append(path)
        if path == '/pending' and outcome == 'partial':
            raise OSError('synthetic partial response')
        status, body, *location = routes[path]
        header = b'Location: ' + location[0].encode() + b'\r\n' if location else b''
        return status, b'HTTP/1.1 200 OK\r\n' + header + b'\r\n' + body
    monkeypatch.setattr(lab, '_one_exchange', exchange)
    clock = iter(i * .71 for i in range(1000))
    monkeypatch.setattr(lab.time, 'monotonic', lambda: next(clock))
    result = lab.run_lab()
    assert visited == ['/', '/a', '/d', '/b', '/deep'] + ([] if outcome == 'unreached' else ['/pending'])
    assert result['complete'] is (outcome == 'visited')
    assert result['reason'] == {'visited': 'none', 'unreached': 'depth_limit',
                                'refused': 'http_refused', 'partial': 'incomplete'}[outcome]
    assert {'from': lab._id('/deep'), 'to': lab._id('/pending'), 'kind': 'link'} in result['graph']['relations']


@pytest.mark.parametrize('case', ['origin_missing', 'origin_forbidden', 'origin_duplicate',
                                  'host_missing', 'host_forbidden', 'host_duplicate',
                                  'capability_missing', 'capability_invalid', 'capability_duplicate',
                                  'request_missing', 'valid'])
def test_lab_request_guards_and_no_secret_logs(monkeypatch, caplog, case):
    from app import fortress_discovery_worker as worker
    caplog.set_level('DEBUG')
    calls = []
    monkeypatch.setattr(worker, 'run_owned_https_lab', lambda: calls.append(True) or {'result': 'synthetic'})
    client, auth = client_and_auth()
    capability = auth['X-Sentinel-Capability']
    headers = [('origin', auth['Origin']), ('host', '127.0.0.1:8007'),
               ('x-sentinel-request', 'sync'), ('x-sentinel-capability', capability),
               ('content-type', 'application/json')]
    field = {'origin': 'origin', 'host': 'host', 'capability': 'x-sentinel-capability',
             'request': 'x-sentinel-request'}.get(case.split('_')[0])
    if case.endswith('_missing'):
        headers = [(k, v) for k, v in headers if k != field]
    elif case.endswith('_forbidden') or case == 'capability_invalid':
        headers = [(k, 'synthetic-secret-invalid' if k == field else v) for k, v in headers]
    elif case.endswith('_duplicate'):
        headers.append((field, dict(headers)[field]))
    request = client.build_request('POST', '/api/fortress/discovery/lab', headers=headers,
                                   content=b'{"authorized":true}')
    if case == 'host_missing':
        app = client.app
        async def without_host(scope, receive, send):
            if scope['type'] == 'http':
                scope = {**scope, 'headers': [(k, v) for k, v in scope['headers'] if k != b'host']}
            await app(scope, receive, send)
        client = TestClient(without_host, base_url='http://127.0.0.1:8007')
    response = client.send(request)
    assert response.status_code == (200 if case == 'valid' else 403)
    assert calls == ([True] if case == 'valid' else [])
    assert capability not in response.text
    assert capability not in caplog.text
    assert 'synthetic-secret-invalid' not in caplog.text


def test_http_server_capability_to_owned_worker():
    import socket
    import threading
    import time
    import http.client
    import uvicorn
    app = FastAPI()
    api.install_disabled_route(app, ('http://127.0.0.1:5177', 'http://127.0.0.1:8007'))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False))
    thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]})
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline:
            time.sleep(.01)
        assert server.started
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
        try:
            headers = {**BASE, 'Host': '127.0.0.1:8007'}
            conn.request('GET', '/api/fortress/mvp/capability', headers=headers)
            capability = json.loads(conn.getresponse().read())['capability']
            conn.request('POST', '/api/fortress/discovery/lab', body=b'{"authorized":true}', headers={**headers, 'Content-Type': 'application/json', 'X-Sentinel-Capability': capability})
            response = conn.getresponse()
            result = json.loads(response.read())
            assert response.status == 200
            assert result['provenance'] == 'lab'
            assert result['requests'] == 4
        finally:
            conn.close()
    finally:
        server.should_exit = True
        thread.join(10)
        listener.close()
        assert not thread.is_alive()
