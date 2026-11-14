import json

from app import fortress_discovery_worker as worker
from app.fortress_discovery_contract import valid_live
from test_discovery_observed_exchange import invoke


def test_opt_in_projects_visited_and_unvisited_aliases(monkeypatch):
    from app import fortress_discovery_transport as transport
    body = b'<a href="/about/secret123">a</a><a href="/about/secret456">b</a>'
    answer = invoke(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    monkeypatch.setattr(transport, 'capture_observed', lambda *args: (answer, {'phase': 'none', 'requests_sent': 1, 'responses_received': 1}))
    result = worker._discovery_observed_live({'mode': 'observed_dynamic', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {'pages': 1, 'depth': 1, 'requests': 2, 'interval': 1, 'seconds': 10, 'page_bytes': 65536, 'total_bytes': 65536}, 'private_view': True})
    assert result['private_paths'] == [{'id': 'page-1', 'path': '/'}, {'id': 'page-2', 'path': '/about/[masqué]'}, {'id': 'page-3', 'path': '/about/[masqué]'}]
    assert valid_live(result)
    assert 'secret123' not in json.dumps(result)


def test_projection_closed_vocabulary():
    from app.fortress_discovery_private import project, valid_path
    for raw in ('/admin', '/123', '/abc-def', '/%61bout', '/<script>', '/user@example.com', '/SECRET', '/about;secret'):
        assert project(raw) == '/[masqué]'
    assert project('/about/contact?token=SECRET#SECRET') == '/about/contact'
    assert project('/' + '/'.join(['about'] * 50)) == '/' + '/'.join(['about'] * 7 + ['[masqué]'])
    assert not valid_path('/about/<script>')
    assert not valid_path('/about?x=1')


def test_api_opt_in_and_worker_validation(monkeypatch):
    import copy
    from app import fortress_discovery_transport as transport
    from test_fortress_discovery_vertical import client_and_auth
    answer = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    monkeypatch.setattr(transport, 'capture_observed', lambda *args: (answer, {'phase': 'none', 'requests_sent': 1, 'responses_received': 1}))
    def gate(argv, timeout, payload, **kwargs):
        return json.dumps(worker._discovery_observed_live(json.loads(payload))).encode()
    monkeypatch.setattr(worker, 'run_gated', gate)
    client, auth = client_and_auth()
    base = {'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/']}
    for toggle in (None, False, True):
        request = dict(base)
        if toggle is not None:
            request['private_view'] = toggle
        response = client.post('/api/fortress/discovery/live', headers=auth, json=request)
        assert response.status_code == 200
        assert ('private_paths' in response.json()) == (toggle is True)
        assert response.headers['cache-control'] == 'no-store'
    assert client.post('/api/fortress/discovery/live', headers=auth, json={**base, 'private_view': 'true'}).status_code == 422
    value = client.post('/api/fortress/discovery/live', headers=auth, json={**base, 'private_view': True}).json()
    for bad in ([{'id': 'page-1', 'path': '/<script>'}], [{'id': 'page-1', 'path': '/secret'}],
                [{'id': 'page-1', 'path': '/', 'extra': 'SECRET'}], [{'id': 'page-2', 'path': '/'}],
                [{'id': 'page-1', 'path': '/'}] * 1001):
        corrupt = copy.deepcopy(value)
        corrupt['private_paths'] = bad
        assert not valid_live(corrupt)
        monkeypatch.setattr(worker, 'run_gated', lambda *args, c=corrupt, **kwargs: json.dumps(c).encode())
        assert client.post('/api/fortress/discovery/live', headers=auth, json={**base, 'private_view': True}).status_code == 503
    monkeypatch.setattr(worker, 'run_gated', lambda *args, **kwargs: json.dumps(value).encode())
    assert client.post('/api/fortress/discovery/live', headers=auth, json=base).status_code == 503


def test_private_timeout_does_not_retain_scope_in_worker_trace(monkeypatch):
    import traceback
    def timeout(*args, **kwargs):
        raise TimeoutError('SECRET_TIMEOUT')
    monkeypatch.setattr(worker, 'run_gated', timeout)
    try:
        worker.run_observed_live('https://example.invalid/SECRET_ROUTE', ['/SECRET_ROUTE'], private_view=True)
    except RuntimeError as exc:
        trace = traceback.TracebackException.from_exception(exc, capture_locals=True)
        frames = [f for f in trace.stack if 'fortress_discovery_worker.py' in f.filename]
        text = str([(f.name, f.locals) for f in frames]) + str(trace.__cause__) + str(trace.__context__)
        assert 'SECRET_ROUTE' not in text and 'SECRET_TIMEOUT' not in text
    else:
        raise AssertionError('timeout accepted')
