from app import fortress_discovery_policy as policy
from app import fortress_discovery_worker as worker
import pytest
from urllib.parse import urlsplit


def test_dynamic_live_contract_must_be_exact():
    limits = {'pages': 5, 'requests': 10, 'depth': 1, 'interval': 1, 'page_bytes': 524288, 'total_bytes': 3145728, 'seconds': 120}
    worker.validate_dynamic_scope('https://example.invalid/', ['/'], limits)
    for key in limits:
        bad = dict(limits)
        bad[key] = True
        with pytest.raises(ValueError):
            worker.validate_dynamic_scope('https://example.invalid/', ['/'], bad)
    with pytest.raises(ValueError):
        worker.validate_dynamic_scope('https://example.invalid/other', ['/'], limits)


def test_dynamic_bfs_only_safe_discovered_routes():
    calls = []
    def exchange(url, cap, timeout):
        calls.append(url)
        links = ['/about', '/file.js', '/login', '/admin', '/api/x', '/q?x=1', 'https://outside.invalid/'] if url.endswith('/') else ['/deep']
        return {'status': 200, 'decoded_bytes': 5, 'links': links, 'location': None}
    now = [0.0]
    def sleep(delay):
        now[0] += delay
    limits = policy.Limits(pages=5, requests=10, depth=1, interval=1, page_bytes=524288, total_bytes=3145728, seconds=120)
    result = policy.discover('https://example.invalid', ['/'], '/', exchange, limits=limits, clock=lambda: now[0], sleep=sleep, dynamic=True)
    assert calls == ['https://example.invalid/', 'https://example.invalid/about']
    assert result['reason'] == 'scope_blocked'


def test_dynamic_bfs_owned_https_fixture(monkeypatch):
    from app import fortress_discovery_lab as lab
    from app import fortress_discovery_transport as transport
    monkeypatch.setattr(lab, '_ROUTES', {
        '/': (200, b'<a href="/a">A</a><a href="/b">B</a><a href="/admin">bad</a><a href="/x.js">script</a>'),
        '/a': (200, b'<a href="/deep">deep</a>'),
        '/b': (200, b'hello'),
    })
    calls = []
    def exchange(url, cap, timeout):
        path = urlsplit(url).path
        calls.append(path)
        status, response = lab._one_exchange(path)
        body = response.split(b'\r\n\r\n', 1)[1]
        assert len(body) <= cap
        parser = transport._Links(url, report_excluded=True)
        parser.feed(body.decode('utf-8'))
        return {'status': status, 'decoded_bytes': len(body), 'links': parser.links, 'location': None}
    now = [0.0]
    def sleep(delay): now[0] += delay
    limits = policy.Limits(pages=5, requests=10, depth=1, interval=1, page_bytes=524288, total_bytes=3145728, seconds=120)
    result = policy.discover('https://standard-lab.invalid', ['/'], '/', exchange, limits=limits, clock=lambda: now[0], sleep=sleep, dynamic=True)
    assert calls == ['/', '/a', '/b']
    assert result['pages'] == 3
    assert now[0] >= 2


def test_dynamic_limits_allow_smaller_and_reject_overrides():
    values = {'pages': 2, 'requests': 3, 'depth': 0, 'interval': 1.5,
              'page_bytes': 100, 'total_bytes': 200, 'seconds': 8}
    assert policy.dynamic_limits(values).pages == 2
    for key, bad in [('pages', 6), ('requests', 11), ('depth', 2), ('interval', .99),
                     ('page_bytes', 524289), ('total_bytes', 3145729), ('seconds', 121),
                     ('seconds', 0), ('seconds', float('nan')), ('pages', True)]:
        with pytest.raises(ValueError):
            policy.dynamic_limits({**values, key: bad})
    with pytest.raises(ValueError):
        policy.dynamic_limits({**values, 'unexpected': 1})


def test_api_rejects_bad_dynamic_scope_before_worker(monkeypatch):
    from test_fortress_discovery_vertical import client_and_auth
    monkeypatch.setattr(worker, 'run_gated', lambda *args: pytest.fail('worker reached'))
    client, auth = client_and_auth()
    limits = {'pages': 5, 'requests': 10, 'depth': 1, 'interval': 1,
              'page_bytes': 524288, 'total_bytes': 3145728, 'seconds': 120}
    payload = {'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': limits}
    for bad in ({**payload, 'extra': 1}, {**payload, 'limits': {**limits, 'pages': 6}},
                {**payload, 'limits': {**limits, 'interval': .9}},
                {**payload, 'target': 'https://127.0.0.1/'}, {**payload, 'routes': ['/', '/other']}):
        result = client.post('/api/fortress/discovery/live', headers=auth, json=bad)
        assert result.status_code == 422


def test_dynamic_policy_budget_limits():
    calls = []
    def exchange(url, cap, timeout):
        calls.append((url, cap))
        return {'status': 200, 'decoded_bytes': 4, 'links': ['/next'], 'location': None}
    values = {'pages': 1, 'requests': 2, 'depth': 1, 'interval': 1,
              'page_bytes': 10, 'total_bytes': 5, 'seconds': 10}
    result = policy.discover('https://example.invalid', ['/'], '/', exchange,
                             limits=policy.dynamic_limits(values), dynamic=True)
    assert result['reason'] == 'page_limit' and result['bytes'] == 4
    assert calls == [('https://example.invalid/', 5)]


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows job fixture')
@pytest.mark.parametrize('redirect', [False, True])
@pytest.mark.parametrize('private_view', [False, True])
def test_api_dynamic_real_supervised_tls(monkeypatch, redirect, private_view):
    import json, socket, ssl, sys, threading, time
    from pathlib import Path
    from test_fortress_discovery_vertical import client_and_auth
    from app.fortress_job import run_gated
    import test_discovery_gated_fixture as fixture

    certs = Path(worker.__file__).with_name('fortress_mvp_tls')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certs / 'server.pem'), str(certs / 'server-key.pem'))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(4)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    calls, errors = [], []
    bodies = [b'<a href="/next">next</a><a href="/login">blocked</a><a href="https://third.invalid/">outside</a><script src="/asset.js"></script>', b'done']
    def serve():
        try:
            for i in range(1 if redirect else 2):
                conn, _ = listener.accept()
                with conn, context.wrap_socket(conn, server_side=True) as tls:
                    req = b''
                    while b'\r\n\r\n' not in req:
                        req += tls.recv(4096)
                    calls.append((time.monotonic(), req))
                    if redirect:
                        reply = b'HTTP/1.1 302 Found\r\nLocation: https://third.invalid/\r\nContent-Length: 0\r\n\r\n'
                    else:
                        body = bodies[i]
                        reply = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
                    tls.sendall(reply)
                    try:
                        tls.unwrap().close()
                    except (ssl.SSLError, OSError):
                        pass
        except Exception as exc:
            errors.append(repr(exc))
    thread = threading.Thread(target=serve)
    thread.start()
    backend = str(Path(worker.__file__).resolve().parents[1])
    def gate(argv, timeout, payload, **kwargs):
        args = [sys.executable, '-I', '-B', str(Path(fixture.__file__).resolve()), 'fixture-child', backend, 'live_tls', str(port), '']
        return run_gated(args, timeout, payload, **kwargs)
    monkeypatch.setattr(worker, 'run_gated', gate)
    client, auth = client_and_auth()
    limits = {'pages': 3, 'requests': 4, 'depth': 1, 'interval': 1,
              'page_bytes': 4096, 'total_bytes': 8192, 'seconds': 10}
    try:
        response = client.post('/api/fortress/discovery/live', headers=auth, json={
            'authorized': True, 'target': f'https://standard-lab.invalid:{port}/', 'routes': ['/'], 'limits': limits,
            'private_view': private_view})
    finally:
        thread.join(8)
        listener.close()
    assert not thread.is_alive() and not errors
    assert response.status_code == 200, response.text
    result = response.json()
    assert ('private_paths' in result) == private_view
    if private_view:
        assert result['private_paths'] == ([{'id': 'page-1', 'path': '/'}] if redirect else
                                           [{'id': 'page-1', 'path': '/'}, {'id': 'page-2', 'path': '/[masqué]'}])
    assert result['pages'][0]['tls']['certificate_verified'] is True
    assert result['pages'][0]['tls']['hostname_verified'] is True
    assert all(req.startswith(b'GET ') for _, req in calls)
    if redirect:
        assert len(calls) == 1 and result['reason'] == 'redirect_blocked'
    else:
        assert [req.split(b' ')[1] for _, req in calls] == [b'/', b'/next']
        assert calls[1][0] - calls[0][0] >= .99
        assert result['requests'] == 2 and result['bytes'] == sum(map(len, bodies))
        assert len(result['pages']) == 2 and result['reason'] == 'scope_blocked'
        assert '/next' not in response.text
