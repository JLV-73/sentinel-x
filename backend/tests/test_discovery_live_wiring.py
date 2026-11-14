import json
import pytest
from app import fortress_discovery_worker as worker
from app import fortress_discovery_transport as transport
from test_fortress_discovery_vertical import client_and_auth
from test_discovery_observed_exchange import invoke


def test_api_to_live_worker_with_in_process_exchange(monkeypatch):
    response = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    calls = []
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: calls.append(args) or response)
    def gated(argv, timeout, payload):
        data = json.loads(payload)
        assert data['mode'] == 'observed_live'
        return json.dumps(worker._discovery_observed_live(data)).encode()
    monkeypatch.setattr(worker, 'run_gated', gated)
    client, auth = client_and_auth()
    result = client.post('/api/fortress/discovery/live', headers=auth,
                         json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/']})
    assert result.status_code == 200, result.text
    assert result.json()['provenance'] == 'live'
    assert result.json()['pages'][0]['status'] == 200
    assert calls[0][0] == 'https://example.invalid/'
    assert 'example.invalid' not in result.text


@pytest.mark.parametrize('status', [201, 202, 205, 206])
def test_api_preserves_unsupported_success_as_incomplete(monkeypatch, status):
    body = b'<a href="/next">x</a>' if status != 205 else b''
    extra = f'Content-Range: bytes 0-{len(body)-1}/{len(body)+10}\r\n' if status == 206 else ''
    raw = (f'HTTP/1.1 {status} Result\r\nContent-Length: {len(body)}\r\n'
           f'{extra}Content-Type: text/html\r\n\r\n').encode() + body
    response = invoke(raw)
    assert response['status'] == status
    assert response['links'] == []
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: response)
    monkeypatch.setattr(worker, 'run_gated', lambda argv, timeout, payload:
                        json.dumps(worker._discovery_observed_live(json.loads(payload))).encode())
    client, auth = client_and_auth()
    result = client.post('/api/fortress/discovery/live', headers=auth,
                         json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/', '/next']})
    assert result.status_code == 200, result.text
    value = result.json()
    assert not value['complete'] and value['reason'] == 'unknown'
    assert value['requests'] == 1 and value['bytes'] == len(body)
    assert value['relations'] == []
    page = value['pages'][0]
    assert (page['status'], page['state'], page['observations'], page['findings']) == (status, 'incomplete', None, [])
    from app.fortress_discovery_contract import valid_live
    assert valid_live(value)
    from copy import deepcopy
    for change in ('refused', 'complete', 'observations', 'findings'):
        bad = deepcopy(value)
        if change == 'refused': bad['reason'] = 'http_refused'
        elif change == 'complete': bad.update(complete=True, reason='none')
        elif change == 'observations': bad['pages'][0]['observations'] = {'http_status': status}
        else: bad['pages'][0]['findings'] = [{'evidence': 'absent'}]
        assert not valid_live(bad)


@pytest.mark.parametrize('status', [201, 202, 205, 206, 304])
def test_exclusion_before_unsupported_success_preserves_unknown(monkeypatch, status):
    body = b'<a href="/outside?token=SECRET">x</a><a href="/next">next</a>'
    ok = invoke(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n' + body)
    unsupported = invoke(f'HTTP/1.1 {status} Result\r\nContent-Length: 0\r\n\r\n'.encode())
    calls = []
    def exchange(url, *args):
        calls.append(url)
        return ok if url.endswith('/') else unsupported
    monkeypatch.setattr(transport, 'exchange_observed', exchange)
    monkeypatch.setattr(worker, 'run_gated', lambda argv, timeout, payload:
                        json.dumps(worker._discovery_observed_live(json.loads(payload))).encode())
    client, auth = client_and_auth()
    response = client.post('/api/fortress/discovery/live', headers=auth,
                           json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/', '/next']})
    assert response.status_code == 200, response.text
    value = response.json()
    assert not value['complete'] and value['reason'] == 'unknown'
    assert value['requests'] == 2 and len(calls) == 2
    assert value['limits'][0] == 'excluded_links:1'
    assert [(p['status'], p['state']) for p in value['pages']] == [(200, 'complete'), (status, 'incomplete')]
    assert value['pages'][1]['observations'] is None and value['pages'][1]['findings'] == []
    assert value['relations'] == [{'from': 'page-1', 'to': 'page-2', 'kind': 'link'}]
    assert 'SECRET' not in response.text
    from app.fortress_discovery_contract import valid_live
    assert valid_live(value)


@pytest.mark.parametrize('raw,reason', [
    (b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n', 'http_refused'),
    (b'HTTP/1.1 302 Found\r\nLocation: /outside\r\nContent-Length: 0\r\n\r\n', 'redirect_blocked'),
])
def test_exclusion_does_not_override_other_stop_reasons(monkeypatch, raw, reason):
    body = b'<a href="/outside?x=secret">x</a><a href="/next">next</a>'
    ok = invoke(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n' + body)
    stopped = invoke(raw)
    monkeypatch.setattr(transport, 'exchange_observed',
                        lambda url, *args: ok if url.endswith('/') else stopped)
    monkeypatch.setattr(worker, 'run_gated', lambda argv, timeout, payload:
                        json.dumps(worker._discovery_observed_live(json.loads(payload))).encode())
    client, auth = client_and_auth()
    response = client.post('/api/fortress/discovery/live', headers=auth,
                           json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/', '/next']})
    assert response.status_code == 200, response.text
    value = response.json()
    assert not value['complete'] and value['reason'] == reason
    assert value['requests'] == 2
    assert value['limits'][0] == ('excluded_links:2' if reason == 'redirect_blocked' else 'excluded_links:1')


@pytest.mark.parametrize('mixed', [False, True])
def test_api_accepts_complete_live_204_no_content(monkeypatch, mixed):
    no_content = invoke(b'HTTP/1.1 204 No Content\r\nX-Content-Type-Options: nosniff\r\n\r\n')
    body = b'<a href="/next">next</a>'
    ok = invoke(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n' + body)
    calls = []
    def exchange(url, *args):
        calls.append(url)
        return ok if mixed and url.endswith('/') else no_content
    monkeypatch.setattr(transport, 'exchange_observed', exchange)
    def gated(argv, timeout, payload):
        return json.dumps(worker._discovery_observed_live(json.loads(payload))).encode()
    monkeypatch.setattr(worker, 'run_gated', gated)
    client, auth = client_and_auth()
    routes = ['/', '/next'] if mixed else ['/']
    result = client.post('/api/fortress/discovery/live', headers=auth,
                         json={'authorized': True, 'target': 'https://example.invalid/', 'routes': routes})
    assert result.status_code == 200, result.text
    value = result.json()
    assert value['complete'] and value['reason'] == 'none'
    assert [p['status'] for p in value['pages']] == ([200, 204] if mixed else [204])
    assert all(p['state'] == 'complete' for p in value['pages'])
    assert value['pages'][-1]['observations']['http_status'] == 204
    assert value['requests'] == len(routes) == len(calls)
    assert value['bytes'] == (len(body) if mixed else 0)
    assert all(p['state'] != 'http_error' for p in value['pages'])


@pytest.mark.parametrize('target,routes', [
    ('https://127.0.0.1/', ['/']), ('http://example.invalid/', ['/']),
    ('https://example.invalid/?token=secret', ['/']),
    ('https://example.invalid/', ['/logout']), ('https://example.invalid/', ['/other']),
    ('https://example.invalid/', ['/', '/bundle.js']), ('https://example.invalid/', ['/', '/style.css']),
])
def test_invalid_scope_never_reaches_worker(monkeypatch, target, routes):
    monkeypatch.setattr(worker, 'run_gated', lambda *args: pytest.fail('worker reached'))
    client, auth = client_and_auth()
    result = client.post('/api/fortress/discovery/live', headers=auth,
                         json={'authorized': True, 'target': target, 'routes': routes})
    assert result.status_code == 422


def test_live_requires_consent_capability_and_rejects_client_provenance(monkeypatch):
    monkeypatch.setattr(worker, 'run_gated', lambda *args: pytest.fail('worker reached'))
    client, auth = client_and_auth()
    payload = {'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/']}
    assert client.post('/api/fortress/discovery/live', json=payload).status_code == 403
    assert client.post('/api/fortress/discovery/live', headers=auth, json={**payload, 'authorized': False}).status_code == 422
    assert client.post('/api/fortress/discovery/live', headers=auth, json={**payload, 'provenance': 'live'}).status_code == 422


def test_worker_rejects_lab_provenance_and_duplicate_keys(monkeypatch):
    for raw in (b'{"schema":"fortress.discovery/1","provenance":"live","provenance":"lab"}',
                b'{"schema":"fortress.discovery/1","provenance":"lab"}'):
        monkeypatch.setattr(worker, 'run_gated', lambda *args: raw)
        with pytest.raises(RuntimeError):
            worker.run_observed_live('https://example.invalid/', ['/'])


def test_scope_exclusion_preserves_reason_and_no_secret(monkeypatch):
    answer = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    answer['links'] = ['/outside?token=SECRET']
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: answer)
    result = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {}})
    assert result['reason'] == 'scope_blocked'
    assert 'excluded_links:1' in result['limits']
    assert 'SECRET' not in repr(result)


def test_unsafe_link_is_counted_without_fetching_or_leaking(monkeypatch):
    body = b'<a href="/private?token=SECRET">x</a>'
    raw = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
           + str(len(body)).encode() + b'\r\n\r\n' + body)
    answer = invoke(raw)
    assert answer['links'] == [None]
    calls = []
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: calls.append(args) or answer)
    result = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {}})
    assert len(calls) == 1
    assert result['reason'] == 'scope_blocked'
    assert 'SECRET' not in repr(result)


def test_non_html_body_is_not_read_after_headers():
    from unittest.mock import patch
    from test_discovery_transport import FakeSocket, FakeContext, row
    sock = FakeSocket(b'', '8.8.8.8')
    with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]), \
         patch.object(transport.socket, 'socket', return_value=sock), \
         patch.object(transport.ssl, 'SSLContext', return_value=FakeContext()), \
         patch.object(sock, 'recv', side_effect=[b'HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: 100\r\n\r\n', AssertionError('CSS body read')]) as receive:
        assert transport.exchange_observed('https://example.invalid/', 1000, 8) == {}
        assert receive.call_count == 1


def test_complete_live_requires_an_observed_page():
    from app.fortress_discovery_contract import valid_live
    value = {'schema': 'fortress.discovery/1', 'provenance': 'live', 'complete': True,
             'reason': 'none', 'requests': 0, 'bytes': 0, 'pages': [], 'relations': [],
             'resources': [], 'limits': ['excluded_links:0', 'no_external_requests',
               'no_authentication', 'headers_only_analysis', 'not_a_vulnerability_or_compliance_conclusion']}
    assert not valid_live(value)
    value['complete'], value['reason'] = False, 'duration_limit'
    assert valid_live(value)
    value['bytes'] = 1
    assert not valid_live(value)


def test_live_complete_rejects_contradictory_worker_results(monkeypatch):
    from copy import deepcopy
    from app.fortress_discovery_contract import valid_live
    answer = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: answer)
    value = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {}})
    assert valid_live(value)
    for mutate in ('excluded', 'unresolved', 'requests'):
        bad = deepcopy(value)
        if mutate == 'excluded':
            bad['limits'][0] = 'excluded_links:1'
        elif mutate == 'unresolved':
            bad['relations'] = [{'from': 'page-1', 'to': 'page-2', 'kind': 'link'}]
        else:
            bad['requests'] += 1
        assert not valid_live(bad), mutate


def test_oversized_scope_is_rejected_before_launch(monkeypatch):
    monkeypatch.setattr(worker, 'run_gated', lambda *args: pytest.fail('worker launched'))
    client, auth = client_and_auth()
    routes = ['/'] + ['/r' + str(i) + 'x' * 220 for i in range(10)]
    result = client.post('/api/fortress/discovery/live', headers=auth,
                         json={'authorized': True, 'target': 'https://example.invalid/', 'routes': routes})
    assert result.status_code == 422


def test_scope_payload_exact_boundary():
    from app.fortress_discovery_policy import Limits
    target = 'https://example.invalid/'
    routes = ['/'] + ['/r' + str(i) + 'x' * 220 for i in range(8)]
    base = len(worker._live_payload(target, routes + ['/z'], Limits(seconds=110)))
    routes.append('/z' + 'x' * (2048 - base))
    assert len(worker._live_payload(target, routes, Limits(seconds=110))) == 2048
    worker.validate_live_scope(target, routes)
    routes[-1] += 'x'
    assert len(worker._live_payload(target, routes, Limits(seconds=110))) == 2049
    with pytest.raises(ValueError):
        worker.validate_live_scope(target, routes)


def test_discovery_capability_guarded_and_closed():
    import os
    client, auth = client_and_auth()
    url = '/api/fortress/discovery/capability'
    assert client.get(url).status_code == 403
    assert client.get(url, headers={**auth, 'Origin': 'http://evil.invalid'}).status_code == 403
    assert client.get(url + '?x=1', headers=auth).status_code == 422
    result = client.get(url, headers=auth)
    assert result.status_code == 200
    assert result.json() == {'schema': 'fortress.discovery-capability/1', 'lab': os.name == 'nt', 'live': os.name == 'nt'}
    assert result.headers['cache-control'] == 'no-store'
    assert auth['X-Sentinel-Capability'] not in result.text


def test_capability_unsupported_platform_and_duplicate_guards(monkeypatch):
    from types import SimpleNamespace
    from app import fortress_mvp_api as api
    client, auth = client_and_auth()
    url = '/api/fortress/discovery/capability'
    assert client.get(url, headers={**auth, 'Host': 'evil.invalid'}).status_code == 403
    assert client.get(url, headers=[('Host', '127.0.0.1:8007'), ('Origin', 'http://127.0.0.1:5177'),
                                    ('Origin', 'http://127.0.0.1:5177'), ('X-Sentinel-Request', 'sync')]).status_code == 403
    monkeypatch.setattr(api, 'os', SimpleNamespace(name='posix'))
    assert client.get(url, headers=auth).json() == {'schema': 'fortress.discovery-capability/1', 'lab': False, 'live': False}


def test_rate_limit_wait_tolerates_early_sleep():
    from app.fortress_discovery_policy import discover, Limits
    now = [0.0]
    sleeps = []
    def sleep(delay):
        sleeps.append(delay)
        now[0] += delay / 2 if len(sleeps) == 1 else delay
    def exchange(url, cap, timeout):
        return {'status': 200, 'decoded_bytes': 0, 'links': ['/next'] if url.endswith('/') else [], 'location': None}
    result = discover('https://example.invalid', ['/', '/next'], '/', exchange,
                      limits=Limits(seconds=5), clock=lambda: now[0], sleep=sleep)
    assert result['complete'] and result['requests'] == 2
    assert len(sleeps) == 2


def test_parent_reject_drops_untrusted_result_locals(monkeypatch):
    import traceback
    monkeypatch.setattr(worker, 'run_gated', lambda *args: b'{"secret":"SECRET_INVALID_RESULT"}')
    with pytest.raises(RuntimeError) as error:
        worker.run_observed_live('https://example.invalid/', ['/'])
    captured = traceback.TracebackException.from_exception(error.value, capture_locals=True)
    assert 'SECRET_INVALID_RESULT' not in ''.join(captured.format())
