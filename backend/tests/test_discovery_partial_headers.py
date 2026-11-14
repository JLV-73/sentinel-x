import copy
import time
import pytest
from app import fortress_discovery_transport as transport, fortress_discovery_policy as policy, fortress_discovery_contract as contract
from test_discovery_http_partial import Stream

P = {'present': ['strict-transport-security', 'content-security-policy', 'set-cookie'], 'completeness': 'headers_validated_body_incomplete'}

def test_partial_read_projects_only_validated_names():
    event = {'phase': 'unknown', 'requests_sent': 1, 'responses_received': 0}
    token = transport._diagnostic.set(event)
    try:
        wire = (b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: SECRET\r\nContent-Security-Policy: SECRET\r\nSet-Cookie: SECRET\r\nContent-Length: 9\r\nContent-Type: text/html\r\n\r\nx')
        with pytest.raises(ValueError):
            transport._read_response(Stream(wire), time.monotonic() + 5, project='observed')
        assert event['_partial_headers'] == P
        assert 'SECRET' not in repr(event)
    finally:
        transport._diagnostic.reset(token)

def test_partial_projection_through_policy_and_contract():
    result = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *a: {'status': 302, 'incomplete': True, 'partial_headers': P}, _live_paths=True)
    result['provenance'] = 'live'
    result['limits'].remove('lab_only')
    result['diagnostic'] = {'phase': 'parse', 'requests_sent': 1, 'responses_received': 1}
    assert result['pages'][0]['partial_headers'] == P
    assert not result['relations'] and contract.valid_live(result)
    for value in ({'present':['authorization'], 'completeness': P['completeness']}, {'present':['set-cookie','set-cookie'], 'completeness':P['completeness']}, {'present':[], 'completeness':P['completeness'], 'value':'SECRET'}):
        bad = copy.deepcopy(result)
        bad['pages'][0]['partial_headers'] = value
        assert not contract.valid_live(bad)
    bad = copy.deepcopy(result)
    bad['pages'][0]['state'] = 'redirected'
    assert not contract.valid_live(bad)
    bad = copy.deepcopy(result)
    bad['relations'] = [{'from': 'page-1', 'to': 'page-2', 'kind': 'redirect'}]
    assert not contract.valid_live(bad)
    bad = copy.deepcopy(result)
    bad['resources'] = [{'page': 'page-1', 'kind': 'script', 'count': 1}]
    assert not contract.valid_live(bad)
    old = copy.deepcopy(result)
    del old['pages'][0]['partial_headers']
    assert contract.valid_live(old)
    empty = copy.deepcopy(result)
    empty['pages'][0]['partial_headers']['present'] = []
    assert contract.valid_live(empty)


def test_api_rejects_worker_projection_outside_allowlist(monkeypatch):
    from app import fortress_discovery_worker as worker
    from test_fortress_discovery_vertical import client_and_auth
    value = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *a: {'status': 302, 'incomplete': True, 'partial_headers': P}, _live_paths=True)
    value['provenance'] = 'live'
    value['limits'].remove('lab_only')
    value['diagnostic'] = {'phase': 'parse', 'requests_sent': 1, 'responses_received': 1}
    value = copy.deepcopy(value)
    value['pages'][0]['partial_headers']['present'].append('authorization')
    monkeypatch.setattr(worker, 'run_observed_live', lambda *args: value)
    client, auth = client_and_auth()
    response = client.post('/api/fortress/discovery/live', headers=auth,
                           json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/']})
    assert response.status_code == 503


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows supervised worker')
@pytest.mark.parametrize('status', [200, 302])
@pytest.mark.parametrize('framing', ['length', 'chunked-gzip', 'malformed', 'over-budget'])
def test_loopback_tls_worker_asgi(monkeypatch, status, framing):
    import gzip, socket, ssl, sys, threading
    from pathlib import Path
    from app import fortress_discovery_worker as worker
    from app.fortress_job import run_gated
    from test_fortress_discovery_vertical import client_and_auth
    import test_discovery_gated_fixture as fixture
    certs = Path(worker.__file__).with_name('fortress_mvp_tls')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certs / 'server.pem'), str(certs / 'server-key.pem'))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(2)
    listener.settimeout(10)
    port = listener.getsockname()[1]
    calls, errors = [], []
    def serve():
        try:
            conn, _ = listener.accept()
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(5)
                request = b''
                while b'\r\n\r\n' not in request:
                    request += tls.recv(4096)
                calls.append(request)
                headers = (b'Strict-Transport-Security: SECRET_HSTS\r\nContent-Security-Policy: SECRET_CSP\r\n'
                           b'Set-Cookie: SECRET_COOKIE\r\nLocation: /next\r\nContent-Type: text/html\r\n')
                if framing == 'malformed':
                    headers += b'Bad Header: SECRET_BAD\r\n'
                if framing == 'chunked-gzip':
                    encoded = gzip.compress(b'<a href="/next">SECRET_BODY</a>')
                    body = b'Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n' + f'{len(encoded):x}'.encode() + b'\r\n' + encoded[:-3]
                elif framing == 'over-budget':
                    body = b'Content-Length: 4097\r\n\r\nSECRET_BODY'
                else:
                    body = b'Content-Length: 100\r\n\r\n<a href="/next">SECRET_BODY</a>'
                tls.sendall(b'HTTP/1.1 ' + str(status).encode() + b' Test\r\n' + headers + body)
                try:
                    tls.unwrap().close()
                except (ssl.SSLError, OSError):
                    pass
        except Exception as exc:
            errors.append(repr(exc))
    thread = threading.Thread(target=serve)
    thread.start()
    backend = str(Path(worker.__file__).resolve().parents[1])
    def gate(argv, timeout, payload):
        return run_gated([sys.executable, '-I', '-B', str(Path(fixture.__file__).resolve()),
                          'fixture-child', backend, 'live_tls', str(port), ''], timeout, payload)
    monkeypatch.setattr(worker, 'run_gated', gate)
    client, auth = client_and_auth()
    try:
        response = client.post('/api/fortress/discovery/live', headers=auth, json={
            'authorized': True, 'target': f'https://standard-lab.invalid:{port}/', 'routes': ['/'],
            'limits': {'pages': 2, 'requests': 2, 'depth': 1, 'interval': 1,
                       'page_bytes': 4096, 'total_bytes': 4096, 'seconds': 10}})
    finally:
        thread.join(12)
        listener.close()
    assert not thread.is_alive() and not errors, (errors, response.status_code, response.text)
    assert response.status_code == 200, response.text
    result = response.json()
    assert len(calls) == result['requests'] == 1
    if framing == 'over-budget':
        assert result['diagnostic'] == {'phase': 'budget', 'requests_sent': 1, 'responses_received': 1}
    assert not result['relations'] and 'SECRET_' not in response.text
    if framing == 'malformed':
        assert result['pages'] == []
    else:
        assert result['pages'][0]['status'] == status
        assert result['pages'][0]['state'] == 'incomplete'
        assert result['pages'][0]['tls']['certificate_verified'] is True
        assert result['pages'][0]['tls']['hostname_verified'] is True
        assert result['pages'][0]['partial_headers'] == P
        assert result['pages'][0]['observations'] is None and result['pages'][0]['findings'] == []
