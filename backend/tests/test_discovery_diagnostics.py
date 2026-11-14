import socket
import ssl
import json
from copy import deepcopy
import pytest
from app import fortress_discovery_worker as worker
from app import fortress_discovery_transport as transport
from app.fortress_discovery_contract import valid_live
from test_discovery_transport import FakeSocket, FakeContext, row, IP


def test_dns_failure_is_attested_without_leaking(monkeypatch):
    def fail(*args):
        raise socket.gaierror('SECRET DNS')
    monkeypatch.setattr(transport.socket, 'getaddrinfo', fail)
    result = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {}})
    assert result['requests'] == 1
    assert result['diagnostic'] == {'phase': 'dns', 'requests_sent': 0, 'responses_received': 0}
    assert 'SECRET' not in repr(result)


@pytest.mark.parametrize('kind,phase,sent,received', [
    ('scope', 'scope', 0, 0), ('connect', 'connect', 0, 0),
    ('tls_ca', 'tls', 0, 0), ('tls_name', 'tls', 0, 0),
    ('send', 'connect', None, 0), ('timeout', 'timeout', 1, 0),
    ('truncated', 'parse', 1, 0), ('framing', 'parse', 1, 1),
    ('budget', 'budget', 1, 1), ('success', 'none', 1, 1),
])
def test_transport_events(monkeypatch, kind, phase, sent, received):
    raw = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
    if kind == 'truncated': raw = b'HTTP/1.1 200 OK\r\nX: SECRET'
    if kind == 'framing': raw = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx'
    if kind == 'budget': raw = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n'
    sock = FakeSocket(raw, IP)
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *a: [row('127.0.0.1' if kind == 'scope' else IP)])
    monkeypatch.setattr(transport.socket, 'socket', lambda *a: sock)
    monkeypatch.setattr(transport.ssl, 'SSLContext', lambda *a: FakeContext())
    def fail(error):
        def invoke(*args, **kwargs): raise error
        return invoke
    if kind == 'connect': monkeypatch.setattr(sock, 'connect', fail(ConnectionRefusedError('SECRET')))
    if kind in ('tls_ca', 'tls_name'): monkeypatch.setattr(sock, 'do_handshake', fail(ssl.SSLCertVerificationError('SECRET')))
    if kind == 'send': monkeypatch.setattr(sock, 'sendall', fail(OSError('SECRET partial')))
    if kind == 'timeout': monkeypatch.setattr(sock, 'recv', fail(TimeoutError('SECRET')))
    result, event = transport.capture_observed('https://example.invalid/', 10, 8)
    assert event == {'phase': phase, 'requests_sent': sent, 'responses_received': received}
    assert 'SECRET' not in repr((result, event))


def test_diagnostic_contract_rejects_invalid_and_accepts_historical(monkeypatch):
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *a: (_ for _ in ()).throw(socket.gaierror('SECRET')))
    value = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {}})
    assert valid_live(value)
    old = deepcopy(value); del old['diagnostic']
    assert valid_live(old)
    for change in ({'phase': 'SECRET'}, {'requests_sent': True}, {'requests_sent': -1},
                   {'requests_sent': 2}, {'responses_received': 1}, {'phase': 'none'}, {'extra': 'SECRET'}):
        bad = deepcopy(value); bad['diagnostic'].update(change)
        assert not valid_live(bad)


def test_asgi_dns_diagnostic_reaches_api_without_secret(monkeypatch):
    from test_fortress_discovery_vertical import client_and_auth
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *a: (_ for _ in ()).throw(socket.gaierror('SECRET')))
    monkeypatch.setattr(worker, 'run_gated', lambda argv, timeout, payload, **kwargs: json.dumps(worker._discovery_observed_live(json.loads(payload))).encode())
    client, auth = client_and_auth()
    response = client.post('/api/fortress/discovery/live', headers=auth,
                           json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/']})
    assert response.status_code == 200
    assert response.json()['diagnostic'] == {'phase': 'dns', 'requests_sent': 0, 'responses_received': 0}
    assert 'SECRET' not in response.text


def test_partial_second_page_preserves_attested_totals(monkeypatch):
    body = b'<a href="/next">next</a>'
    raw = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
           + str(len(body)).encode() + b'\r\n\r\n' + body)
    sockets = iter([FakeSocket(raw, IP), FakeSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx', IP)])
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *a: [row()])
    monkeypatch.setattr(transport.socket, 'socket', lambda *a: next(sockets))
    monkeypatch.setattr(transport.ssl, 'SSLContext', lambda *a: FakeContext())
    value = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/', '/next'], 'limits': {}})
    assert value['requests'] == 2 and len(value['pages']) == 2
    assert value['pages'][1]['state'] == 'incomplete'
    assert value['pages'][1]['status'] == 200
    assert value['pages'][1]['observations'] is None and value['pages'][1]['findings'] == []
    assert value['diagnostic'] == {'phase': 'parse', 'requests_sent': 2, 'responses_received': 2}
    assert valid_live(value)


def test_partial_response_through_worker_and_asgi(monkeypatch):
    from test_fortress_discovery_vertical import client_and_auth
    from unittest.mock import patch
    sock = FakeSocket(b'HTTP/1.1 302 Found\r\nLocation: /secret\r\nSet-Cookie: secret=value\r\nContent-Length: 8\r\n\r\nx', IP)
    def gate(argv, timeout, payload, **kwargs):
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]), \
             patch.object(transport.socket, 'socket', return_value=sock), \
             patch.object(transport.ssl, 'SSLContext', return_value=FakeContext()):
            return json.dumps(worker._discovery_observed_live(json.loads(payload))).encode()
    monkeypatch.setattr(worker, 'run_gated', gate)
    client, auth = client_and_auth()
    response = client.post('/api/fortress/discovery/live', headers=auth,
                           json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/']})
    assert response.status_code == 200, response.text
    value = response.json()
    assert valid_live(value)
    assert value['diagnostic'] == {'phase': 'parse', 'requests_sent': 1, 'responses_received': 1}
    assert value['pages'][0]['status'] == 302 and value['pages'][0]['state'] == 'incomplete'
    assert value['pages'][0]['observations'] is None and value['pages'][0]['findings'] == []
    assert value['relations'] == [] and 'secret' not in response.text.lower()


def test_timeout_after_header_keeps_response_attestation(monkeypatch):
    sock = FakeSocket(b'', IP)
    replies = iter([b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n', TimeoutError('SECRET')])
    def recv(n):
        value = next(replies)
        if isinstance(value, Exception): raise value
        return value
    monkeypatch.setattr(sock, 'recv', recv)
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *a: [row()])
    monkeypatch.setattr(transport.socket, 'socket', lambda *a: sock)
    monkeypatch.setattr(transport.ssl, 'SSLContext', lambda *a: FakeContext())
    _, event = transport.capture_observed('https://example.invalid/', 100, 8)
    assert event == {'phase': 'timeout', 'requests_sent': 1, 'responses_received': 1}


def test_http_refusal_is_distinct_from_transport_failure(monkeypatch):
    sock = FakeSocket(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n', IP)
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *a: [row()])
    monkeypatch.setattr(transport.socket, 'socket', lambda *a: sock)
    monkeypatch.setattr(transport.ssl, 'SSLContext', lambda *a: FakeContext())
    value = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {}})
    assert value['reason'] == 'http_refused'
    assert value['diagnostic'] == {'phase': 'http', 'requests_sent': 1, 'responses_received': 1}
    assert valid_live(value)


def test_substituted_exchange_does_not_invent_send_counts(monkeypatch):
    monkeypatch.setattr(transport, 'exchange_observed', lambda *a: {})
    value = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {}})
    assert value['diagnostic'] == {'phase': 'unknown', 'requests_sent': None, 'responses_received': None}
    assert valid_live(value)
