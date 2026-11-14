import gzip

import pytest

from app import fortress_discovery_transport as transport
from test_discovery_transport import FakeContext, FakeSocket, IP, row


@pytest.mark.parametrize('response,limit', [
    (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 524289\r\n\r\n', 512 * 1024),
    (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\n\r\n', 10),
    (lambda body: b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body, 10),
])
def test_size_overruns_are_budget_after_response_headers(monkeypatch, response, limit):
    if callable(response):
        response = response(gzip.compress(b'x' * 11))
    sock = FakeSocket(response, IP)
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *a: [row()])
    monkeypatch.setattr(transport.socket, 'socket', lambda *a: sock)
    monkeypatch.setattr(transport.ssl, 'SSLContext', lambda *a: FakeContext())
    result, event = transport.capture_observed('https://example.invalid/', limit, 8)
    assert result == {'status': 200, 'incomplete': True, 'partial_headers': {
        'present': [], 'completeness': 'headers_validated_body_incomplete'}}
    assert event == {'phase': 'budget', 'requests_sent': 1, 'responses_received': 1}
    assert sock.closed


@pytest.mark.parametrize('response', [
    b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 524289\r\nTransfer-Encoding: chunked\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 524289\r\nContent-Length: 524289\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1\r\n\r\nxx',
    b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 22\r\n\r\n' + gzip.compress(b'x') + b'x',
])
def test_malformed_framing_remains_parse_and_blocked(monkeypatch, response):
    sock = FakeSocket(response, IP)
    monkeypatch.setattr(transport.socket, 'getaddrinfo', lambda *a: [row()])
    monkeypatch.setattr(transport.socket, 'socket', lambda *a: sock)
    monkeypatch.setattr(transport.ssl, 'SSLContext', lambda *a: FakeContext())
    result, event = transport.capture_observed('https://example.invalid/', 512 * 1024, 8)
    if b'Content-Encoding: gzip' in response:
        # Header framing was valid; the later invalid gzip body remains incomplete.
        assert result == {'status': 200, 'incomplete': True, 'partial_headers': {
            'present': [], 'completeness': 'headers_validated_body_incomplete'}}
    else:
        assert result == {}
    assert event == {'phase': 'parse', 'requests_sent': 1, 'responses_received': 1}
    assert sock.closed
