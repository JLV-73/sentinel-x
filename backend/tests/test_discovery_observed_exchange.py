"""Synthetic-only acceptance of a single shared navigation/evidence exchange."""
from unittest.mock import patch

from app import fortress_discovery_transport as transport
from test_discovery_transport import FakeContext, FakeSocket, IP, row


def invoke(response):
    sock = FakeSocket(response, IP)
    with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]), \
         patch.object(transport.socket, 'socket', return_value=sock), \
         patch.object(transport.ssl, 'SSLContext', return_value=FakeContext()):
        return transport.exchange_observed('https://example.invalid/', 1000, 8)


def test_navigation_and_observations_come_from_the_same_response():
    body = b'<a href="/next">SECRET_BODY</a>'
    response = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'
                b'Strict-Transport-Security: max-age=3600\r\n'
                b'Set-Cookie: token=SECRET_COOKIE; Secure; HttpOnly\r\n'
                b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    sock = FakeSocket(response, IP)
    with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]), \
         patch.object(transport.socket, 'socket', return_value=sock), \
         patch.object(transport.ssl, 'SSLContext', return_value=FakeContext()):
        result = transport.exchange_observed('https://example.invalid/', 1000, 8)
    assert result['links'] == ['/next']
    assert result['decoded_bytes'] == len(body)
    assert result['observations']['hsts'] == 'positive'
    assert 'SECRET_BODY' not in repr(result)
    assert 'SECRET_COOKIE' not in repr(result)


def test_changed_headers_change_observations_without_changing_navigation():
    body = b'<a href="/next">go</a>'
    prefix = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'
              b'Content-Length: ' + str(len(body)).encode() + b'\r\n')
    without = invoke(prefix + b'\r\n' + body)
    with_hsts = invoke(prefix + b'Strict-Transport-Security: max-age=0\r\n\r\n' + body)
    assert without['links'] == with_hsts['links'] == ['/next']
    assert without['observations']['hsts'] == 'absent'
    assert with_hsts['observations']['hsts'] == 'disabled'


def test_refusal_redirect_and_truncation_are_not_positive_observations():
    for response, status in (
        (b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n', 403),
        (b'HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n', 302),
    ):
        result = invoke(response)
        assert result['status'] == status
        assert result['observations'] is None
    assert invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na') == {'status': 200, 'incomplete': True, 'partial_headers': {'present': [], 'completeness': 'headers_validated_body_incomplete'}}
