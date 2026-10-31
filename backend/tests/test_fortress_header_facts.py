from test_fortress_transport import URL, build
import pytest
from unittest.mock import Mock
from test_fortress_transport import FakeSocket, answer
from app.fortress_transport import SafeTransport, validate_scope


@pytest.mark.parametrize('payload', [
    b'HTTP/1.1 200 OK\r\n',
    b'HTTP/1.1 200 OK\r\nX-Test: value\r\n',
    b'HTTP/1.1 200 OK\r\nX-Test: val',
    b'HTTP/1.1 200 OK\nX-Test: value\n\n',
    b'HTTP/1.1 200 OK\r\nX-Test: value\rReferrer-Policy: no-referrer\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nX-Test: value\r\n continued\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 0, 0\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nX-Test: ' + b'x' * 65537 + b'\r\n\r\n',
    b'HTTP/1.1 200 OK\r\n' + (b'X-Test: ' + b'x' * 2000 + b'\r\n') * 70 + b'\r\n',
    b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n',
], ids=lambda value: 'invalid-framing')
def test_invalid_framing_halts_without_header_absence(payload):
    transport = build(payload)[0]
    result = transport.observe_headers('GET', URL)
    assert result['outcome'] != 'ok'
    assert set(result.get('security_headers', {}).values()) <= {'unknown'}
    assert transport.blocked
    assert transport.observe_headers('GET', URL)['outcome'] == 'error'


def test_interim_response_and_repeated_cookies_remain_supported():
    payload = (b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n'
               b'Set-Cookie: a=private; Secure\r\nSet-Cookie: b=private; HttpOnly\r\n'
               b'Content-Length: 0\r\n\r\n')
    result = build(payload)[0].observe_headers('GET', URL)
    assert result['outcome'] == 'ok'
    assert result['cookies']['count'] == 2
    assert result['security_headers']['hsts'] == 'absent'
    assert 'private' not in repr(result)


def test_complete_response_reports_absent_without_raw_data():
    transport, _, _, _ = build(b'HTTP/1.1 200 OK\r\nX-Private: sentinel-secret\r\nContent-Length: 0\r\n\r\n')
    result = transport.observe_headers('GET', URL)
    assert result['security_headers'] == dict.fromkeys(('hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy'), 'absent')
    assert 'sentinel-secret' not in repr(result)


@pytest.mark.parametrize('header,key,value', [
    ('Strict-Transport-Security', 'hsts', 'max-age=31536000; includeSubDomains'),
    ('Content-Security-Policy', 'csp', "default-src 'none'"),
    ('X-Content-Type-Options', 'x_content_type_options', 'NoSniff'),
    ('Referrer-Policy', 'referrer_policy', 'strict-origin-when-cross-origin'),
    ('Permissions-Policy', 'permissions_policy', 'camera=()'),
])
def test_recognized_values_are_present_without_exposing_values(header, key, value):
    payload = f'HTTP/1.1 200 OK\r\n{header.swapcase()}: {value}\r\nContent-Length: 0\r\n\r\n'.encode()
    result = build(payload)[0].observe_headers('GET', URL)
    assert result['security_headers'][key] == 'present'
    assert value not in repr(result)


@pytest.mark.parametrize('header,key', [
    ('Strict-Transport-Security', 'hsts'), ('Content-Security-Policy', 'csp'),
    ('X-Content-Type-Options', 'x_content_type_options'), ('Referrer-Policy', 'referrer_policy'),
    ('Permissions-Policy', 'permissions_policy'),
])
def test_empty_invalid_duplicate_ambiguous_and_unrecognized_unknown(header, key):
    for value, expected in [('', 'invalid'), ('sentinel-secret', 'unknown')]:
        result = build(f'HTTP/1.1 200 OK\r\n{header}: {value}\r\nContent-Length: 0\r\n\r\n'.encode())[0].observe_headers('GET', URL)
        assert result['security_headers'][key] == expected
        assert 'sentinel-secret' not in repr(result)
    payload = f'HTTP/1.1 200 OK\r\n{header}: sentinel-secret\r\n{header.swapcase()}: sentinel-secret\r\nContent-Length: 0\r\n\r\n'.encode()
    assert build(payload)[0].observe_headers('GET', URL)['security_headers'][key] == 'unknown'


def test_malformed_header_line_cannot_prove_absence():
    payload = (b'HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n'
               b'Malformed line\r\nReferrer-Policy: no-referrer\r\n\r\n')
    transport = build(payload)[0]
    result = transport.observe_headers('GET', URL)
    assert result['outcome'] == 'error' and transport.blocked
    assert set(result.get('security_headers', {}).values()) <= {'unknown'}


@pytest.mark.parametrize('payload', [
    b'HTTP/1.1 403 Forbidden\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 0\r\n\r\n',
    b'HTTP/1.1 206 Partial\r\nContent-Length: 0\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nshort',
    b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncaptcha',
])
def test_incomplete_or_blocked_never_returns_positive_or_absent(payload):
    result = build(payload)[0].observe_headers('GET', URL)
    assert result['outcome'] != 'ok'
    assert set(result.get('security_headers', {}).values()) <= {'unknown'}


def test_redirect_has_only_unknown_facts_and_no_private_data():
    first = FakeSocket(b'HTTP/1.1 302 Found\r\nLocation: /private-sentinel\r\nContent-Length: 0\r\n\r\n')
    second = FakeSocket(b'HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nSet-Cookie: sentinel=sentinel-secret\r\nContent-Length: 0\r\n\r\n')
    resolver = Mock(return_value=[answer()])
    t = SafeTransport(validate_scope(URL, ['http://example.com/private-sentinel']), resolver=resolver,
                      socket_factory=Mock(side_effect=[first, second]))
    result = t.observe_headers('GET', URL)
    assert result['redirected'] is True and set(result['security_headers'].values()) == {'unknown'}
    assert 'sentinel' not in repr(result) and 'example.com' not in repr(result)
