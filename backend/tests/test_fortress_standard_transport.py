"""Strict single-GET transport contract; all network dependencies are local fakes."""
import socket
from unittest.mock import Mock

import pytest

from app.fortress_transport import SafeTransport, TransportError, validate_scope
from test_fortress_transport import FakeSocket, answer, PUBLIC
from test_fortress_tls_lab import (certificates, TLSLab, LocalSocketAdapter,
                                    client_context, resolver as lab_resolver, HOST)

URL = 'https://example.com/'


def make_transport(payload, **kwargs):
    sock = FakeSocket(payload, peer=(PUBLIC, 443))
    resolver = Mock(return_value=[answer(port=443)])
    context = Mock(verify_mode=2, check_hostname=True)
    context.wrap_socket.return_value = sock
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver,
                              socket_factory=Mock(return_value=sock), tls_context=context,
                              strict_standard=True, **kwargs)
    return transport, sock, resolver, context


def test_strict_redirect_is_observed_without_following_or_cookie_values():
    transport, sock, resolver, context = make_transport(
        b'HTTP/1.1 302 Found\r\nLocation: https://outside.invalid/private\r\n'
        b'Set-Cookie: sid=secret; Secure; HttpOnly; SameSite=Strict\r\nContent-Length: 0\r\n\r\n')
    result = transport.request('GET', URL)
    assert result.status == 302 and not result.blocked
    assert 'secret' not in repr(result) and 'outside.invalid' not in repr(result)
    assert resolver.call_count == len(sock.sent) == transport.count == 1
    assert context.wrap_socket.call_args.kwargs['server_hostname'] == 'example.com'
    with pytest.raises(TransportError):
        transport.request('GET', URL)
    assert resolver.call_count == 1


def test_strict_header_observer_reports_redirect_status_without_target():
    transport, sock, resolver, _ = make_transport(
        b'HTTP/1.1 302 Found\r\nLocation: https://private.invalid/secret\r\n'
        b'Set-Cookie: sid=secret\r\nContent-Length: 0\r\n\r\n')
    result = transport.observe_headers('GET', URL)
    assert result['status'] == 302 and result['redirected'] is True
    assert result['outcome'] == 'indeterminate'
    assert 'secret' not in repr(result) and 'private.invalid' not in repr(result)
    assert resolver.call_count == len(sock.sent) == 1


def test_strict_standard_facts_never_claim_success_for_redirect():
    transport, _, _, _ = make_transport(
        b'HTTP/1.1 302 Found\r\nLocation: /other\r\nContent-Length: 0\r\n\r\n')
    result = transport.observe_standard_facts('GET', URL)
    assert result['outcome'] == 'indeterminate'
    assert result['status'] == 302 and result['redirected'] is True


def test_expiry_during_socket_close_cannot_return_success(monkeypatch):
    import app.fortress_transport as module
    clock = [100.0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    transport, sock, resolver, _ = make_transport(
        b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', deadline=1)
    sock.close = lambda: clock.__setitem__(0, 102.0)
    with pytest.raises(TransportError):
        transport.request('GET', URL)
    assert resolver.call_count == 1


def test_expiry_after_close_does_not_retain_raw_response_in_traceback(monkeypatch):
    import traceback
    import app.fortress_transport as module

    clock = [100.0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    body = b'CANARY_BODY'
    transport, sock, resolver, _ = make_transport(
        b'HTTP/1.1 200 OK\r\nX-Test: CANARY_HEADER\r\nContent-Length: 11\r\n\r\n' + body,
        deadline=1)
    sock.close = lambda: clock.__setitem__(0, 102.0)
    with pytest.raises(TransportError) as caught:
        transport.request('GET', URL)
    exc = caught.value
    captured = traceback.TracebackException.from_exception(exc, capture_locals=True)
    transport_frames = [frame for frame in captured.stack
                        if frame.filename.endswith('fortress_transport.py')]
    assert transport_frames
    leaked = any('CANARY_BODY' in str(frame.locals) or 'CANARY_HEADER' in str(frame.locals)
                 for frame in transport_frames)
    assert not leaked, 'raw response canary retained in transport traceback locals'
    assert exc.__context__ is None and exc.__cause__ is None
    assert transport.blocked and transport.count == 1 and resolver.call_count == 1
    with pytest.raises(TransportError):
        transport.request('GET', URL)
    assert resolver.call_count == 1


def test_expiry_while_deriving_observation_cannot_return_success(monkeypatch):
    import app.fortress_transport as module
    clock = [100.0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    transport, _, _, _ = make_transport(
        b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', deadline=1)
    original = module._header_facts
    def expire(*args):
        result = original(*args)
        clock[0] = 102.0
        return result
    monkeypatch.setattr(module, '_header_facts', expire)
    assert transport.observe_headers('GET', URL)['outcome'] == 'error'


@pytest.mark.parametrize('target,extra', [
    ('http://example.com/', []),
    ('https://example.com/', ['https://example.com/other']),
    ('https://93.184.216.34/', []),
])
def test_strict_scope_rejected_before_network(target, extra):
    with pytest.raises(TransportError):
        SafeTransport(validate_scope(target, extra), strict_standard=True)


@pytest.mark.parametrize('method,url', [
    ('HEAD', URL), ('POST', URL), ('GET', 'https://example.com/other'),
])
def test_strict_method_and_route_rejected_before_dns(method, url):
    transport, sock, resolver, _ = make_transport(b'')
    with pytest.raises(TransportError):
        transport.request(method, url)
    resolver.assert_not_called()
    assert not sock.sent


@pytest.mark.parametrize('bad', ['127.0.0.1', '10.0.0.1', '192.0.2.1', '::1', '::ffff:93.184.216.34'])
def test_strict_mixed_dns_is_rejected_before_connect(bad):
    transport, sock, resolver, _ = make_transport(b'')
    resolver.return_value = [answer(port=443), answer(bad, 443)]
    with pytest.raises(TransportError):
        transport.request('GET', URL)
    assert not sock.connected and not sock.sent


@pytest.mark.parametrize('hostname,trust,success', [
    (HOST, True, True), ('wrong-fortress-lab.invalid', True, False), (HOST, False, False),
])
def test_strict_real_tls_only_owned_loopback(certificates, hostname, trust, success):
    lab = TLSLab(certificates)
    try:
        context = client_context(certificates / 'ca.pem' if trust else None)
        url = f'https://{hostname}/'
        transport = SafeTransport(validate_scope(url, []), resolver=lab_resolver,
            socket_factory=lambda *args: LocalSocketAdapter(lab.address, lab.record),
            tls_context=context, timeout=4, strict_standard=True)
        if success:
            result = transport.request('GET', url)
            assert result.status == 200 and result.body == b'OK'
            assert result.tls_version in ('TLSv1.2', 'TLSv1.3')
        else:
            with pytest.raises(TransportError):
                transport.request('GET', url)
    finally:
        lab.finish()
    assert lab.record['sni'] == [hostname]
    assert lab.record['actual_connected_peer'] == lab.address
    assert lab.address[0] == '127.0.0.1'
    if success:
        assert lab.record['request'].startswith(f'GET / HTTP/1.1\r\nHost: {hostname}\r\n'.encode())
        assert b'Cookie:' not in lab.record['request']
    else:
        assert lab.record['request'] == b''
